//go:build linux

package coordinator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/workload"
	"golang.org/x/sys/unix"
)

type HostConfig struct {
	ProcRoot, CgroupRoot string
	// Independently configured host namespace identities (e.g. pid:[4026531836]),
	// NOT learned from an arbitrary workload. The administrator must authorize
	// these read-only host mounts; CgroupRoot must be the complete host v2 root,
	// not a delegated subtree. The producer must run in both authorized host
	// namespaces. Only unified cgroup v2 is supported.
	HostPIDNamespace, HostCgroupNamespace string
	TrustHostMounts                       bool
	MaxBindings                           int
	// Gaps beyond this bound retire lifetime continuity even if the next
	// evidence looks identical. Configure no larger than coordinator MaxAge.
	MaxObservationGap time.Duration
}

type hostEvidence struct {
	container, start, membership, namespaces, boot string
	pid                                            int
	dev, ino                                       uint64
}

type pinnedBinding struct {
	evidence hostEvidence
	binding  workload.Binding
	dir      *os.File
}

type HostVerifier struct {
	mu                                    sync.Mutex
	proc, cgroups                         *os.Root
	boot, session                         string
	sequence                              uint64
	max                                   int
	inspect                               func(*os.File) (uint64, uint64, error)
	hostPIDNamespace, hostCgroupNamespace string
	active                                map[uint64]pinnedBinding
	closed                                bool
	maxGap                                time.Duration
	observedUntil                         time.Time
}

func NewHostVerifier(cfg HostConfig) (*HostVerifier, error) {
	if !cfg.TrustHostMounts || !filepath.IsAbs(cfg.ProcRoot) || !filepath.IsAbs(cfg.CgroupRoot) ||
		!namespaceToken(cfg.HostPIDNamespace, "pid") || !namespaceToken(cfg.HostCgroupNamespace, "cgroup") ||
		cfg.MaxBindings < 1 || cfg.MaxBindings > 65536 || cfg.MaxObservationGap < time.Millisecond || cfg.MaxObservationGap > 10*time.Minute {
		return nil, errors.New("explicit trusted host mounts, namespaces and bounds required")
	}
	proc, err := os.OpenRoot(cfg.ProcRoot)
	if err != nil {
		return nil, err
	}
	cgroups, err := os.OpenRoot(cfg.CgroupRoot)
	if err != nil {
		proc.Close()
		return nil, err
	}
	v := &HostVerifier{proc: proc, cgroups: cgroups, max: cfg.MaxBindings, maxGap: cfg.MaxObservationGap, active: make(map[uint64]pinnedBinding), inspect: inspectCgroup}
	fail := func(err error) (*HostVerifier, error) { v.Close(); return nil, err }
	if err := checkFilesystem(proc, unix.PROC_SUPER_MAGIC); err != nil {
		return fail(err)
	}
	if err := checkFilesystem(cgroups, unix.CGROUP2_SUPER_MAGIC); err != nil {
		return fail(err)
	}
	mounts, err := readRootFile(proc, "self/mountinfo", 1<<20)
	if err != nil || !fullCgroupMount(string(mounts), filepath.Clean(cfg.CgroupRoot)) {
		return fail(errors.New("cgroup root must be a full unified host hierarchy mount"))
	}
	pidNS, err := proc.Readlink("1/ns/pid")
	if err != nil || pidNS != cfg.HostPIDNamespace {
		return fail(errors.New("proc root is not the authorized host PID namespace"))
	}
	cgNS, err := proc.Readlink("1/ns/cgroup")
	if err != nil || cgNS != cfg.HostCgroupNamespace {
		return fail(errors.New("proc root is not the authorized host cgroup namespace"))
	}
	selfNS, err := proc.Readlink("self/ns/cgroup")
	if err != nil || selfNS != cfg.HostCgroupNamespace {
		return fail(errors.New("producer must run in the authorized host cgroup namespace"))
	}
	selfPIDNS, err := proc.Readlink("self/ns/pid")
	if err != nil || selfPIDNS != cfg.HostPIDNamespace {
		return fail(errors.New("producer must run in the authorized host PID namespace"))
	}
	boot, err := readRootFile(proc, "sys/kernel/random/boot_id", 128)
	if err != nil || !validBoot(strings.TrimSpace(string(boot))) {
		return fail(errors.New("missing host boot identity"))
	}
	v.boot = strings.TrimSpace(string(boot))
	v.hostPIDNamespace, v.hostCgroupNamespace = cfg.HostPIDNamespace, cfg.HostCgroupNamespace
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fail(err)
	}
	v.session = hex.EncodeToString(random[:])
	return v, nil
}

func checkFilesystem(root *os.Root, magic int64) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &st); err != nil {
		return err
	}
	if st.Type != magic {
		return errors.New("host mount has wrong filesystem type")
	}
	return nil
}

func namespaceToken(s, kind string) bool {
	prefix := kind + ":["
	if !strings.HasPrefix(s, prefix) || !strings.HasSuffix(s, "]") {
		return false
	}
	n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(s, prefix), "]"), 10, 64)
	return err == nil && n != 0
}

func validBoot(s string) bool {
	if len(s) != 36 {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return err == nil
}

func fullCgroupMount(data, mountpoint string) bool {
	unescape := strings.NewReplacer("\\040", " ", "\\011", "\t", "\\012", "\n", "\\134", "\\")
	for _, line := range strings.Split(data, "\n") {
		left, right, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		fields, fs := strings.Fields(left), strings.Fields(right)
		if len(fields) >= 6 && len(fs) >= 1 && fs[0] == "cgroup2" &&
			unescape.Replace(fields[3]) == "/" && unescape.Replace(fields[4]) == mountpoint {
			return true
		}
	}
	return false
}

// Verify uses only exact runtime PID claims. It pins each observed cgroup inode
// until retirement, checks proc start-time, membership and namespaces twice,
// and issues an opaque boot/session/incarnation lifetime. No name-based cgroup
// inference or process scan is performed. Inode IDs refer only to exact cgroups;
// unobserved descendants remain unknown.
func (v *HostVerifier) Verify(ctx context.Context, claims []ProcessClaim) ([]workload.Binding, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, errors.New("host verifier closed")
	}
	start := time.Now()
	if !start.Before(v.observedUntil) {
		for _, old := range v.active {
			old.dir.Close()
		}
		v.active = make(map[uint64]pinnedBinding)
	}
	v.observedUntil = start.Add(v.maxGap)
	next := make(map[uint64]pinnedBinding)
	commit := func() {
		for id, old := range v.active {
			if n, ok := next[id]; !ok || n.dir != old.dir {
				old.dir.Close()
			}
		}
		v.active = next
	}
	if len(claims) > v.max {
		commit()
		return nil, errors.New("host binding budget exceeded")
	}
	boot, err := readRootFile(v.proc, "sys/kernel/random/boot_id", 128)
	if err != nil || strings.TrimSpace(string(boot)) != v.boot {
		commit()
		return nil, errors.New("host boot identity changed")
	}
	if v.hostPIDNamespace != "" {
		pidNS, e1 := v.proc.Readlink("1/ns/pid")
		cgNS, e2 := v.proc.Readlink("1/ns/cgroup")
		selfNS, e3 := v.proc.Readlink("self/ns/cgroup")
		selfPIDNS, e4 := v.proc.Readlink("self/ns/pid")
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || pidNS != v.hostPIDNamespace || cgNS != v.hostCgroupNamespace || selfNS != v.hostCgroupNamespace || selfPIDNS != v.hostPIDNamespace {
			commit()
			return nil, errors.New("host namespace provenance changed")
		}
	}
	// Peak pinned directory descriptors are at most 2*MaxBindings while a
	// complete replacement is being verified. A gap is conservatively retired.
	seenID := make(map[string]int)
	seenPID := make(map[int]int)
	for _, c := range claims {
		seenID[c.ContainerID]++
		seenPID[c.PID]++
	}
	conflict := make(map[uint64]bool)
	for _, claim := range claims {
		if ctx.Err() != nil {
			for _, n := range next {
				if old, ok := v.active[n.binding.CgroupID]; !ok || old.dir != n.dir {
					n.dir.Close()
				}
			}
			next = make(map[uint64]pinnedBinding)
			commit()
			return nil, ctx.Err()
		}
		if !safeID(claim.ContainerID) || claim.PID <= 1 || seenID[claim.ContainerID] != 1 || seenPID[claim.PID] != 1 {
			continue
		}
		e, dir, err := v.observe(claim)
		if err != nil {
			continue
		} // retire any prior claim, never reuse stale evidence
		id := e.ino
		if conflict[id] {
			dir.Close()
			continue
		}
		if n, ok := next[id]; ok {
			if old, exists := v.active[id]; !exists || old.dir != n.dir {
				n.dir.Close()
			}
			dir.Close()
			delete(next, id)
			conflict[id] = true
			continue
		}
		if old, ok := v.active[id]; ok && old.evidence == e {
			dir.Close()
			next[id] = old
		} else {
			v.sequence++
			next[id] = pinnedBinding{evidence: e, dir: dir, binding: workload.Binding{CgroupID: id, ContainerID: claim.ContainerID,
				Lifetime: fmt.Sprintf("%s:%s:%d", v.boot, v.session, v.sequence)}}
		}
	}
	if ctx.Err() != nil || !time.Now().Before(v.observedUntil) {
		for id, n := range next {
			if old, ok := v.active[id]; !ok || old.dir != n.dir {
				n.dir.Close()
			}
		}
		next = make(map[uint64]pinnedBinding)
		commit()
		return nil, errors.New("host verification observation deadline expired")
	}
	commit()
	out := make([]workload.Binding, 0, len(next))
	for _, n := range next {
		out = append(out, n.binding)
	}
	return out, nil
}

func (v *HostVerifier) observe(claim ProcessClaim) (hostEvidence, *os.File, error) {
	e := hostEvidence{container: claim.ContainerID, pid: claim.PID, boot: v.boot}
	proc, err := v.proc.OpenRoot(strconv.Itoa(claim.PID))
	if err != nil {
		return e, nil, err
	}
	defer proc.Close()
	first, err := readProcess(proc, claim.PID)
	if err != nil {
		return e, nil, err
	}
	// Reject the host root and malformed/escaping paths. os.Root additionally
	// prevents symlink escapes under the authorized cgroup hierarchy.
	member, err := unifiedMembership(first.cgroup)
	if err != nil {
		return e, nil, err
	}
	dir, err := v.cgroups.Open(strings.TrimPrefix(member, "/"))
	if err != nil {
		return e, nil, err
	}
	fail := func(err error) (hostEvidence, *os.File, error) { dir.Close(); return e, nil, err }
	info, err := dir.Stat()
	if err != nil || !info.IsDir() {
		return fail(errors.New("cgroup is not a directory"))
	}
	dev, ino, err := v.inspect(dir)
	if err != nil {
		return fail(err)
	}
	if err := cgroupContainsPID(dir, claim.PID); err != nil {
		return fail(err)
	}
	second, err := readProcess(proc, claim.PID)
	if err != nil || first != second {
		return fail(errors.New("process identity changed during host verification"))
	}
	// Re-open the PID path too: a retained proc directory must not bless a
	// successor that reused the numeric PID during observation.
	current, err := v.proc.OpenRoot(strconv.Itoa(claim.PID))
	if err != nil {
		return fail(err)
	}
	third, err := readProcess(current, claim.PID)
	current.Close()
	if err != nil || third != first {
		return fail(errors.New("PID was retired during host verification"))
	}
	if err := cgroupContainsPID(dir, claim.PID); err != nil {
		return fail(err)
	}
	e.start, e.membership, e.namespaces = first.start, member, first.namespaces
	e.dev, e.ino = dev, ino
	return e, dir, nil
}

func cgroupContainsPID(dir *os.File, pid int) error {
	// Read relative to the pinned directory, not its possibly replaced path.
	// The producer runs in the authorized host PID namespace, so these IDs
	// have the same interpretation as the trusted runtime's PID assertion.
	fd, err := unix.Openat(int(dir.Fd()), "cgroup.procs", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "cgroup.procs")
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("cgroup process evidence byte budget exceeded")
	}
	found := false
	for _, field := range strings.Fields(string(data)) {
		n, err := strconv.ParseUint(field, 10, 32)
		if err != nil || n == 0 {
			return errors.New("invalid cgroup process evidence")
		}
		if n == uint64(pid) {
			found = true
		}
	}
	if !found {
		return errors.New("runtime PID absent from pinned cgroup")
	}
	return nil
}

func inspectCgroup(dir *os.File) (uint64, uint64, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		return 0, 0, err
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(dir.Fd()), &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || st.Ino == 0 {
		return 0, 0, errors.New("unverified cgroup filesystem")
	}
	return uint64(st.Dev), st.Ino, nil
}

type processEvidence struct{ start, cgroup, namespaces string }

func readProcess(proc *os.Root, pid int) (processEvidence, error) {
	var out processEvidence
	stat, err := readRootFile(proc, "stat", 8192)
	if err != nil {
		return out, err
	}
	out.start, err = processStart(string(stat), pid)
	if err != nil {
		return out, err
	}
	cgroup, err := readRootFile(proc, "cgroup", 16384)
	if err != nil {
		return out, err
	}
	out.cgroup = string(cgroup)
	for _, kind := range []string{"pid", "cgroup", "mnt"} {
		ns, err := proc.Readlink("ns/" + kind)
		if err != nil || !namespaceToken(ns, kind) {
			return out, errors.New("missing process namespace evidence")
		}
		out.namespaces += ns + ";"
	}
	return out, nil
}

func processStart(stat string, pid int) (string, error) {
	// comm can contain whitespace and ')'. Fields after its LAST ')' start at
	// field 3; starttime is field 22, index 19 in the remaining fields.
	left, right := strings.IndexByte(stat, '('), strings.LastIndexByte(stat, ')')
	if left < 1 || right <= left || strings.TrimSpace(stat[:left]) != strconv.Itoa(pid) {
		return "", errors.New("malformed proc stat PID")
	}
	fields := strings.Fields(stat[right+1:])
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return "", errors.New("dead or incomplete process")
	}
	n, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || n == 0 {
		return "", errors.New("invalid process start identity")
	}
	return fields[19], nil
}

func unifiedMembership(data string) (string, error) {
	lines := strings.Split(strings.TrimSuffix(data, "\n"), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "0::/") {
		return "", errors.New("unified host cgroup membership required")
	}
	member := strings.TrimPrefix(lines[0], "0::")
	if member == "/" || len(member) > 4096 || strings.IndexByte(member, 0) >= 0 || path.Clean(member) != member || strings.ContainsAny(member, "\r\n") {
		return "", errors.New("unsafe or root cgroup membership")
	}
	return member, nil
}

func readRootFile(root *os.Root, name string, limit int) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, errors.New("host evidence byte budget exceeded")
	}
	return b, nil
}

func safeID(id string) bool {
	if id == "" || len(id) > 256 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func (v *HostVerifier) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	for _, n := range v.active {
		n.dir.Close()
	}
	v.active = nil
	return errors.Join(v.proc.Close(), v.cgroups.Close())
}
