//go:build linux

package ebpf

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

// ResolveCgroupID returns the kernel cgroup ID for a given cgroup v2 filesystem path.
// The cgroup ID is the inode number of the cgroup directory.
func ResolveCgroupID(cgroupPath string) (uint64, error) {
	var stat unix.Statx_t
	err := unix.Statx(unix.AT_FDCWD, cgroupPath, 0, unix.STATX_INO, &stat)
	if err != nil {
		return 0, fmt.Errorf("statx %s: %w", cgroupPath, err)
	}
	return stat.Ino, nil
}

// ResolveCgroupIDs resolves multiple cgroup paths to their kernel IDs.
func ResolveCgroupIDs(paths []string) ([]uint64, error) {
	ids := make([]uint64, 0, len(paths))
	for _, p := range paths {
		id, err := ResolveCgroupID(p)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// CgroupView identifies which cgroup hierarchy version is mounted at a root.
type CgroupView int

const (
	CgroupViewUnknown CgroupView = iota // neither a v2 nor a v1 hierarchy was identified
	CgroupViewV1
	CgroupViewV2
)

func (v CgroupView) String() string {
	switch v {
	case CgroupViewV1:
		return "v1"
	case CgroupViewV2:
		return "v2"
	default:
		return "unknown"
	}
}

// DetectCgroupView reports the cgroup hierarchy version mounted at cgroupRoot.
// The superblock magic from statfs is authoritative and works even when a
// non-root v2 subtree is configured. The marker-based fallback exists so the
// detection is testable with ordinary temporary directories (tmpfs), which
// carry no cgroup superblock.
func DetectCgroupView(cgroupRoot string) CgroupView {
	var st unix.Statfs_t
	if err := unix.Statfs(cgroupRoot, &st); err == nil {
		switch st.Type {
		case unix.CGROUP2_SUPER_MAGIC:
			return CgroupViewV2
		case unix.CGROUP_SUPER_MAGIC:
			return CgroupViewV1
		}
	}
	return detectCgroupViewByFiles(cgroupRoot)
}

// detectCgroupViewByFiles infers the version from well-known control files:
//   - cgroup.controllers at the root is the cgroup v2 unified-hierarchy marker;
//   - cgroup.procs without cgroup.controllers is a v1 controller mount;
//   - otherwise v1 controller subdirectories (each with cgroup.procs) identify
//     the classic /sys/fs/cgroup tmpfs layout.
func detectCgroupViewByFiles(cgroupRoot string) CgroupView {
	if info, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err == nil && !info.IsDir() {
		return CgroupViewV2
	}
	if info, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.procs")); err == nil && !info.IsDir() {
		return CgroupViewV1
	}
	entries, err := os.ReadDir(cgroupRoot)
	if err != nil {
		return CgroupViewUnknown
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if info, err := os.Stat(filepath.Join(cgroupRoot, entry.Name(), "cgroup.procs")); err == nil && !info.IsDir() {
			return CgroupViewV1
		}
	}
	return CgroupViewUnknown
}

// RequireCgroupV2 refuses to proceed unless cgroupRoot is a cgroup v2
// hierarchy. BPF identifies a process's cgroup with
// bpf_get_current_cgroup_id() (the kernfs node id), while userspace resolves
// scope IDs from the statx inode of the cgroup directory (ResolveCgroupID).
// These values coincide only on cgroup v2: on v1 (or an unknown view) the
// kernel ID is unusable for comparison, so default-deny kernel marking and
// cgroup filtering would silently mis-enforce. Callers must fail closed.
func RequireCgroupV2(cgroupRoot string) error {
	switch view := DetectCgroupView(cgroupRoot); view {
	case CgroupViewV2:
		return nil
	case CgroupViewV1:
		return fmt.Errorf("cgroup v1 detected at %s: kernel cgroup IDs (bpf_get_current_cgroup_id) and userspace scope IDs (statx inode) only match on cgroup v2; refusing cgroup filtering or kernel default-deny marking", cgroupRoot)
	default:
		return fmt.Errorf("cannot determine cgroup hierarchy version at %s: refusing cgroup filtering or kernel default-deny marking without a confirmed cgroup v2 view", cgroupRoot)
	}
}

// podCgroupDirRe matches the per-pod cgroup directory names kubelet creates:
// systemd driver "kubepods-pod<uid>.slice" / "kubepods-<qos>-pod<uid>.slice"
// (prefixed "kubelet-" when kubelet's cgroupRoot is /kubelet, as in kind)
// (uid dashes escaped to underscores), cgroupfs driver "pod<uid>". QoS-class
// slices such as "kubepods-besteffort.slice" deliberately do not match.
var podCgroupDirRe = regexp.MustCompile(`^((kubelet-)?kubepods(-[a-z]+)?-pod[0-9a-fA-F_]+\.slice|pod[0-9a-fA-F-]+)$`)

func isPodCgroupDir(name string) bool {
	return podCgroupDirRe.MatchString(name)
}

// DiscoverPodCgroups walks the kubepods cgroup hierarchy and returns cgroup IDs
// for all discovered pod cgroups and their container cgroups. This provides "monitor all K8s pods, skip host"
// behavior when --cgroup-filter=auto is specified.
func DiscoverPodCgroups(cgroupRoot string) ([]uint64, error) {
	return discoverPodCgroups(cgroupRoot, ResolveCgroupID)
}

// The resolver argument makes deletion between Walk's stat and Statx
// deterministic in unprivileged tests, without a mutable global test hook.
func discoverPodCgroups(cgroupRoot string, resolve func(string) (uint64, error)) ([]uint64, error) {
	kubepodsDirs := []string{
		filepath.Join(cgroupRoot, "kubepods.slice"),
		filepath.Join(cgroupRoot, "kubepods"),
		// kind configures kubelet cgroupRoot=/kubelet. systemd encodes
		// ancestor names in each slice component; cgroupfs uses plain dirs.
		// These are explicit layouts, not a recursive search of host cgroups.
		filepath.Join(cgroupRoot, "kubelet.slice", "kubelet-kubepods.slice"),
		filepath.Join(cgroupRoot, "kubelet", "kubepods"),
	}

	var baseDir string
	for _, d := range kubepodsDirs {
		info, err := os.Stat(d)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("stat kubepods: %w", err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("kubepods path %s is not a directory", d)
		}
		baseDir = d
		break
	}
	if baseDir == "" {
		return nil, fmt.Errorf("kubepods cgroup directory not found under %s", cgroupRoot)
	}

	var ids []uint64
	// Pod directories are matched by name; every cgroup below one (the
	// container scopes/dirs) belongs to that pod and is included as well.
	// Walk is depth-first in lexical order, so a pod's subtree is visited
	// contiguously right after the pod directory itself.
	var podDir string
	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && path != baseDir {
				return nil
			} // ordinary pod churn
			return err
		}
		if !info.IsDir() {
			return nil
		}
		if path == baseDir {
			return nil
		}
		inPod := podDir != "" && strings.HasPrefix(path, podDir+string(filepath.Separator))
		if !inPod {
			podDir = ""
			if !isPodCgroupDir(info.Name()) {
				return nil
			}
			podDir = path
		}
		id, err := resolve(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		ids = append(ids, id)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk kubepods: %w", err)
	}

	return ids, nil
}

// GetPIDCgroupID reads the cgroup ID for a given PID by reading /proc/<pid>/cgroup
// and resolving the cgroup v2 path. Used as a fallback when eBPF cgroup_id is unavailable.
func GetPIDCgroupID(pid uint32) (uint64, error) {
	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// cgroup v2 line format: "0::<path>"
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" {
			cgroupPath := filepath.Join("/sys/fs/cgroup", parts[2])
			return ResolveCgroupID(cgroupPath)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	return 0, fmt.Errorf("no cgroup v2 entry found for pid %d", pid)
}
