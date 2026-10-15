//go:build integration

package ebpf

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// integrityHarness scopes lsm_integrity to a dedicated cgroup and runs
// children directly inside it (CLONE_INTO_CGROUP), so enforce mode never
// touches the rest of the VM.
type integrityHarness struct {
	t        *testing.T
	loader   *LSMLoader
	cgroupFD int
	dir      string
}

func newIntegrityHarness(t *testing.T) *integrityHarness {
	t.Helper()
	requireRoot(t)
	requireLSM(t)

	loader := loadLSMOrSkip(t)
	t.Cleanup(func() { loader.Close() })

	cgPath := filepath.Join("/sys/fs/cgroup", "warmor-integrity-"+strings.ReplaceAll(t.Name(), "/", "_"))
	if err := os.Mkdir(cgPath, 0o755); err != nil && !os.IsExist(err) {
		t.Skipf("cannot create test cgroup (cgroup v2 not mounted?): %v", err)
	}
	t.Cleanup(func() { os.Remove(cgPath) })

	fd, err := syscall.Open(cgPath, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatalf("open cgroup: %v", err)
	}
	t.Cleanup(func() { syscall.Close(fd) })

	id, err := ResolveCgroupID(cgPath)
	if err != nil {
		t.Fatalf("resolve cgroup id: %v", err)
	}
	if err := loader.SetCgroupFilter([]uint64{id}); err != nil {
		t.Fatalf("SetCgroupFilter: %v", err)
	}

	// The VM's root (and /tmp) is a 9p share from the host, which IMA cannot
	// hash (bpf_ima_file_hash returns -EOPNOTSUPP). Real hosts run binaries
	// from ext4/xfs/overlayfs; use a tmpfs so the test exercises IMA.
	dir := t.TempDir()
	if err := syscall.Mount("tmpfs", dir, "tmpfs", 0, "size=64m"); err != nil {
		t.Fatalf("mount tmpfs: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(dir, syscall.MNT_DETACH) })

	h := &integrityHarness{t: t, loader: loader, cgroupFD: fd, dir: dir}
	if err := loader.EnableIntegrity(nil, IntegrityOff); err != nil {
		// CI sets WARMOR_REQUIRE_IMA on the IMA-enabled kernels it builds, where
		// a skip would hide exactly what that job exists to test.
		required := os.Getenv("WARMOR_REQUIRE_IMA") == "1"
		if errors.Is(err, ErrIMAUnavailable) && !required {
			t.Skipf("kernel has no IMA: %v", err)
		}
		if strings.Contains(err.Error(), "lsm_integrity") && !required {
			t.Skipf("kernel cannot load lsm_integrity: %v", err)
		}
		t.Fatalf("EnableIntegrity: %v", err)
	}
	return h
}

// copyBinary copies /bin/true (an ELF, so no interpreter is exec'd) to name.
func (h *integrityHarness) copyBinary(name string) string {
	h.t.Helper()
	src, err := os.Open("/bin/true")
	if err != nil {
		h.t.Fatalf("open /bin/true: %v", err)
	}
	defer src.Close()
	path := filepath.Join(h.dir, name)
	dst, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		h.t.Fatalf("create %s: %v", path, err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		h.t.Fatalf("copy: %v", err)
	}
	if err := dst.Close(); err != nil {
		h.t.Fatalf("close: %v", err)
	}
	return path
}

func digestOf(t *testing.T, path string) Digest {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return sha256.Sum256(b)
}

// run execs path inside the test cgroup and returns the exec error, if any.
func (h *integrityHarness) run(path string) error {
	cmd := exec.Command(path)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: h.cgroupFD}
	return cmd.Run()
}

// runOK fails the test if path doesn't run, logging the kernel counters
// (including the hash algorithm IMA returned) to make the cause visible.
func (h *integrityHarness) runOK(path, what string) {
	h.t.Helper()
	if err := h.run(path); err != nil {
		stats, serr := h.loader.IntegrityStats()
		cmdline, _ := os.ReadFile("/proc/cmdline")
		h.t.Fatalf("%s: %v (integrity stats %+v, stats err %v, cmdline %q)", what, err, stats, serr, cmdline)
	}
}

func requireExecDenied(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("exec succeeded, want EPERM")
	}
	if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
		t.Fatalf("exec failed with %v, want EPERM", err)
	}
}

func TestIntegrity_EnforceAllowsListedBlocksUnlisted(t *testing.T) {
	h := newIntegrityHarness(t)
	good := h.copyBinary("good")

	// Same bytes as good but one appended byte: a different SHA-256.
	bad := h.copyBinary("bad")
	f, err := os.OpenFile(bad, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte{0})
	f.Close()

	if err := h.loader.EnableIntegrity([]Digest{digestOf(t, good)}, IntegrityEnforce); err != nil {
		t.Fatalf("EnableIntegrity: %v", err)
	}
	t.Cleanup(func() { h.loader.SetIntegrityMode(IntegrityOff) })

	h.runOK(good, "allowlisted binary blocked")
	requireExecDenied(t, h.run(bad))

	// Path does not matter, only content: a copy of good elsewhere runs.
	if err := h.run(h.copyBinary("good-copy")); err != nil {
		t.Fatalf("allowlisted content at another path blocked: %v", err)
	}
}

func TestIntegrity_CacheInvalidatedOnModify(t *testing.T) {
	h := newIntegrityHarness(t)
	bin := h.copyBinary("mutable")
	if err := h.loader.EnableIntegrity([]Digest{digestOf(t, bin)}, IntegrityEnforce); err != nil {
		t.Fatalf("EnableIntegrity: %v", err)
	}
	t.Cleanup(func() { h.loader.SetIntegrityMode(IntegrityOff) })

	// Twice: the second exec should come from the inode verdict cache.
	for i := 0; i < 2; i++ {
		h.runOK(bin, "allowlisted binary blocked")
	}
	stats, err := h.loader.IntegrityStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.CacheHits == 0 {
		t.Errorf("expected a cache hit after re-exec, stats=%+v", stats)
	}

	// Tamper in place (same inode). ctime changes, so the cached "allowed"
	// verdict must not be reused.
	time.Sleep(10 * time.Millisecond)
	f, err := os.OpenFile(bin, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("tampered"))
	f.Close()
	requireExecDenied(t, h.run(bin))
}

func TestIntegrity_AllowlistUpdateRevokes(t *testing.T) {
	h := newIntegrityHarness(t)
	bin := h.copyBinary("revoked")
	d := digestOf(t, bin)
	if err := h.loader.EnableIntegrity([]Digest{d}, IntegrityEnforce); err != nil {
		t.Fatalf("EnableIntegrity: %v", err)
	}
	t.Cleanup(func() { h.loader.SetIntegrityMode(IntegrityOff) })

	h.runOK(bin, "run before revoke")
	// Cached as allowed; removing the digest must invalidate the cache.
	if err := h.loader.SetIntegrityAllowlist(nil); err != nil {
		t.Fatalf("SetIntegrityAllowlist: %v", err)
	}
	requireExecDenied(t, h.run(bin))

	// And granting it again works without touching the file.
	if err := h.loader.SetIntegrityAllowlist([]Digest{d}); err != nil {
		t.Fatalf("SetIntegrityAllowlist: %v", err)
	}
	if err := h.run(bin); err != nil {
		t.Fatalf("run after re-grant: %v", err)
	}
}

func TestIntegrity_AuditModeReportsWithoutBlocking(t *testing.T) {
	h := newIntegrityHarness(t)
	bin := h.copyBinary("unlisted")
	if err := h.loader.EnableIntegrity(nil, IntegrityAudit); err != nil {
		t.Fatalf("EnableIntegrity: %v", err)
	}
	t.Cleanup(func() { h.loader.SetIntegrityMode(IntegrityOff) })

	if err := h.run(bin); err != nil {
		t.Fatalf("audit mode blocked exec: %v", err)
	}

	// The violation must be reported through the shared LSM ring buffer.
	deadline := time.After(5 * time.Second)
	events := make(chan *Event, 16)
	go func() {
		for {
			ev, err := h.loader.ReadLSMEvent()
			if err != nil {
				close(events)
				return
			}
			events <- ev
		}
	}()
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				t.Fatal("ring buffer closed before integrity event")
			}
			if ev.IntegrityViolation {
				if ev.KernelDenied {
					t.Error("audit-mode integrity event marked KernelDenied")
				}
				if ev.Filename != bin {
					t.Errorf("integrity event filename = %q, want %q", ev.Filename, bin)
				}
				return
			}
		case <-deadline:
			t.Fatal("no integrity event within 5s")
		}
	}
}

func TestIntegrity_OffIsNoop(t *testing.T) {
	h := newIntegrityHarness(t)
	if err := h.run(h.copyBinary("anything")); err != nil {
		t.Fatalf("integrity off blocked exec: %v", err)
	}
	stats, err := h.loader.IntegrityStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Hashed != 0 || stats.Denied != 0 {
		t.Errorf("integrity off still did work: %+v", stats)
	}
}

// TestIntegrity_Overlayfs runs the allow/deny check on overlayfs, which is
// what container root filesystems are: the lower layer holds the image
// binary, and a file written in the upper layer (dropped after start) must
// be refused.
func TestIntegrity_Overlayfs(t *testing.T) {
	h := newIntegrityHarness(t)
	lower := filepath.Join(h.dir, "lower")
	upper := filepath.Join(h.dir, "upper")
	work := filepath.Join(h.dir, "work")
	merged := filepath.Join(h.dir, "merged")
	for _, d := range []string{lower, upper, work, merged} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	image := h.copyBinary("lower/app")
	d := digestOf(t, image)

	opts := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work
	if err := syscall.Mount("overlay", merged, "overlay", 0, opts); err != nil {
		if os.Getenv("WARMOR_REQUIRE_IMA") == "1" {
			t.Fatalf("mount overlayfs: %v", err)
		}
		t.Skipf("overlayfs unavailable: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(merged, syscall.MNT_DETACH) })

	if err := h.loader.EnableIntegrity([]Digest{d}, IntegrityEnforce); err != nil {
		t.Fatalf("EnableIntegrity: %v", err)
	}
	t.Cleanup(func() { _ = h.loader.SetIntegrityMode(IntegrityOff) })

	h.runOK(filepath.Join(merged, "app"), "image binary on overlayfs blocked")

	dropped := filepath.Join(merged, "dropped")
	if err := os.WriteFile(dropped, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	requireExecDenied(t, h.run(dropped))
}
