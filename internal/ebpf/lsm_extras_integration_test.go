//go:build integration

package ebpf

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// waitEvent reads LSM events until match returns true or the deadline passes.
func waitEvent(t *testing.T, loader *LSMLoader, match func(*Event) bool) *Event {
	t.Helper()
	found := make(chan *Event, 1)
	go func() {
		for {
			ev, err := loader.ReadLSMEvent()
			if err != nil {
				return
			}
			if match(ev) {
				found <- ev
				return
			}
		}
	}()
	select {
	case ev := <-found:
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("no matching LSM event within 5s")
		return nil
	}
}

func TestLSM_MountReportsSource(t *testing.T) {
	requireRoot(t)
	requireLSM(t)
	loader := loadLSMOrSkip(t)
	defer loader.Close()

	target := t.TempDir()
	// The source string is reported as given; tmpfs ignores it.
	if err := syscall.Mount("warmor-test-src", target, "tmpfs", 0, ""); err != nil {
		t.Fatalf("mount: %v", err)
	}
	defer syscall.Unmount(target, 0)

	ev := waitEvent(t, loader, func(ev *Event) bool {
		return ev.Hook == "mount" && ev.MountSource == "warmor-test-src"
	})
	if ev.Filename != "tmpfs" {
		t.Errorf("mount event Filename = %q, want the fs type tmpfs", ev.Filename)
	}
}

func TestLSM_PtraceReportsTargetCgroup(t *testing.T) {
	requireRoot(t)
	requireLSM(t)
	loader := loadLSMOrSkip(t)
	defer loader.Close()

	cgPath := filepath.Join("/sys/fs/cgroup", "warmor-ptrace-target")
	if err := os.Mkdir(cgPath, 0o755); err != nil && !os.IsExist(err) {
		t.Skipf("cannot create cgroup: %v", err)
	}
	defer os.Remove(cgPath)
	fd, err := syscall.Open(cgPath, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	wantCg, err := ResolveCgroupID(cgPath)
	if err != nil {
		t.Fatal(err)
	}

	// Target runs in its own cgroup; we (the tracer) do not.
	cmd := exec.Command("/bin/sleep", "10")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()

	if err := syscall.PtraceAttach(cmd.Process.Pid); err == nil {
		syscall.PtraceDetach(cmd.Process.Pid)
	}

	ev := waitEvent(t, loader, func(ev *Event) bool { return ev.Hook == "ptrace" && ev.Filename == "sleep" })
	if ev.TargetCgroupID != wantCg {
		t.Errorf("TargetCgroupID = %d, want %d", ev.TargetCgroupID, wantCg)
	}
	if ev.TargetCgroupID == ev.CgroupID {
		t.Error("target cgroup equals tracer cgroup; test setup did not separate them")
	}
}

func TestLSM_UnixConnectWatched(t *testing.T) {
	requireRoot(t)
	requireLSM(t)
	loader := loadLSMOrSkip(t)
	defer loader.Close()

	dir := t.TempDir()
	watched := filepath.Join(dir, "watched.sock")
	unwatched := filepath.Join(dir, "other.sock")
	for _, p := range []string{watched, unwatched} {
		l, err := net.Listen("unix", p)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
	}
	if err := loader.SetUnixWatch([]string{watched}); err != nil {
		t.Fatalf("SetUnixWatch: %v", err)
	}

	// Connect to the unwatched one first: it must not be reported, so the
	// first connect_unix event seen has to be the watched path.
	for _, p := range []string{unwatched, watched} {
		c, err := net.Dial("unix", p)
		if err != nil {
			t.Fatalf("dial %s: %v", p, err)
		}
		c.Close()
	}
	ev := waitEvent(t, loader, func(ev *Event) bool { return ev.Hook == "connect_unix" })
	if ev.Filename != watched {
		t.Errorf("first reported unix connect = %q, want %q (unwatched leaked?)", ev.Filename, watched)
	}

	if err := loader.SetUnixWatch([]string{string(make([]byte, 200))}); err == nil {
		t.Error("SetUnixWatch accepted an over-long path")
	}
}
