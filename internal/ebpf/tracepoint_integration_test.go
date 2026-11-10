//go:build integration

package ebpf

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// TestTracepointExec_CapturesArgvAndParent loads the exec tracepoint
// monitor, runs a child exec, and checks the emitted event carries the
// command's argv and the parent's comm and PID — the ABI version 4
// capture (see docs/design/abi-v4-process-context.md). It doubles as the
// verifier exercise for the argv walk and the CO-RE parent read, which
// clang alone does not prove.
func TestTracepointExec_CapturesArgvAndParent(t *testing.T) {
	requireRoot(t)

	loader, err := Load()
	if err != nil {
		// requireRoot already skipped the non-root case, and the kernels
		// this runs on in CI all support syscall tracepoints and BTF (they
		// run the CO-RE LSM programs), so a failure here is a real load or
		// verifier problem, not a missing capability.
		t.Fatalf("Load tracepoint monitors: %v", err)
	}
	defer loader.Close()

	events := make(chan *Event, 256)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			ev, err := loader.ReadProcessEvent()
			if err != nil {
				return // reader closed (or failed); loader.Close follows
			}
			select {
			case events <- ev:
			default: // never block the reader; drop rather than stall
			}
		}
	}()

	const script = "exit 42"
	cmd := exec.Command("/bin/sh", "-c", script)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	pid := cmd.Process.Pid

	var got *Event
	deadline := time.Now().Add(10 * time.Second)
	for got == nil && time.Now().Before(deadline) {
		select {
		case ev := <-events:
			if ev.PID == uint32(pid) {
				got = ev
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	_ = cmd.Wait()

	if got == nil {
		t.Fatalf("no exec event for child pid %d within 10s", pid)
	}

	if want := []string{"/bin/sh", "-c", script}; !slices.Equal(got.Args, want) {
		t.Errorf("Args = %q, want %q", got.Args, want)
	}
	if got.PPID != uint32(os.Getpid()) {
		t.Errorf("PPID = %d, want %d (the test process)", got.PPID, os.Getpid())
	}
	// comm is 15 characters at most, like the kernel's TASK_COMM_LEN.
	wantParent := filepath.Base(os.Args[0])
	if len(wantParent) > 15 {
		wantParent = wantParent[:15]
	}
	if got.ParentComm != wantParent {
		t.Errorf("ParentComm = %q, want %q", got.ParentComm, wantParent)
	}
}
