//go:build integration

package ebpf

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// countFileEvents reads LSM events until the reader is closed, counting
// file_open misses for name.
func countFileEvents(l *LSMLoader, name string, n *atomic.Int64, done chan<- struct{}) {
	defer close(done)
	for {
		ev, err := l.ReadLSMEvent()
		if err != nil {
			return
		}
		if ev.Hook == "file" && ev.Filename == name {
			n.Add(1)
		}
	}
}

// TestLSM_EventLossIsCounted floods file opens into a deliberately small ring
// and checks that every open is accounted for: either delivered to userspace
// or counted in lsm_drops. A silent loss would be an operation nobody
// evaluated and nobody knows about.
func TestLSM_EventLossIsCounted(t *testing.T) {
	requireRoot(t)
	requireLSM(t)
	loader, err := LoadLSMWithOptions(LSMOptions{RingBufferSize: uint32(os.Getpagesize())})
	if err != nil {
		t.Fatalf("LoadLSMWithOptions: %v", err)
	}
	if loader == nil {
		t.Skip("BPF LSM unavailable")
	}

	name := "warmor-loss-probe"
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	before, err := loader.EventDrops()
	if err != nil {
		t.Fatal(err)
	}

	var delivered atomic.Int64
	done := make(chan struct{})
	go countFileEvents(loader, name, &delivered, done)

	const opens = 20000
	for i := 0; i < opens; i++ {
		fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		_ = syscall.Close(fd)
	}

	// Let the reader drain what was queued (it polls every lsmPollInterval).
	deadline := time.Now().Add(5 * time.Second)
	for last := int64(-1); time.Now().Before(deadline); {
		time.Sleep(50 * time.Millisecond)
		if cur := delivered.Load(); cur == last {
			break
		} else {
			last = cur
		}
	}

	after, err := loader.EventDrops()
	if err != nil {
		t.Fatal(err)
	}
	loader.Close()
	<-done

	dropped := int64(after["file"] - before["file"])
	got := delivered.Load()
	t.Logf("opens=%d delivered=%d dropped=%d (one-page ring)", opens, got, dropped)
	if dropped == 0 {
		t.Fatal("a one-page ring under a 20k-open flood reported no drops; is lsm_drops counting?")
	}
	// Other processes in the VM may open files too, so allow drops from them,
	// but every probe open must be delivered or counted.
	if got+dropped < opens {
		t.Fatalf("%d of %d opens neither delivered nor counted as dropped", opens-got-dropped, opens)
	}
}

// TestLSM_OnEventLossDeny checks that with --on-event-loss=deny and enforce
// mode, an exec whose event cannot be queued is refused instead of allowed
// unevaluated, and that the default allows it.
func TestLSM_OnEventLossDeny(t *testing.T) {
	requireRoot(t)
	requireLSM(t)

	for _, tc := range []struct {
		mode     OnEventLoss
		wantDeny bool
	}{
		{OnLossLog, false},
		{OnLossDeny, true},
	} {
		loader, err := LoadLSMWithOptions(LSMOptions{RingBufferSize: uint32(os.Getpagesize()), OnEventLoss: tc.mode})
		if err != nil {
			t.Fatalf("LoadLSMWithOptions: %v", err)
		}
		if loader == nil {
			t.Skip("BPF LSM unavailable")
		}
		if err := loader.SetEnforceMode(true); err != nil {
			t.Fatal(err)
		}

		// Fill the ring with nobody reading it: file_open misses queue until
		// the one-page ring is full.
		path := filepath.Join(t.TempDir(), "filler")
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 200; i++ {
			fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			_ = syscall.Close(fd)
		}

		// /bin/true has no policy map entry, so its exec is a miss whose event
		// cannot be queued.
		pid, ferr := syscall.ForkExec("/bin/true", []string{"true"}, &syscall.ProcAttr{})
		denied := errors.Is(ferr, syscall.EPERM)
		if ferr == nil {
			var ws syscall.WaitStatus
			_, _ = syscall.Wait4(pid, &ws, 0, nil)
		}
		loader.Close()

		if denied != tc.wantDeny {
			t.Errorf("on-event-loss=%d: exec denied=%v (err %v), want denied=%v", tc.mode, denied, ferr, tc.wantDeny)
		}
	}
}
