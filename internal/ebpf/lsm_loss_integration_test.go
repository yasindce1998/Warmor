//go:build integration

package ebpf

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
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

// fillLSMRingForLoss fills a one-page LSM ring with file_open misses while
// nobody is reading it. file_open is an audit-only hook: even with
// --on-event-loss=deny its events are counted but the opens still succeed, so
// the flood itself cannot be refused (and it leaves no reader to drain the
// events the hook under test is about to drop).
func fillLSMRingForLoss(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "filler")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
		if err != nil {
			t.Fatalf("filler open: %v (audit hook must not fail closed)", err)
		}
		_ = syscall.Close(fd)
	}
}

// TestLSM_OnEventLossDenyBlockingHooks extends the exec/connect coverage to
// every blocking hook. With --on-event-loss=deny and enforce on, an operation
// whose miss event cannot be queued must be refused with EPERM so that a
// flood cannot hide a would-be denial. With the default log mode it must
// still be allowed (and the drop counted). Audit-only hooks (file, integrity)
// must keep allowing on a drop — the filler opens above are an implicit
// check of that for file_open.
func TestLSM_OnEventLossDenyBlockingHooks(t *testing.T) {
	requireRoot(t)
	requireLSM(t)

	// run performs the target operation, calling fill() at the point where
	// the ring must already be full. hook is the lsm_drops label for the
	// event the operation emits.
	type scenario struct {
		name string
		hook string
		run  func(t *testing.T, fill func()) error
	}

	local := net.IPv4(127, 0, 0, 1).To4()
	scenarios := []scenario{
		{
			name: "bind",
			hook: "bind",
			run: func(t *testing.T, fill func()) error {
				fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer syscall.Close(fd)
				addr := &syscall.SockaddrInet4{}
				copy(addr.Addr[:], local)
				fill()
				return syscall.Bind(fd, addr)
			},
		},
		{
			name: "listen",
			hook: "listen",
			run: func(t *testing.T, fill func()) error {
				fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer syscall.Close(fd)
				addr := &syscall.SockaddrInet4{}
				copy(addr.Addr[:], local)
				// The listen hook ignores port 0, so bind to an
				// ephemeral port before the ring is full.
				if err := syscall.Bind(fd, addr); err != nil {
					t.Fatal(err)
				}
				fill()
				return syscall.Listen(fd, 1)
			},
		},
		{
			name: "ptrace",
			hook: "ptrace",
			run: func(t *testing.T, fill func()) error {
				cmd := exec.Command("/bin/sleep", "30")
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
				// Confirm the environment permits ptrace at all, so
				// an EPERM from the LSM is not confused with a
				// Yama/capability restriction.
				if err := syscall.PtraceAttach(cmd.Process.Pid); err != nil {
					t.Skipf("ptrace not permitted here: %v", err)
				}
				_ = syscall.PtraceDetach(cmd.Process.Pid)
				time.Sleep(20 * time.Millisecond)
				fill()
				err := syscall.PtraceAttach(cmd.Process.Pid)
				if err == nil {
					_ = syscall.PtraceDetach(cmd.Process.Pid)
				}
				return err
			},
		},
		{
			name: "mount",
			hook: "mount",
			run: func(t *testing.T, fill func()) error {
				// Confirm the environment permits mounting tmpfs.
				probe := t.TempDir()
				if err := syscall.Mount("warmor-test-src", probe, "tmpfs", 0, ""); err != nil {
					t.Skipf("mount not permitted here: %v", err)
				}
				_ = syscall.Unmount(probe, 0)
				target := t.TempDir()
				fill()
				err := syscall.Mount("warmor-test-src", target, "tmpfs", 0, "")
				if err == nil {
					_ = syscall.Unmount(target, 0)
				}
				return err
			},
		},
	}

	for _, s := range scenarios {
		for _, mode := range []OnEventLoss{OnLossLog, OnLossDeny} {
			t.Run(fmt.Sprintf("%s/%d", s.name, mode), func(t *testing.T) {
				loader, err := LoadLSMWithOptions(LSMOptions{
					RingBufferSize: uint32(os.Getpagesize()),
					OnEventLoss:    mode,
				})
				if err != nil {
					t.Fatalf("LoadLSMWithOptions: %v", err)
				}
				if loader == nil {
					t.Skip("BPF LSM unavailable")
				}
				defer loader.Close()
				if err := loader.SetEnforceMode(true); err != nil {
					t.Fatal(err)
				}

				// Snapshot drops right after the flood, so the assertion
				// below measures only the operation's own ring-full emit
				// and not background activity during the flood.
				var beforeOp map[string]uint64
				opErr := s.run(t, func() {
					fillLSMRingForLoss(t)
					var err error
					beforeOp, err = loader.EventDrops()
					if err != nil {
						t.Fatal(err)
					}
				})
				after, err := loader.EventDrops()
				if err != nil {
					t.Fatal(err)
				}

				denied := errors.Is(opErr, syscall.EPERM)
				wantDeny := mode == OnLossDeny
				if denied != wantDeny {
					t.Errorf("on-event-loss=%d: %s denied=%v (err %v), want denied=%v",
						mode, s.name, denied, opErr, wantDeny)
				}
				// The verdict only comes from the ring-full path if the
				// operation actually tried (and failed) to emit.
				if delta := after[s.hook] - beforeOp[s.hook]; delta == 0 {
					t.Errorf("%s: no dropped %s event; ring-full path was not exercised",
						s.name, s.hook)
				}
			})
		}
	}
}
