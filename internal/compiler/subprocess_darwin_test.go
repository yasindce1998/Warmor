package compiler

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestDarwinZombieOnlyPermissionResult(t *testing.T) {
	for _, exited := range []bool{false, true} {
		t.Run(map[bool]string{false: "live-member", true: "zombie-only"}[exited], func(t *testing.T) {
			mode := "cargo-slow"
			if exited {
				mode = "nonzero"
			}
			cmd := toolTestCommand(t, mode)
			cmd.Env = append(cmd.Env, "CARGO_TARGET_DIR="+t.TempDir())
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = killOwnedToolGroup(cmd.Process.Pid); _ = cmd.Wait() }()
			if exited {
				awaitToolExit(t, cmd.Process.Pid)
			}
			called := false
			err := killDarwinToolGroup(cmd.Process.Pid, func(group int, sig syscall.Signal) error {
				called = true
				if group != -cmd.Process.Pid || sig != syscall.SIGKILL {
					t.Fatalf("not the owned group: %d, %v", group, sig)
				}
				return syscall.EPERM
			})
			if !called || (exited && err != nil) || (!exited && !errors.Is(err, syscall.EPERM)) {
				t.Fatalf("exited=%v signalCalled=%v err=%v", exited, called, err)
			}
		})
	}
}

func TestDarwinRejectReapedLeaderBeforeSignal(t *testing.T) {
	cmd := toolTestCommand(t, "nonzero")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Wait() }() // join os/exec resources after the outside wait
	awaitToolExit(t, cmd.Process.Pid)
	var status unix.WaitStatus
	if _, err := unix.Wait4(cmd.Process.Pid, &status, 0, nil); err != nil {
		t.Fatal(err)
	}
	called := false
	err := killDarwinToolGroup(cmd.Process.Pid, func(int, syscall.Signal) error {
		called = true
		return nil
	})
	if called || !errors.Is(err, syscall.ECHILD) {
		t.Fatalf("reaped leader: signaled=%v err=%v", called, err)
	}
}

func TestDarwinZombieGroupEvidence(t *testing.T) {
	leader := unix.KinfoProc{}
	leader.Proc.P_pid, leader.Proc.P_stat = 123, darwinZombie
	leader.Eproc.Pgid, leader.Eproc.Ppid = 123, 42
	liveChild := leader
	liveChild.Proc.P_pid, liveChild.Proc.P_stat = 124, 2 // SRUN
	zombieChild := liveChild
	zombieChild.Proc.P_stat = darwinZombie
	wrongParent := leader
	wrongParent.Eproc.Ppid++
	wrongGroup := leader
	wrongGroup.Eproc.Pgid++
	for _, tc := range []struct {
		name    string
		members []unix.KinfoProc
		want    bool
	}{
		{"empty", nil, false},
		{"leader-only", []unix.KinfoProc{leader}, true},
		{"all-zombies", []unix.KinfoProc{leader, zombieChild}, true},
		{"live-child", []unix.KinfoProc{leader, liveChild}, false},
		{"missing-leader", []unix.KinfoProc{zombieChild}, false},
		{"wrong-parent", []unix.KinfoProc{wrongParent}, false},
		{"wrong-group", []unix.KinfoProc{wrongGroup}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := darwinGroupOnlyZombies(123, 42, tc.members); got != tc.want {
				t.Fatalf("zombie-only evidence = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDarwinRejectAutoReapBeforeStart(t *testing.T) {
	if mode := os.Getenv("WARMOR_DARWIN_WAIT_MODE"); mode != "" {
		// Change signal disposition only in this isolated test subprocess.
		if mode == "ignore" {
			signal.Ignore(syscall.SIGCHLD)
		} else {
			// __sigaction (kernel input) includes the trampoline pointer. No
			// handler is installed; SA_NOCLDWAIT with SIG_DFL needs no tramp.
			action := struct {
				handler, trampoline uintptr
				mask, flags         uint32
			}{flags: 0x20}
			_, _, errno := syscall.Syscall(unix.SYS_SIGACTION, uintptr(syscall.SIGCHLD), uintptr(unsafe.Pointer(&action)), 0)
			runtime.KeepAlive(&action)
			if errno != 0 {
				t.Fatal(errno)
			}
		}
		self, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
		if err != nil || self.Proc.P_flag&darwinNoChildWait == 0 {
			t.Fatalf("isolated fixture did not enable auto-reap mode %s: %v", mode, err)
		}
		cmd := exec.Command("/usr/bin/true")
		if _, err := runTool(context.Background(), cmd); err == nil || cmd.Process != nil {
			t.Fatalf("auto-reap mode %s must fail before Start: process=%v err=%v", mode, cmd.Process, err)
		}
		return
	}
	for _, mode := range []string{"ignore", "no-child-wait"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestDarwinRejectAutoReapBeforeStart$")
			cmd.Env = append(os.Environ(), "WARMOR_DARWIN_WAIT_MODE="+mode)
			if data, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("isolated signal-mode test: %v\n%s", err, data)
			}
		})
	}
}

func TestDarwinWaitidABI(t *testing.T) {
	var info darwinSiginfo
	if unsafe.Sizeof(info) != 104 || unsafe.Offsetof(info.pid) != 12 {
		t.Fatalf("unexpected Darwin siginfo_t ABI: size=%d si_pid offset=%d", unsafe.Sizeof(info), unsafe.Offsetof(info.pid))
	}
	// Exercise native success independently of fake-tool and artifact logic.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for range 20 {
		if _, err := runTool(ctx, exec.Command("/usr/bin/true")); err != nil {
			t.Fatalf("native fast-exit success: %v", err)
		}
	}
}

func TestDarwinCargoAvailableNormalExit(t *testing.T) {
	fakeToolchain(t, "success")
	if !CargoAvailable() {
		t.Fatal("successful rustup probe must not fail on zombie-only EPERM")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := Build(safetyPolicy(), BuildOptions{Context: ctx, OutputPath: filepath.Join(t.TempDir(), "policy.wasm")})
	defer Cleanup(result)
	if err != nil {
		t.Fatal(err)
	}
}
