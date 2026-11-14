//go:build linux

package enforcer

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
	"golang.org/x/sys/unix"
)

// spawnSleeper starts a throwaway child process that the test may kill.
func spawnSleeper(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot spawn sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

// waitKilled waits for cmd to exit and asserts it died from SIGKILL.
func waitKilled(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected child to be killed, Wait() = %v", err)
		}
		ws, ok := exitErr.Sys().(syscall.WaitStatus)
		if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
			t.Fatalf("expected SIGKILL, got %v", exitErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("child was not terminated")
	}
}

func verifiedChildEvent(t *testing.T, cmd *exec.Cmd) *api.Event {
	t.Helper()
	if err := verifySignalingNamespaces(); err != nil {
		t.Skipf("verified signaling unavailable: %v", err)
	}
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		t.Skipf("pidfds unavailable: %v", err)
	}
	_ = unix.Close(fd)
	start, err := readProcessStartTicks(uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	hz, err := readClockTicks()
	if err != nil {
		t.Fatal(err)
	}
	upper, err := startTickUpperNS(start, hz)
	if err != nil {
		t.Fatal(err)
	}
	now, err := monotonicNowNS()
	if err != nil {
		t.Fatal(err)
	}
	if eventBoot := signalingClockBaseline.eventBootLower(now); upper > eventBoot && upper-eventBoot > uint64(100*time.Millisecond) {
		t.Skip("conservative clock check unavailable for young child after additional suspend")
	}
	for signalingClockBaseline.eventBootLower(now) <= upper {
		time.Sleep(time.Millisecond)
		now, err = monotonicNowNS()
		if err != nil {
			t.Fatal(err)
		}
	}
	return &api.Event{PID: uint32(cmd.Process.Pid), KernelTimestampNS: now, Timestamp: time.Now()}
}

func TestTerminateEventProcess_KillsIsolatedChild(t *testing.T) {
	cmd := spawnSleeper(t)
	event := verifiedChildEvent(t, cmd)
	if attempted, err := terminateEventProcess(event); !attempted || err != nil {
		t.Fatalf("terminateEventProcess = %v, %v", attempted, err)
	}
	waitKilled(t, cmd)
}

func TestTerminateEventProcess_ExitedChild(t *testing.T) {
	cmd := spawnSleeper(t)
	event := verifiedChildEvent(t, cmd)
	_ = cmd.Process.Kill()
	_ = cmd.Wait() // reaped: PID no longer exists

	attempted, err := terminateEventProcess(event)
	if err == nil {
		t.Fatal("expected error killing a reaped PID")
	}
	if !errors.Is(err, syscall.ESRCH) {
		t.Errorf("expected ESRCH, got %v", err)
	}
	if attempted {
		t.Error("exited child must not reach signal syscall")
	}
}

func TestActionHandler_DenyKillsProcess(t *testing.T) {
	cmd := spawnSleeper(t)
	handler := NewActionHandler(false)

	event := verifiedChildEvent(t, cmd)
	result := &api.ActionResult{Action: api.ActionDeny, Reason: "test deny"}
	if err := handler.Enforce(context.Background(), event, result); err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	waitKilled(t, cmd)

	if got := handler.GetStats().Denied; got != 1 {
		t.Errorf("Denied = %d, want 1", got)
	}
	if !result.EnforcementAttempted || !result.Enforced || result.EnforcementError != "" {
		t.Fatalf("incorrect successful outcome: %+v", result)
	}
}

func TestActionHandler_DenyAlreadyExitedProcessReportsRefusal(t *testing.T) {
	cmd := spawnSleeper(t)
	event := verifiedChildEvent(t, cmd)
	_ = cmd.Process.Kill()
	_ = cmd.Wait()

	handler := NewActionHandler(false)
	result := &api.ActionResult{Action: api.ActionDeny}
	err := handler.Enforce(context.Background(), event, result)
	if err == nil || result.Enforced || result.EnforcementAttempted || result.EnforcementError == "" {
		t.Errorf("exited process must report refused enforcement: result=%+v err=%v", result, err)
	}
}

func TestActionHandler_AuditModeDoesNotKill(t *testing.T) {
	cmd := spawnSleeper(t)
	handler := NewActionHandler(true)

	event := &api.Event{PID: uint32(cmd.Process.Pid)}
	if err := handler.Enforce(context.Background(), event, &api.ActionResult{Action: api.ActionDeny}); err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	// Signal 0 probes existence without affecting the process.
	if err := syscall.Kill(cmd.Process.Pid, 0); err != nil {
		t.Errorf("audit-mode deny must not kill the process: %v", err)
	}
}

func TestHandleEvent_SandboxViolationKillsProcess(t *testing.T) {
	cmd := spawnSleeper(t)
	pid := uint32(cmd.Process.Pid)

	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	event := verifiedChildEvent(t, cmd)
	if err := e.Sandbox().ApplySandbox(pid, "network-deny"); err != nil {
		t.Fatal(err)
	}
	event.Comm = "sleep"
	event.Network = &api.NetworkEvent{BaseEvent: api.BaseEvent{Type: api.EventTypeNetwork}, RemoteAddr: "8.8.8.8"}
	e.handleEvent(event)
	waitKilled(t, cmd)
	if stats := e.GetStats(); stats.EnforcementAttempted != 1 || stats.EnforcementSucceeded != 1 || stats.EnforcementFailed != 0 || stats.EnforcementRefused != 0 {
		t.Fatalf("lost outcomes: %+v", stats)
	}
}

func TestReloadPolicy_RuntimeCreationError(t *testing.T) {
	// Point the user cache dir at a regular file so MkdirAll fails.
	dir := t.TempDir()
	notADir := dir + "/file"
	if err := writeFile(notADir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CACHE_HOME", notADir)

	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	oldEval := e.evaluator
	err := e.ReloadPolicy()
	if err == nil {
		t.Fatal("expected error when cache dir cannot be created")
	}
	if e.evaluator != oldEval {
		t.Error("evaluator must not change on failed reload")
	}
}

func writeFile(path string) error {
	return os.WriteFile(path, []byte("x"), 0o600)
}
