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
)

// spawnSleeper starts a throwaway child process that the test may kill.
func spawnSleeper(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "60")
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

func TestTerminateProcess_KillsChild(t *testing.T) {
	cmd := spawnSleeper(t)
	if err := terminateProcess(uint32(cmd.Process.Pid)); err != nil {
		t.Fatalf("terminateProcess: %v", err)
	}
	waitKilled(t, cmd)
}

func TestTerminateProcess_NonexistentPID(t *testing.T) {
	cmd := spawnSleeper(t)
	pid := uint32(cmd.Process.Pid)
	_ = cmd.Process.Kill()
	_ = cmd.Wait() // reaped: PID no longer exists

	err := terminateProcess(pid)
	if err == nil {
		t.Fatal("expected error killing a reaped PID")
	}
	if !errors.Is(err, syscall.ESRCH) {
		t.Errorf("expected ESRCH, got %v", err)
	}
}

func TestActionHandler_DenyKillsProcess(t *testing.T) {
	cmd := spawnSleeper(t)
	handler := NewActionHandler(false)

	event := &api.Event{PID: uint32(cmd.Process.Pid), Comm: "sleep", Filename: "/usr/bin/sleep"}
	result := &api.ActionResult{Action: api.ActionDeny, Reason: "test deny"}
	if err := handler.Enforce(context.Background(), event, result); err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	waitKilled(t, cmd)

	if got := handler.GetStats().Denied; got != 1 {
		t.Errorf("Denied = %d, want 1", got)
	}
}

func TestActionHandler_DenyAlreadyExitedProcessIsNotError(t *testing.T) {
	cmd := spawnSleeper(t)
	pid := uint32(cmd.Process.Pid)
	_ = cmd.Process.Kill()
	_ = cmd.Wait()

	handler := NewActionHandler(false)
	err := handler.Enforce(context.Background(), &api.Event{PID: pid}, &api.ActionResult{Action: api.ActionDeny})
	if err != nil {
		t.Errorf("deny on exited process should be tolerated, got %v", err)
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
	if err := e.Sandbox().ApplySandbox(pid, "network-deny"); err != nil {
		t.Fatal(err)
	}
	e.handleEvent(&api.Event{
		PID:     pid,
		Comm:    "sleep",
		Network: &api.NetworkEvent{BaseEvent: api.BaseEvent{Type: api.EventTypeNetwork}, RemoteAddr: "8.8.8.8"},
	})
	waitKilled(t, cmd)
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
