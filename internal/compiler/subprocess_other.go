//go:build !linux && !darwin

package compiler

import (
	"context"
	"os/exec"
)

// Windows and other platforms retain parent-only cancellation. In particular,
// this is NOT a Windows Job Object implementation: assigning a running process
// to a job leaves a child-spawn race. Do not claim tree containment here.
func runOwnedTool(ctx context.Context, cmd *exec.Cmd, overflow <-chan struct{}) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	case <-overflow:
	}
	// os.Process is the owned process handle, not a rediscovered arbitrary PID.
	_ = cmd.Process.Kill()
	return <-done
}
