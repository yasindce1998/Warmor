//go:build linux || darwin

package compiler

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

func runOwnedTool(ctx context.Context, cmd *exec.Cmd, overflow <-chan struct{}) error {
	// No caller-supplied group, no discovery via Getpgid, and no positive-PID
	// fallback: Start must establish a new group led by this exact child.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Do not call Wait (even in a goroutine) until after group cleanup. Keeping
	// the leader unreaped pins its PID/PGID even if it exits before its children.
	exited, closeObserver, err := observeToolExit(cmd.Process.Pid)
	if err == nil {
		defer closeObserver()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
	loop:
		for {
			var done bool
			done, err = exited()
			if err != nil || done {
				break
			}
			select {
			case <-ctx.Done():
				err = ctx.Err()
				break loop
			case <-overflow:
				err = errToolOutputLimit
				break loop
			case <-ticker.C:
			}
		}
	}
	// Also clean up children after an ordinary parent exit. A tool is not
	// entitled to leave background work running after its command completes.
	// ECHILD means an external reaper violated ownership; do not signal an ID
	// that can no longer be proven to belong to this command.
	if !errors.Is(err, syscall.ECHILD) {
		killErr := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if killErr != nil && !errors.Is(killErr, syscall.ESRCH) {
			err = errors.Join(err, fmt.Errorf("kill owned toolchain group: %w", killErr))
		}
	}
	waitErr := cmd.Wait()
	return errors.Join(err, waitErr)
}
