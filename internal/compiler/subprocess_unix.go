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
	if err := prepareOwnedTool(); err != nil {
		return err
	}
	// No caller-supplied group, no discovery via Getpgid, and no positive-PID
	// fallback: Start must establish a new group led by this exact child.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Do not call Wait (even in a goroutine) until after group cleanup. Keeping
	// the leader unreaped pins its PID/PGID even if it exits before its children.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var err error
	probeFailed := false
loop:
	for {
		var done bool
		done, err = toolChildExited(cmd.Process.Pid)
		if err != nil || done {
			probeFailed = err != nil
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
	// Also clean up children after an ordinary parent exit. A tool is not
	// entitled to leave background work running after its command completes.
	// Recheck wait ownership immediately before signaling, including when
	// cancellation wins the select. Never signal after ECHILD or probe failure.
	if !probeFailed {
		if killErr := killOwnedToolGroup(cmd.Process.Pid); killErr != nil {
			err = errors.Join(err, fmt.Errorf("kill owned toolchain group: %w", killErr))
		}
	}
	waitErr := cmd.Wait()
	return errors.Join(err, waitErr)
}
