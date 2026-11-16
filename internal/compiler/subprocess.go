package compiler

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

const (
	// Both streams share this budget, including in verbose mode.
	toolOutputLimit  = 1 << 20
	toolCheckTimeout = 10 * time.Second
	toolPipeWait     = time.Second
)

var errToolOutputLimit = errors.New("toolchain output exceeds 1048576-byte limit")

type toolOutput struct {
	stdout string
	stderr string
}

// toolCapture never blocks a copying goroutine, even after the budget is
// exhausted. The owner is notified to terminate the command; subsequent output
// is discarded until the pipes close. stdout and stderr may arrive concurrently.
type toolCapture struct {
	mu             sync.Mutex
	remaining      int
	stdout, stderr []byte
	overflow       chan struct{}
	exceeded       bool
}

type toolStream struct {
	capture *toolCapture
	stderr  bool
}

func (w toolStream) Write(p []byte) (int, error) {
	c := w.capture
	c.mu.Lock()
	defer c.mu.Unlock()
	n := min(len(p), c.remaining)
	if w.stderr {
		c.stderr = append(c.stderr, p[:n]...)
	} else {
		c.stdout = append(c.stdout, p[:n]...)
	}
	c.remaining -= n
	if n < len(p) && !c.exceeded {
		c.exceeded = true
		close(c.overflow)
	}
	return len(p), nil
}

// runTool owns cmd from Start through Wait. Do not pass a CommandContext: its
// independent cancellation/reaping lifecycle would break process-group ownership.
// All pipe writers are internal, bounded, and nonblocking; WaitDelay also closes
// pipes retained by descendants that deliberately leave the owned process group.
func runTool(ctx context.Context, cmd *exec.Cmd) (toolOutput, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return toolOutput{}, err
	}
	capture := &toolCapture{remaining: toolOutputLimit, overflow: make(chan struct{})}
	cmd.Stdout = toolStream{capture: capture}
	cmd.Stderr = toolStream{capture: capture, stderr: true}
	cmd.WaitDelay = toolPipeWait
	err := runOwnedTool(ctx, cmd, capture.overflow)
	// runOwnedTool always joins Cmd.Wait, including its pipe-copy goroutines.
	output := toolOutput{stdout: string(capture.stdout), stderr: string(capture.stderr)}
	if ctx.Err() != nil {
		return output, ctx.Err()
	}
	if capture.exceeded {
		return output, errToolOutputLimit
	}
	if err != nil {
		return output, fmt.Errorf("toolchain subprocess: %w", err)
	}
	return output, nil
}
