//go:build darwin

package enforcer

import (
	"fmt"
	"syscall"
	"time"
)

// terminateProcess forcefully kills a process by PID using SIGKILL.
func terminateProcess(pid uint32) error {
	if err := syscall.Kill(int(pid), syscall.SIGKILL); err != nil {
		return fmt.Errorf("kill(%d, SIGKILL): %w", pid, err)
	}
	return nil
}

// terminateEventProcess kills the process an event came from. PIDs are not
// reused fast enough on Unix for the event time to matter.
func terminateEventProcess(pid uint32, _ time.Time) error {
	return terminateProcess(pid)
}
