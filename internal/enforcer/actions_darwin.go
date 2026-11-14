//go:build darwin

package enforcer

import (
	"fmt"
	"github.com/yasindce1998/warmor/pkg/api"
	"syscall"
)

// terminateProcess forcefully kills a process by PID using SIGKILL.
func terminateProcess(pid uint32) error {
	if err := syscall.Kill(int(pid), syscall.SIGKILL); err != nil {
		return fmt.Errorf("kill(%d, SIGKILL): %w", pid, err)
	}
	return nil
}

// The verified Linux pidfd path does not apply to this experimental backend.
func terminateEventProcess(event *api.Event) (bool, error) {
	return true, terminateProcess(event.PID)
}
