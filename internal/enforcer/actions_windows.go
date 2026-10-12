//go:build windows

package enforcer

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

// errPIDReused means the PID now belongs to a process created after the
// event, so the process the event was about has already exited.
var errPIDReused = errors.New("PID reused by a newer process")

// terminateEventProcess terminates the process an event came from. Windows
// recycles PIDs quickly and ETW delivers events late, so the PID may already
// belong to another process: the process is only terminated if it was
// created no later than the event. The check and the termination use the
// same handle, so the process cannot change between them.
func terminateEventProcess(pid uint32, seen time.Time) error {
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()

	if !seen.IsZero() {
		var created, exited, kernel, user windows.Filetime
		if err := windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
			return fmt.Errorf("GetProcessTimes(%d): %w", pid, err)
		}
		if time.Unix(0, created.Nanoseconds()).After(seen) {
			return fmt.Errorf("TerminateProcess(%d): %w", pid, errPIDReused)
		}
	}

	if err := windows.TerminateProcess(handle, 1); err != nil {
		return fmt.Errorf("TerminateProcess(%d): %w", pid, err)
	}
	return nil
}
