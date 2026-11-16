//go:build windows

package enforcer

import (
	"errors"
	"fmt"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
	"golang.org/x/sys/windows"
)

// errPIDReused means the PID now belongs to a process created after the
// event, so the process the event was about has already exited.
var errPIDReused = errors.New("PID reused by a newer process")

// pidReuseSkew tolerates small differences between the sensor's creation
// time and GetProcessTimes. FILETIME conversion and ETW timestamp granularity
// can differ by a few ticks; treating any difference as PID reuse would fail
// open and leave the real offender alive.
const pidReuseSkew = 2 * time.Second

// terminateEventProcess terminates the process an event came from. Windows
// recycles PIDs quickly and kernel events can be delayed, so the PID may
// already belong to another process. Prefer the creation time captured by the
// kernel at hook time (ProcessCreateTime); otherwise fall back to the event
// time. The check and termination use the same handle.
func terminateEventProcess(event *api.Event) (bool, error) {
	pid, seen := event.PID, event.ProcessCreateTime
	if seen.IsZero() {
		seen = event.Timestamp
	}
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()

	if !seen.IsZero() {
		var created, exited, kernel, user windows.Filetime
		if err := windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
			return false, fmt.Errorf("GetProcessTimes(%d): %w", pid, err)
		}
		if time.Unix(0, created.Nanoseconds()).After(seen.Add(pidReuseSkew)) {
			return false, fmt.Errorf("TerminateProcess(%d): %w", pid, errPIDReused)
		}
	}

	if err := windows.TerminateProcess(handle, 1); err != nil {
		return true, fmt.Errorf("TerminateProcess(%d): %w", pid, err)
	}
	return true, nil
}
