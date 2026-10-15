//go:build linux

package container

import (
	"time"

	"golang.org/x/sys/unix"
)

// bootClockNow returns the wall clock and CLOCK_BOOTTIME (time since boot,
// including suspend), read back to back.
func bootClockNow() (time.Time, time.Duration, bool) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return time.Time{}, 0, false
	}
	return time.Now(), time.Duration(ts.Nano()), true
}
