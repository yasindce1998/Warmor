//go:build !linux

package container

import "time"

// bootClockNow is unsupported off Linux: there are no cgroups to date.
func bootClockNow() (time.Time, time.Duration, bool) { return time.Time{}, 0, false }
