package container

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// userHZ is the unit of /proc/<pid>/stat time fields (USER_HZ). It is 100
// on every architecture Linux containers run on; the kernel converts its
// internal HZ to it for userspace.
const userHZ = 100

// readPIDs parses a cgroup.procs file. Unreadable files yield no pids.
func readPIDs(path string) []int {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var pids []int
	for _, f := range bytes.Fields(data) {
		if pid, err := strconv.Atoi(string(f)); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids
}

// processStartTime returns when pid started, from field 22 (starttime, in
// clock ticks since boot, CLOCK_BOOTTIME since Linux 5.5) of
// procRoot/<pid>/stat. wall and sinceBoot are the wall clock and the time
// since boot at one instant, which converts boot-relative to wall time.
func processStartTime(procRoot string, pid int, wall time.Time, sinceBoot time.Duration) (time.Time, bool) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return time.Time{}, false
	}
	ticks, ok := parseStartTicks(data)
	if !ok {
		return time.Time{}, false
	}
	started := time.Duration(ticks) * (time.Second / userHZ)
	if started > sinceBoot {
		// Can't start in the future; tolerate one tick of rounding.
		if started-sinceBoot > time.Second/userHZ {
			return time.Time{}, false
		}
		started = sinceBoot
	}
	return wall.Add(-(sinceBoot - started)), true
}

// parseStartTicks extracts starttime from a /proc/<pid>/stat line. The comm
// field (2) is parenthesised and may itself contain spaces and parentheses,
// so fields are counted from the last ')'.
func parseStartTicks(stat []byte) (uint64, bool) {
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, false
	}
	fields := bytes.Fields(stat[i+1:])
	// fields[0] is field 3 (state), so field 22 is fields[19].
	const idx = 22 - 3
	if len(fields) <= idx {
		return 0, false
	}
	v, err := strconv.ParseUint(string(fields[idx]), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
