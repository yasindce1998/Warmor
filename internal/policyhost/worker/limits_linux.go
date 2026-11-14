//go:build linux

package worker

import (
	"runtime"

	"github.com/yasindce1998/warmor/internal/policyhost/protocol"
	"golang.org/x/sys/unix"
)

func applyLimits(l protocol.Limits) error {
	// rlimits apply to the entire process, including wazero compiler threads.
	// They must be established successfully before acknowledging module input.
	for _, r := range []struct {
		resource int
		value    uint64
	}{
		{unix.RLIMIT_AS, l.AddressSpaceBytes},
		{unix.RLIMIT_CPU, l.CPUSeconds},
		{unix.RLIMIT_CORE, 0},
		{unix.RLIMIT_FSIZE, 0},
		{unix.RLIMIT_NOFILE, 32},
	} {
		if err := unix.Setrlimit(r.resource, &unix.Rlimit{Cur: r.value, Max: r.value}); err != nil {
			return err
		}
	}
	// Do not claim process-wide seccomp/no-new-privileges: prctl is per-thread
	// and Go has already started threads. DUMPABLE is process-wide.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
