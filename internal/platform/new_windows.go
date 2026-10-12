//go:build windows
// +build windows

package platform

import "log"

// New creates a platform instance for the current OS. The LSM flags map to
// eBPF-for-Windows: --no-lsm uses ETW only, --require-lsm fails startup
// unless an eBPF hook attaches. --lsm-enforce has no effect; eBPF hooks
// enforce whenever they load.
func New(cfg Config) (Platform, error) {
	if len(cfg.CgroupFilter) > 0 {
		log.Println("⚠ Cgroup filtering is not available on Windows; flag ignored")
	}
	return NewWindowsPlatform(WindowsConfig{
		SkipEBPF:    cfg.SkipLSM,
		RequireEBPF: cfg.RequireLSM,
	})
}
