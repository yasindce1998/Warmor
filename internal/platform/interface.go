package platform

import (
	"context"

	"github.com/yasindce1998/warmor/pkg/api"
)

// Platform represents the OS-specific implementation
type Platform interface {
	// Name returns the platform name
	Name() string

	// Load initializes the platform-specific monitoring
	Load(ctx context.Context) error

	// Start begins event monitoring
	Start(ctx context.Context, eventChan chan<- *api.Event) error

	// Stop stops event monitoring
	Stop() error

	// Close cleans up resources
	Close() error

	// Capabilities returns what this platform supports
	Capabilities() Capabilities

	// PolicyMap returns the LSM policy map manager, or nil if unavailable.
	PolicyMap() any
}

// Capabilities describes platform features
type Capabilities struct {
	ProcessMonitoring bool // Can monitor process execution
	FileMonitoring    bool // Can monitor file operations
	NetworkMonitoring bool // Can monitor network operations
	Enforcement       bool // Can actually block, not just log
	LSMEnforcement    bool // Kernel-level blocking via LSM-BPF
}

// Config holds platform-agnostic configuration passed to New().
//
// NOTE: LinuxConfig is derived from Config via a direct struct conversion
// (LinuxConfig(cfg) in new_linux.go), so the two must keep identical fields
// in the same order.
type Config struct {
	CgroupFilter []string
	LSMEnforce   bool
	// RequireLSM makes BPF-LSM kernel enforcement mandatory: if the LSM
	// programs cannot be loaded (unsupported kernel, missing BTF, verifier
	// rejection), Load fails instead of silently falling back to
	// tracepoint-only observation. This selects fail-closed startup.
	RequireLSM bool
	// SkipLSM disables LSM-BPF program loading entirely, running in
	// tracepoint-only observe mode regardless of kernel capabilities.
	SkipLSM bool
	// IntegrityMode is "off", "audit" or "enforce". Anything but off loads
	// the content-hash exec check with IntegrityDigests (hex SHA-256) as
	// the allowlist; failing to load it is fatal, since the operator asked
	// for it explicitly. Linux only.
	IntegrityMode    string
	IntegrityDigests []string
	// UnixWatch lists unix socket paths whose connects the kernel reports
	// (Linux LSM only); used for container runtime socket access detection.
	UnixWatch []string
	// LSMRingBufferSize is the LSM event ring size in bytes (0 = default).
	LSMRingBufferSize uint32
	// OnEventLoss is "log" (default) or "deny": what the kernel does with an
	// unknown exec/connect whose event can't be queued because the ring is
	// full. Linux LSM only.
	OnEventLoss string
}

// Current returns the platform for the current OS with default config.
func Current() (Platform, error) {
	return New(Config{})
}
