//go:build linux

package enforcer

import "github.com/yasindce1998/warmor/internal/ebpf"

// The Linux LSM policy map must satisfy both syncer interfaces, or network
// decisions silently fall back to string keys the kernel never looks up.
var (
	_ PolicyMapSyncer         = (*ebpf.PolicyMapManager)(nil)
	_ endpointPolicyMapSyncer = (*ebpf.PolicyMapManager)(nil)
)
