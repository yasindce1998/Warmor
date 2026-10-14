//go:build windows

package enforcer

import "github.com/yasindce1998/warmor/internal/platform/efw"

// The eBPF-for-Windows policy map must be clearable on reload and describe
// its kernel keys, or no decision is ever synced.
var (
	_ PolicyMapSyncer      = (*efw.PolicyMap)(nil)
	_ eventPolicyMapSyncer = (*efw.PolicyMap)(nil)
	_ kernelKeyFielder     = (*efw.PolicyMap)(nil)
)
