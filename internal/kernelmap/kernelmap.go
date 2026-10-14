// Package kernelmap holds definitions shared by the platform-specific kernel
// policy maps (Linux BPF-LSM, eBPF for Windows) and the enforcer that syncs
// decisions into them.
package kernelmap

import "errors"

// ErrNotKernelMatchable is returned (wrapped) by a policy map for a decision
// its kernel programs could not match exactly. Such decisions are refused
// rather than written, since a key that covers only part of what userspace
// decided on would apply the decision to other events; userspace keeps
// enforcing them. The enforcer counts these as skipped, not failed.
var ErrNotKernelMatchable = errors.New("decision cannot be matched exactly by the kernel programs")
