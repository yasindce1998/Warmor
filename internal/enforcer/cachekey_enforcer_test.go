package enforcer

import (
	"errors"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/pkg/api"
)

// TestCacheKeyInputsNeverSyncedToKernel verifies the feedback soundness of
// the two host-owned observations added to the decision cache key. The kernel
// policy map has no key for PPID or for the capture-quality mask: a decision
// that reads either must stay userspace-only, otherwise the kernel would keep
// applying it to events with a different parent or different capture loss.
func TestCacheKeyInputsNeverSyncedToKernel(t *testing.T) {
	pm := &fakePolicyMap{} // kernel keys: path (process), endpoint (network)
	e := &Enforcer{policyMap: pm}
	exec := &api.Event{Type: api.EventTypeProcess, Filename: "/bin/tool"}
	result := &api.ActionResult{Action: api.ActionDeny}
	path := compiler.FieldBitPath

	tests := []struct {
		name   string
		fields uint32
	}{
		{"path and ppid", path | compiler.FieldBitPPID},
		{"ppid only", compiler.FieldBitPPID},
		{"path and require-complete capture", path | compiler.FieldBitRequireCompleteCapture},
		{"require-complete capture only", compiler.FieldBitRequireCompleteCapture},
		{"both new declarations", path | compiler.FieldBitPPID | compiler.FieldBitRequireCompleteCapture},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if decisionDeterminedByKernelKey(pm, exec, tc.fields) {
				t.Fatalf("fields %#x reported as kernel-key-determined", tc.fields)
			}
			before := len(pm.snapshot())
			if err := e.syncToPolicyMap(exec, result, 0, tc.fields); !errors.Is(err, errNotKeyDetermined) {
				t.Fatalf("sync err = %v, want errNotKeyDetermined", err)
			}
			if after := len(pm.snapshot()); after != before {
				t.Fatalf("policy map rules = %d, want %d (no feedback for non-key inputs)", after, before)
			}
		})
	}

	// Sanity: a decision that reads only the kernel-key-covered path is
	// still eligible for the fast path.
	if !decisionDeterminedByKernelKey(pm, exec, path) {
		t.Fatal("path-only decision unexpectedly refused by kernel-key check")
	}
	if err := e.syncToPolicyMap(exec, result, 0, path); err != nil {
		t.Fatalf("path-only sync: %v", err)
	}
	if len(pm.snapshot()) != 1 {
		t.Fatalf("policy map rules = %d, want 1", len(pm.snapshot()))
	}
}
