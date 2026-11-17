//go:build linux

package ebpf

import (
	"errors"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/kernelmap"
)

// TestKernelKeyPathBoundary pins the shared exact-path identity limit at the
// kernel-map write API: 127 bytes are accepted verbatim, 128 and 254 are
// refused with ErrNotKernelMatchable rather than silently truncated into a key
// a raw writer could use to allow a path WASM only saw as a truncated prefix.
func TestKernelKeyPathBoundary(t *testing.T) {
	const limit = kernelmap.MaxPolicyPathBytes // 127
	atLimit := strings.Repeat("p", limit)

	k, err := stringPolicyKey(42, EventTypeExec, atLimit)
	if err != nil {
		t.Fatalf("len %d must be accepted: %v", limit, err)
	}
	if string(k.Path[:limit]) != atLimit || k.Path[limit] != 0 {
		t.Fatal("127-byte key must be the full, zero-terminated identity")
	}

	for _, n := range []int{128, 254} {
		if _, err := stringPolicyKey(42, EventTypeExec, strings.Repeat("q", n)); !errors.Is(err, ErrNotKernelMatchable) {
			t.Fatalf("len %d: got %v, want ErrNotKernelMatchable", n, err)
		}
	}
}

// TestKernelKeyLengthLimitAppliesToAllStringDomains covers every policy-
// decision domain keyed by a string (exec, mount, ptrace). Mount and ptrace are
// bounded even tighter by their sensor buffers, but must also never admit a
// pattern beyond the shared 127-byte identity limit.
func TestKernelKeyLengthLimitAppliesToAllStringDomains(t *testing.T) {
	for _, typ := range []uint8{EventTypeExec, EventTypeMount, EventTypePtrace} {
		if _, err := stringPolicyKey(42, typ, strings.Repeat("z", 254)); !errors.Is(err, ErrNotKernelMatchable) {
			t.Fatalf("event type %d accepted a 254-byte pattern", typ)
		}
	}
}

// TestSetRuleRejectsOverlongPathWithoutTruncation checks the public kernel-map
// write API directly: a 127-byte path is stored in full, while an over-long
// path is refused without installing a truncated prefix key.
func TestSetRuleRejectsOverlongPathWithoutTruncation(t *testing.T) {
	b := newFakeBackend()
	m := &PolicyMapManager{policyMap: b}
	const limit = kernelmap.MaxPolicyPathBytes

	atLimit := strings.Repeat("a", limit)
	if err := m.SetRule(0, EventTypeExec, atLimit, ActionAllow, false); err != nil {
		t.Fatalf("127-byte rule must be accepted: %v", err)
	}
	if len(b.entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(b.entries))
	}

	// 254 bytes of a distinct character: its first 127 bytes are NOT the
	// legitimate entry above, so a truncated-key regression is detectable.
	overlong := strings.Repeat("c", 254)
	if err := m.SetRule(0, EventTypeExec, overlong, ActionAllow, false); !errors.Is(err, ErrNotKernelMatchable) {
		t.Fatalf("SetRule(254-byte path) = %v, want ErrNotKernelMatchable", err)
	}
	if len(b.entries) != 1 {
		t.Fatalf("over-long rule installed %d extra entries", len(b.entries)-1)
	}
	if _, ok := b.entries[mustStringKey(t, 0, EventTypeExec, overlong[:limit])]; ok {
		t.Fatal("a truncated 127-byte prefix key was installed")
	}
	if v := b.entries[mustStringKey(t, 0, EventTypeExec, atLimit)]; v.Action != ActionAllow {
		t.Fatal("the legitimate 127-byte entry was disturbed")
	}
}

// preloadExecAllowlist models the enforcer's default-deny preload sequence:
// write every global-domain static rule first, and only mark the domain
// default-deny after all writes succeed. It uses only PolicyMapManager APIs.
func preloadExecAllowlist(t *testing.T, m *PolicyMapManager, patterns []string) error {
	t.Helper()
	for _, p := range patterns {
		if err := m.SetRule(0, EventTypeExec, p, ActionAllow, false); err != nil {
			return err
		}
	}
	return m.SetDefaultDeny(EventTypeExec, DefaultDenyModeDeny)
}

// TestDefaultDenyPreloadRejectsOverlongRule verifies the complete-allowlist
// property: an over-long rule aborts preload, so neither a truncated allow key
// nor the default-deny marking (which would deny its misses) is installed.
func TestDefaultDenyPreloadRejectsOverlongRule(t *testing.T) {
	b := newFakeBackend()
	dd := &fakeDefaultDenyBackend{}
	m := &PolicyMapManager{policyMap: b, defaultDenyMap: dd}

	valid := strings.Repeat("v", kernelmap.MaxPolicyPathBytes)
	overlong := strings.Repeat("o", 254)

	if err := preloadExecAllowlist(t, m, []string{valid, overlong}); !errors.Is(err, ErrNotKernelMatchable) {
		t.Fatalf("preload err = %v, want ErrNotKernelMatchable", err)
	}
	if _, ok := b.entries[mustStringKey(t, 0, EventTypeExec, overlong[:kernelmap.MaxPolicyPathBytes])]; ok {
		t.Fatal("preload installed a truncated key for the over-long rule")
	}
	if _, marked := dd.entries[DefaultDenyKey{EventType: EventTypeExec}]; marked {
		t.Fatal("domain was marked default-deny despite a rejected rule")
	}
}

// TestSyncFromWASMSkipsOverlongRuleWithoutTruncatedKey covers the batch
// preload path: an over-long pattern is skipped, with no truncated key left in
// the map. Userspace WASM evaluation of the full path is unaffected.
func TestSyncFromWASMSkipsOverlongRuleWithoutTruncatedKey(t *testing.T) {
	b := newFakeBackend()
	m := &PolicyMapManager{policyMap: b}
	overlong := strings.Repeat("s", 254)

	if err := m.SyncFromWASM([]CachedDecision{{
		CgroupID: 42, EventType: EventTypeExec, Pattern: overlong, Action: ActionAllow,
	}}); err != nil {
		t.Fatal(err)
	}
	if len(b.entries) != 0 {
		t.Fatalf("SyncFromWASM installed %d entries for an over-long rule", len(b.entries))
	}
	if _, ok := b.entries[mustStringKey(t, 42, EventTypeExec, overlong[:kernelmap.MaxPolicyPathBytes])]; ok {
		t.Fatal("SyncFromWASM installed a truncated prefix key")
	}
}
