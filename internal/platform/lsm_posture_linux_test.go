//go:build linux

package platform

import (
	"errors"
	"reflect"
	"testing"

	"github.com/yasindce1998/warmor/internal/ebpf"
)

// Exercise the actual initialization ordering/status publication with fake map
// writers, never attach BPF or change a host-wide enforcement toggle.
func TestLSMBlockingRequiresSuccessfulScopeAndToggleInitialization(t *testing.T) {
	for _, tc := range []struct {
		name          string
		enforce       bool
		scopeFailure  bool
		toggleFailure bool
	}{
		{name: "loaded audit-only"},
		{name: "blocking", enforce: true},
		{name: "scope failure", enforce: true, scopeFailure: true},
		{name: "toggle failure", enforce: true, toggleFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &LinuxPlatform{ebpfLoader: &ebpf.Loader{}, stopChan: make(chan struct{}), lsmEnabled: true,
				config: LinuxConfig{LSMEnforce: tc.enforce, RequireLSM: true, CgroupFilter: []string{"/scope"}}}
			if !p.Capabilities().LSMEnforcement || p.LSMBlocking() {
				t.Fatal("fixture must distinguish loaded capability from blocking")
			}
			failure := errors.New("injected map write failure")
			var writes []string
			err := p.initializeLSMPosture([]uint64{42}, func(ids []uint64) error {
				writes = append(writes, "scope")
				if !reflect.DeepEqual(ids, []uint64{42}) {
					t.Fatal("scope identity changed", ids)
				}
				if tc.scopeFailure {
					return failure
				}
				return nil
			}, func(enabled bool) error {
				writes = append(writes, "toggle")
				if enabled != tc.enforce {
					t.Fatal("requested posture changed")
				}
				if tc.toggleFailure {
					return failure
				}
				return nil
			})
			failed := tc.scopeFailure || tc.toggleFailure
			if errors.Is(err, failure) != failed || p.LSMBlocking() != (tc.enforce && !failed) {
				t.Fatal("failed or audit-only toggle advertised blocking", err)
			}
			wantWrites := []string{"scope", "toggle"}
			if tc.scopeFailure {
				wantWrites = wantWrites[:1]
			}
			if !reflect.DeepEqual(writes, wantWrites) {
				t.Fatal("blocking enabled before scope", writes)
			}
			if tc.enforce && failed && p.Ready() == nil {
				t.Fatal("failed enforce initialization reported ready")
			}
			if !failed && p.Ready() != nil {
				t.Fatal("initialized requested posture not ready", p.Ready())
			}
		})
	}
}
