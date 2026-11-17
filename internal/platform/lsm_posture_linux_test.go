//go:build linux

package platform

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/yasindce1998/warmor/internal/ebpf"
)

// The cgroup-v2 identity assertion only gates features that correlate BPF
// cgroup IDs with userspace scope IDs; observe-only runs are unaffected.
func TestRequireCgroupV2ForEnforcementGate(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")

	observe := &LinuxPlatform{config: LinuxConfig{CgroupRoot: missing}}
	if err := observe.requireCgroupV2ForEnforcement(); err != nil {
		t.Fatalf("observe-only run must not require cgroup v2: %v", err)
	}

	for _, cfg := range []LinuxConfig{
		{LSMEnforce: true, CgroupRoot: missing},
		{CgroupFilter: []string{"auto"}, CgroupRoot: missing},
	} {
		p := &LinuxPlatform{config: cfg}
		if err := p.requireCgroupV2ForEnforcement(); err == nil {
			t.Fatalf("cfg %+v: a non-v2 view must be refused", cfg)
		}
	}
}

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
