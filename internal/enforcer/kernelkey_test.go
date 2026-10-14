package enforcer

import (
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

// setRuleOnly is a syncer that cannot describe its kernel key.
type setRuleOnly struct{ fakePolicyMap }

func (*setRuleOnly) KernelKeyFields() {} // wrong signature: not a kernelKeyFielder

func TestDecisionDeterminedByKernelKey(t *testing.T) {
	linux := &fakePolicyMap{}
	windows := &eventSyncRecorder{}
	path := compiler.FieldBitPath
	ep := compiler.FieldBitRemoteAddr | compiler.FieldBitRemotePort

	tests := []struct {
		name   string
		pm     PolicyMapSyncer
		typ    api.EventType
		fields uint32
		want   bool
	}{
		{"constant decision", linux, api.EventTypeProcess, 0, true},
		{"path only", linux, api.EventTypeProcess, path, true},
		{"path and uid", linux, api.EventTypeProcess, path | compiler.FieldBitUID, false},
		{"comm", linux, api.EventTypeProcess, compiler.FieldBitComm, false},
		{"args", linux, api.EventTypeProcess, path | compiler.FieldBitArgs, false},
		{"pid", linux, api.EventTypeProcess, compiler.FieldBitPID, false},
		{"undeclared", linux, api.EventTypeProcess, wasm.FieldsUnknown, false},
		{"endpoint", linux, api.EventTypeNetwork, ep, true},
		{"endpoint+protocol (linux key lacks it)", linux, api.EventTypeNetwork, ep | compiler.FieldBitProtocol, false},
		{"endpoint+protocol (windows key has it)", windows, api.EventTypeNetwork, ep | compiler.FieldBitProtocol, true},
		{"endpoint+local port", windows, api.EventTypeNetwork, ep | compiler.FieldBitLocalPort, false},
		{"file never keyed", linux, api.EventTypeFile, 0, false},
		{"syncer without key description", &setRuleOnly{}, api.EventTypeProcess, 0, false},
	}
	for _, tc := range tests {
		if got := decisionDeterminedByKernelKey(tc.pm, tc.typ, tc.fields); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestHandleEvent_KernelSyncOnlyForKeyDeterminedDecisions(t *testing.T) {
	bash := func(uid uint32) *api.Event {
		return &api.Event{PID: 0, UID: uid, Comm: "bash", Filename: "/bin/bash", CgroupID: 3}
	}
	allPath := &[3]uint32{compiler.FieldBitPath, compiler.FieldBitPath, compiler.FieldBitPath}
	readsUID := &[3]uint32{compiler.FieldBitUID, compiler.FieldBitUID, compiler.FieldBitUID}

	tests := []struct {
		name     string
		policy   []byte
		wantSync bool
	}{
		{"path-only declaration syncs", wasmtest.PathPrefixPolicy("/bin", allPath), true},
		{"uid-reading declaration does not sync", wasmtest.UIDPolicy(readsUID), false},
		{"undeclared policy does not sync", wasmtest.UIDPolicy(nil), false},
		// A policy that lies (reads uid, declares path) is the author's bug;
		// the declaration is what is trusted.
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pm := &fakePolicyMap{}
			e, _ := newTestEnforcer(t, testEnforcerOpts{policyMap: pm, policyWasm: tc.policy})
			e.handleEvent(bash(0))
			if e.GetStats().Denied != 1 {
				t.Fatalf("stats = %+v, want the event denied", e.GetStats())
			}
			rules := pm.snapshot()
			if !tc.wantSync {
				if len(rules) != 0 {
					t.Fatalf("decision not determined by the kernel key was synced: %+v", rules)
				}
				return
			}
			want := policyRule{cgroupID: 3, eventType: 0, pattern: "/bin/bash", action: 1}
			if len(rules) != 1 || rules[0] != want {
				t.Fatalf("rules = %+v, want [%+v]", rules, want)
			}
		})
	}
}

func TestHandleEvent_CacheKeyFollowsPIDDeclaration(t *testing.T) {
	ls := func(pid uint32) *api.Event {
		return &api.Event{PID: pid, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls"}
	}

	// pathPolicy declares it does not read the PID: a new process running
	// the same binary is a cache hit.
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyWasm: pathPolicy})
	e.cache.SetPIDRelevant(pidRelevance(e.evaluator))
	e.handleEvent(ls(0))
	e.handleEvent(ls(0x7fffffff)) // non-existent PID: never signalled
	if hits := e.GetStats().CacheHits; hits != 1 {
		t.Errorf("declared PID-independent policy: CacheHits = %d, want 1", hits)
	}

	// The undeclared fixture might read the PID, so every process misses.
	e2, _ := newTestEnforcer(t, testEnforcerOpts{})
	e2.cache.SetPIDRelevant(pidRelevance(e2.evaluator))
	e2.handleEvent(ls(0))
	e2.handleEvent(ls(0x7fffffff))
	if hits := e2.GetStats().CacheHits; hits != 0 {
		t.Errorf("undeclared policy: CacheHits = %d, want 0", hits)
	}
}
