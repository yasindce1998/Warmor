package enforcer

import (
	"context"
	"time"

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

func TestHandleEvent_LoopingPolicyFailsClosedWithoutCaching(t *testing.T) {
	pm := &fakePolicyMap{}
	// uid 0 loops forever inside the policy; other uids are allowed.
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyMap: pm, poolSize: 1, policyWasm: wasmtest.LoopOnUIDPolicy()})
	e.evaluator.SetTimeout(20 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// PID 0: handleDeny never signals anything.
		e.handleEvent(&api.Event{PID: 0, UID: 0, Filename: "/bin/spin"})
		e.handleEvent(&api.Event{PID: 0, UID: 1000, Filename: "/bin/ok"})
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("looping policy hung the event loop")
	}

	stats := e.GetStats()
	if stats.Denied != 1 || stats.Allowed != 1 {
		t.Fatalf("stats = %+v, want the timed-out event denied and the next allowed", stats)
	}
	if _, hit := e.cache.Get(&api.Event{PID: 0, UID: 0, Filename: "/bin/spin"}); hit {
		t.Error("timed-out evaluation was cached")
	}
	if len(pm.snapshot()) != 0 {
		t.Error("timed-out evaluation was synced to the kernel")
	}
}

func TestNew_EvalTimeoutOption(t *testing.T) {
	isolateCacheDir(t)
	stubPlatform(t, &fakePlatform{}, nil)
	e, err := New(context.Background(), testPolicyPath, &Options{MetricsPort: -1, EvalTimeout: 123 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if got := e.evaluator.Timeout(); got != 123*time.Millisecond {
		t.Fatalf("evaluator timeout = %v, want 123ms", got)
	}
	e.evaluator = nil // let ReloadPolicy close the old pool only once
	if err := e.ReloadPolicy(); err != nil {
		t.Fatal(err)
	}
	if got := e.evaluator.Timeout(); got != 123*time.Millisecond {
		t.Fatalf("timeout after reload = %v, want 123ms", got)
	}
}
