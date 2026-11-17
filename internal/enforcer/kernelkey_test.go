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

// hookAwareFake mirrors the Linux PolicyMapManager: bind, listen and connect
// share event type network but use different exact keys. Bind/connect carry
// the remote endpoint; listen carries only remote_port (family+port, no
// address). Hooks with no exact key are refused.
type hookAwareFake struct{ fakePolicyMap }

func (*hookAwareFake) KernelKeyFieldsForEvent(event *api.Event) []string {
	if event == nil {
		return nil
	}
	switch event.GetType() {
	case api.EventTypeProcess:
		if event.Hook != "" && event.Hook != "exec" {
			return nil
		}
		return []string{"path"}
	case api.EventTypeFile:
		// Mirror PolicyMapManager: only sb_mount is keyed, by fstype (hook
		// metadata with no compiler bit); plain file_open has no key.
		if event.Hook == "mount" {
			return []string{"fstype"}
		}
		return nil
	case api.EventTypeNetwork:
		switch event.Hook {
		case "", "connect", "bind":
			return []string{"remote_addr", "remote_port"}
		case "listen":
			return []string{"remote_port"}
		default:
			return nil
		}
	}
	return nil
}

func TestDecisionDeterminedByKernelKey(t *testing.T) {
	linux := &fakePolicyMap{}
	hookAware := &hookAwareFake{}
	windows := &eventSyncRecorder{}
	path := compiler.FieldBitPath
	ep := compiler.FieldBitRemoteAddr | compiler.FieldBitRemotePort

	proc := &api.Event{Type: api.EventTypeProcess, CgroupID: 1, Filename: "/bin/sh"}
	file := &api.Event{Type: api.EventTypeFile, CgroupID: 1, Filename: "/etc/shadow"}
	mountEv := &api.Event{
		Type: api.EventTypeFile, CgroupID: 1, LSMEvent: true, Hook: "mount",
		File: &api.FileEvent{Path: "proc"},
	}
	net := func(hook string) *api.Event {
		return &api.Event{
			Type: api.EventTypeNetwork, CgroupID: 1, Hook: hook,
			Network: &api.NetworkEvent{Operation: "connect", RemoteAddr: "127.0.0.1", RemotePort: 8443},
		}
	}

	tests := []struct {
		name   string
		pm     PolicyMapSyncer
		event  *api.Event
		fields uint32
		want   bool
	}{
		{"constant decision", linux, proc, 0, true},
		{"path only", linux, proc, path, true},
		{"path and uid", linux, proc, path | compiler.FieldBitUID, false},
		{"comm", linux, proc, compiler.FieldBitComm, false},
		{"args", linux, proc, path | compiler.FieldBitArgs, false},
		{"pid", linux, proc, compiler.FieldBitPID, false},
		{"undeclared", linux, proc, wasm.FieldsUnknown, false},
		{"path and wall clock", linux, proc, path | compiler.FieldBitTime, false},
		{"path and container age", linux, proc, path | compiler.FieldBitContainerAge, false},
		{"endpoint and wall clock (windows)", windows, net("connect"), ep | compiler.FieldBitTime, false},
		{"endpoint", linux, net("connect"), ep, true},
		{"endpoint+protocol (linux key lacks it)", linux, net("connect"), ep | compiler.FieldBitProtocol, false},
		{"endpoint+protocol (windows key has it)", windows, net("connect"), ep | compiler.FieldBitProtocol, true},
		{"endpoint+local port", windows, net("connect"), ep | compiler.FieldBitLocalPort, false},
		{"file never keyed", linux, file, 0, false},
		{"syncer without key description", &setRuleOnly{}, proc, 0, false},
		// Hook-aware bind gating: a bind decision is kernel-matchable only
		// under the exact bind key and only from endpoint fields.
		{"bind endpoint", hookAware, net("bind"), ep, true},
		{"bind endpoint via hook-agnostic fallback", linux, net("bind"), ep, true},
		{"bind + operation is not key-determined", hookAware, net("bind"), ep | compiler.FieldBitOperation, false},
		{"bind + protocol is not key-determined", hookAware, net("bind"), ep | compiler.FieldBitProtocol, false},
		{"bind + uid is not key-determined", hookAware, net("bind"), ep | compiler.FieldBitUID, false},
		{"bind with connect_unix hook has no key", hookAware, net("connect_unix"), ep, false},
		{"listen endpoint addr is not key-determined", hookAware, net("listen"), ep, false},
		{"listen remote_port only is key-determined", hookAware, net("listen"), compiler.FieldBitRemotePort, true},
		{"listen port + protocol is not key-determined", hookAware, net("listen"), compiler.FieldBitRemotePort | compiler.FieldBitProtocol, false},
		{"listen port + uid is not key-determined", hookAware, net("listen"), compiler.FieldBitRemotePort | compiler.FieldBitUID, false},
		{"listen port + wall clock is not key-determined", hookAware, net("listen"), compiler.FieldBitRemotePort | compiler.FieldBitTime, false},
		{"exec hook respected for process", hookAware, proc, path, true},
		{"non-exec process hook has no key", hookAware, &api.Event{Type: api.EventTypeProcess, Hook: "ptrace", Filename: "/bin/sh"}, path, false},
		// Mount: fstype is hook metadata, not a policy field. Only a decision
		// that reads no policy field is determined by that key; source/target
		// paths are not in the key and uid/temporal are never covered.
		{"mount constant decision is key-determined", hookAware, mountEv, 0, true},
		{"mount + path is not key-determined", hookAware, mountEv, compiler.FieldBitPath, false},
		{"mount + uid is not key-determined", hookAware, mountEv, compiler.FieldBitUID, false},
		{"mount + comm is not key-determined", hookAware, mountEv, compiler.FieldBitComm, false},
		{"mount + wall clock is not key-determined", hookAware, mountEv, compiler.FieldBitTime, false},
		{"mount + container age is not key-determined", hookAware, mountEv, compiler.FieldBitContainerAge, false},
		{"file_open has no key", hookAware, file, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := decisionDeterminedByKernelKey(tc.pm, tc.event, tc.fields); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestBindLSMWritebackFoldsAudit checks the LSM gate relaxation in
// persistDecision: a bind LSM miss may be written back because the kernel
// already accepted the bind, userspace evaluated the complete event and the
// key is exact. Other LSM events stay record-only. Audit downgrade must still
// reach the kernel (audit=1 means a would-deny, never a block).
func TestBindLSMWritebackFoldsAudit(t *testing.T) {
	endpointMask := &[3]uint32{0, 0, compiler.FieldBitRemoteAddr | compiler.FieldBitRemotePort}
	newBind := func() *api.Event {
		return &api.Event{
			Type: api.EventTypeNetwork, CgroupID: 42, LSMEvent: true, Hook: "bind",
			Network: &api.NetworkEvent{Operation: "connect", Protocol: "tcp", RemoteAddr: "127.0.0.1", RemotePort: 8443},
		}
	}

	for _, tc := range []struct {
		name      string
		auditMode bool
		wantAudit bool
	}{
		{"plain deny", false, false},
		{"audit downgraded deny", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &eventSyncRecorder{}
			e, _ := newTestEnforcer(t, testEnforcerOpts{
				policyMap:  rec,
				policyWasm: wasmtest.ConstPolicy(1, endpointMask), // deny all, declares endpoint-only reads
			})
			e.auditMode = tc.auditMode
			e.handleEvent(newBind())
			if len(rec.events) != 1 {
				t.Fatalf("bind LSM DENY not written back: %+v", rec)
			}
			if rec.actions[0] != 1 {
				t.Fatalf("action = %d, want DENY", rec.actions[0])
			}
			if rec.audits[0] != tc.wantAudit {
				t.Fatalf("audit = %v, want %v", rec.audits[0], tc.wantAudit)
			}
		})
	}

	// A non-bind LSM event is still recorded, never re-synced.
	rec := &eventSyncRecorder{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{
		policyMap:  rec,
		policyWasm: wasmtest.ConstPolicy(1, endpointMask),
	})
	e.handleEvent(&api.Event{
		Type: api.EventTypeNetwork, CgroupID: 42, LSMEvent: true, Hook: "connect",
		Network: &api.NetworkEvent{Operation: "connect", RemoteAddr: "127.0.0.1", RemotePort: 8443},
	})
	if len(rec.events) != 0 {
		t.Fatalf("non-bind LSM event was synced: %+v", rec)
	}
}

// listenSyncRecorder mirrors the Linux PolicyMapManager's hook-aware key
// report and records SyncEvent calls, so the listen LSM write-back gate can be
// tested end-to-end (port-only key, no address).
type listenSyncRecorder struct{ eventSyncRecorder }

func (*listenSyncRecorder) KernelKeyFieldsForEvent(event *api.Event) []string {
	if event == nil || event.GetType() != api.EventTypeNetwork {
		return nil
	}
	switch event.Hook {
	case "", "connect", "bind":
		return []string{"remote_addr", "remote_port"}
	case "listen":
		return []string{"remote_port"}
	default:
		return nil
	}
}

// TestListenLSMWritebackFoldsAudit checks the LSM gate relaxation in
// persistDecision: a listen LSM miss may be written back because the kernel
// already accepted the listen, userspace evaluated the complete event and the
// key is the exact port-only listen key. Other LSM events stay record-only.
// Audit downgrade must still reach the kernel (audit=1 = would-deny, no block).
func TestListenLSMWritebackFoldsAudit(t *testing.T) {
	portOnly := &[3]uint32{0, 0, compiler.FieldBitRemotePort}
	newListen := func() *api.Event {
		return &api.Event{
			Type: api.EventTypeNetwork, CgroupID: 42, LSMEvent: true, Hook: "listen",
			Network: &api.NetworkEvent{Operation: "listen", Protocol: "tcp", RemotePort: 8080},
		}
	}

	for _, tc := range []struct {
		name      string
		auditMode bool
		wantAudit bool
	}{
		{"plain deny", false, false},
		{"audit downgraded deny", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &listenSyncRecorder{}
			e, _ := newTestEnforcer(t, testEnforcerOpts{
				policyMap:  rec,
				policyWasm: wasmtest.ConstPolicy(1, portOnly), // deny all, declares port-only reads
			})
			e.auditMode = tc.auditMode
			e.handleEvent(newListen())
			if len(rec.events) != 1 {
				t.Fatalf("listen LSM DENY not written back: %+v", rec)
			}
			if rec.actions[0] != 1 {
				t.Fatalf("action = %d, want DENY", rec.actions[0])
			}
			if rec.audits[0] != tc.wantAudit {
				t.Fatalf("audit = %v, want %v", rec.audits[0], tc.wantAudit)
			}
		})
	}

	// A policy that reads a field the listen key cannot cover (remote_addr)
	// must NOT be written back even though this is an LSM listen miss.
	readsAddr := &[3]uint32{0, 0, compiler.FieldBitRemoteAddr | compiler.FieldBitRemotePort}
	rec := &listenSyncRecorder{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{
		policyMap:  rec,
		policyWasm: wasmtest.ConstPolicy(1, readsAddr),
	})
	e.handleEvent(newListen())
	if len(rec.events) != 0 {
		t.Fatalf("unsound listen LSM decision was written back: %+v", rec)
	}

	// A non-listen LSM event is still recorded, never re-synced.
	rec2 := &listenSyncRecorder{}
	e2, _ := newTestEnforcer(t, testEnforcerOpts{
		policyMap:  rec2,
		policyWasm: wasmtest.ConstPolicy(1, portOnly),
	})
	e2.handleEvent(&api.Event{
		Type: api.EventTypeNetwork, CgroupID: 42, LSMEvent: true, Hook: "connect",
		Network: &api.NetworkEvent{Operation: "connect", Protocol: "tcp", RemoteAddr: "127.0.0.1", RemotePort: 8080},
	})
	if len(rec2.events) != 0 {
		t.Fatalf("non-listen LSM event was synced: %+v", rec2)
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
	inProcessEvaluator(t, e).SetTimeout(20 * time.Millisecond)

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
	if got := inProcessEvaluator(t, e).Timeout(); got != 123*time.Millisecond {
		t.Fatalf("evaluator timeout = %v, want 123ms", got)
	}
	e.evaluator = nil // let ReloadPolicy close the old pool only once
	if err := e.ReloadPolicy(); err != nil {
		t.Fatal(err)
	}
	if got := inProcessEvaluator(t, e).Timeout(); got != 123*time.Millisecond {
		t.Fatalf("timeout after reload = %v, want 123ms", got)
	}
}

// mountSyncRecorder mirrors the Linux PolicyMapManager's mount key report:
// only sb_mount (Hook=="mount") has an exact key, keyed by fstype (hook
// metadata with no compiler bit). It records SyncEvent calls.
type mountSyncRecorder struct{ eventSyncRecorder }

func (*mountSyncRecorder) KernelKeyFieldsForEvent(event *api.Event) []string {
	if event == nil || event.GetType() != api.EventTypeFile || event.Hook != "mount" {
		return nil
	}
	return []string{"fstype"}
}

// TestMountLSMWritebackFoldsAudit checks the LSM gate relaxation in
// persistDecision: a mount LSM miss may be written back because the hook
// already accepted the mount (it only emitted on a policy-map miss), the
// userspace decision is keyed by the very same fstype, and there is no
// default-deny domain. Only a decision determined by the key alone (no
// policy field read) is synced; source/target/uid/temporal decisions stay
// userspace-only. Audit downgrade must still reach the kernel (audit=1 means a
// would-deny, never a block).
func TestMountLSMWritebackFoldsAudit(t *testing.T) {
	newMount := func() *api.Event {
		return &api.Event{
			Type: api.EventTypeFile, CgroupID: 42, LSMEvent: true, Hook: "mount",
			Filename: "proc", MountSource: "/proc", File: &api.FileEvent{Path: "proc"},
		}
	}
	// A deny that declares no policy fields read is fully determined by the
	// fstype key and may be written back.
	for _, tc := range []struct {
		name      string
		auditMode bool
		wantAudit bool
	}{
		{"plain deny", false, false},
		{"audit downgraded deny", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &mountSyncRecorder{}
			e, _ := newTestEnforcer(t, testEnforcerOpts{
				policyMap:  rec,
				policyWasm: wasmtest.ConstPolicy(1, &[3]uint32{0, 0, 0}), // deny, no fields read
			})
			e.auditMode = tc.auditMode
			e.handleEvent(newMount())
			if len(rec.events) != 1 {
				t.Fatalf("mount LSM DENY not written back: %+v", rec)
			}
			if rec.actions[0] != 1 {
				t.Fatalf("action = %d, want DENY", rec.actions[0])
			}
			if rec.audits[0] != tc.wantAudit {
				t.Fatalf("audit = %v, want %v", rec.audits[0], tc.wantAudit)
			}
		})
	}

	// A decision that reads `path` (the mount source/target, not in the key)
	// must NOT be written back even though this is an LSM mount miss.
	readsPath := &[3]uint32{0, compiler.FieldBitPath, 0}
	rec := &mountSyncRecorder{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{
		policyMap:  rec,
		policyWasm: wasmtest.ConstPolicy(1, readsPath),
	})
	e.handleEvent(newMount())
	if len(rec.events) != 0 {
		t.Fatalf("unsound mount LSM decision was written back: %+v", rec)
	}

	// A non-mount LSM event (plain file_open) is still recorded, never re-synced.
	rec2 := &mountSyncRecorder{}
	e2, _ := newTestEnforcer(t, testEnforcerOpts{
		policyMap:  rec2,
		policyWasm: wasmtest.ConstPolicy(1, &[3]uint32{0, 0, 0}),
	})
	e2.handleEvent(&api.Event{
		Type: api.EventTypeFile, CgroupID: 42, LSMEvent: true, Hook: "file",
		File: &api.FileEvent{Path: "proc"},
	})
	if len(rec2.events) != 0 {
		t.Fatalf("non-mount LSM event was synced: %+v", rec2)
	}
}
