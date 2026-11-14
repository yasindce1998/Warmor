package enforcer

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/platform"
	"github.com/yasindce1998/warmor/internal/telemetry"
	"github.com/yasindce1998/warmor/pkg/api"
)

func attachTestTelemetry(t *testing.T, e *Enforcer) (telemetry.Assignment, telemetry.Revision) {
	t.Helper()
	e.telemetry = &telemetry.Collector{}
	lease := telemetry.Session{Epoch: "epoch", SessionID: "session"}
	if err := e.telemetry.SetSession(lease); err != nil {
		t.Fatal(err)
	}
	a := telemetry.Assignment{Session: lease, AssignmentRevision: 1}
	r := telemetry.Revision{PolicyID: "p", PolicyVersion: 1, PolicyHash: strings.Repeat("a", 64)}
	s, err := e.telemetry.Prepare(a, r)
	if err != nil {
		t.Fatal(err)
	}
	e.telemetry.Replace(s)
	return a, r
}

func TestTelemetryCountsEventsNotCachedOutcomes(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	// Count semantics, not scheduler speed under race/native CI load. Keep a
	// bounded test-only deadline; evaluation-error quality is exercised below.
	e.evaluator.SetTimeout(5 * time.Second)
	attachTestTelemetry(t, e)
	event := &api.Event{PID: 0, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls", CgroupID: 7}
	for i := 0; i < 5; i++ {
		e.handleEvent(event)
	}
	if e.cache.Stats().Size != 1 {
		t.Fatal("expected single cached result")
	}
	if s := e.telemetry.Snapshot(); s.Total != 5 || s.Denied != 0 {
		t.Fatalf("counted cache insertions instead of events: %+v", s)
	}
	e.recordTelemetryDecision(&api.ActionResult{Action: api.ActionDeny, Cached: true}, nil)
	e.recordTelemetryDecision(&api.ActionResult{Action: api.ActionDeny, Cached: true}, nil)
	e.recordTelemetryDecision(&api.ActionResult{Action: api.ActionDeny}, errors.New("timeout"))
	e.recordTelemetryDecision(&api.ActionResult{Action: api.ActionDeny, Audit: true}, nil)
	if s := e.telemetry.Snapshot(); s.Total != 7 || s.Denied != 2 || s.Errors != 1 || s.Excluded != 1 {
		t.Fatalf("wrong population: %+v", s)
	}
}

func TestTelemetryActivationFailureAndOutOfBandReload(t *testing.T) {
	isolateCacheDir(t)
	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	a, r := attachTestTelemetry(t, e)
	e.telemetry.Record(true, false, false)
	old := e.telemetry.Snapshot()
	a.AssignmentRevision++
	if err := e.ActivatePolicyTelemetry(testPolicyPath, func() error { return errors.New("disk full") }, a, r); err == nil {
		t.Fatal("activation unexpectedly succeeded")
	}
	if s := e.telemetry.Snapshot(); s.Revision != old.Revision || s.Total != 1 || s.Sequence <= old.Sequence {
		t.Fatalf("failed activation changed collector: %+v", s)
	}
	if err := e.ActivatePolicyTelemetry(testPolicyPath, func() error { return nil }, a, r); err != nil {
		t.Fatal(err)
	}
	if s := e.telemetry.Snapshot(); s.Revision.ActivationID == old.Revision.ActivationID || s.Total != 0 || s.Revision.AssignmentRevision != 2 {
		t.Fatalf("activation didn't reset identity/counters: %+v", s)
	}
	if err := e.ReloadPolicy(); err != nil {
		t.Fatal(err)
	}
	if e.telemetry.Snapshot() != nil {
		t.Fatal("out-of-band reload retained fleet attribution")
	}
}

func TestTelemetryFinalizedEventPopulation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		opts     testEnforcerOpts
		event    api.Event
		total    uint64
		denied   uint64
		excluded uint64
		hits     uint64
	}{
		{name: "allow-including-cache-hits", event: api.Event{UID: 1000, Comm: "ls"}, total: 3, hits: 2},
		// PID zero refuses termination, but these are still policy decisions,
		// not successful-enforcement counters or evaluation errors.
		{name: "deny-including-refused-cache-hits", event: api.Event{Comm: "bash"}, total: 3, denied: 3, hits: 2},
		{name: "audit-allow", opts: testEnforcerOpts{audit: true}, event: api.Event{UID: 1000, Comm: "ls"}, excluded: 3, hits: 2},
		{name: "audit-deny", opts: testEnforcerOpts{audit: true}, event: api.Event{Comm: "bash"}, excluded: 3, hits: 2},
		{name: "log-only", event: api.Event{Comm: "python"}, excluded: 3, hits: 2},
		{name: "learning-bypass", opts: testEnforcerOpts{learning: true}, event: api.Event{Comm: "bash"}},
		{name: "kernel-bypass", event: api.Event{Comm: "bash", KernelDenied: true}},
		{name: "independent-filter-bypass", opts: testEnforcerOpts{netFilter: &NetFilterConfig{BlockCIDRs: []string{"10.0.0.0/8"}}}, event: api.Event{Type: api.EventTypeNetwork, Network: &api.NetworkEvent{RemoteAddr: "10.0.0.1"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newTestEnforcer(t, tc.opts)
			// Population/cache assertions must not depend on a 50ms wall-clock
			// budget under instrumentation. Production timeout is unchanged.
			e.evaluator.SetTimeout(5 * time.Second)
			attachTestTelemetry(t, e)
			for range 3 {
				e.handleEvent(&tc.event)
			}
			s := e.telemetry.Snapshot()
			if s.Total != tc.total || s.Denied != tc.denied || s.Excluded != tc.excluded || s.Errors != 0 || s.Lost != 0 || s.Overflow {
				t.Fatalf("wrong finalized population: %+v", s)
			}
			if got := e.cache.Stats().TotalHits; got != tc.hits {
				t.Fatalf("cache hits = %d, want %d", got, tc.hits)
			}
		})
	}
}

func TestTelemetryEvaluationFailuresAreQualityNotPolicyDenials(t *testing.T) {
	pm := &fakePolicyMap{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{poolSize: 1, policyMap: pm, policyWasm: pathPolicy})
	attachTestTelemetry(t, e)
	inst, err := e.pool.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer e.pool.Put(inst)
	e.cancel() // exhausted pool makes every evaluation fail deterministically
	for range 3 {
		e.handleEvent(&api.Event{UID: 1000, Comm: "ls", Filename: "/usr/bin/ls"})
	}
	if s := e.telemetry.Snapshot(); s.Errors != 3 || s.Total != 0 || s.Denied != 0 || s.Excluded != 0 {
		t.Fatalf("fallback denials contaminated decision population: %+v", s)
	}
	if e.cache.Stats().Size != 0 || len(pm.snapshot()) != 0 || e.GetStats().Denied != 3 {
		t.Fatal("telemetry changed fail-closed enforcement or persisted error-derived decisions")
	}
}

func TestTelemetryActivationCannotBypassSignedAssignment(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	a, r := attachTestTelemetry(t, e)
	e.signedAssignment = true
	old := e.evaluator
	committed := false
	if err := e.ActivatePolicyTelemetry("missing.wasm", func() error { committed = true; return nil }, a, r); err == nil {
		t.Fatal("legacy telemetry activation bypassed signed authorization")
	}
	if committed || e.evaluator != old {
		t.Fatal("refused telemetry activation changed signed state")
	}
	e.recordTelemetryDecision(&api.ActionResult{Action: api.ActionAllow}, nil)
	if s := e.telemetry.Snapshot(); s.Total != 0 || s.Errors != 0 || s.Excluded != 0 {
		t.Fatalf("signed decisions entered legacy telemetry: %+v", s)
	}
}

func TestGenerationTelemetryStartupRejectedBeforeSideEffects(t *testing.T) {
	collector := &telemetry.Collector{}
	session := telemetry.Session{Epoch: "epoch", SessionID: "session"}
	if err := collector.SetSession(session); err != nil {
		t.Fatal(err)
	}
	snapshot, err := collector.Prepare(telemetry.Assignment{Session: session, AssignmentRevision: 1}, telemetry.Revision{PolicyID: "p", PolicyVersion: 1, PolicyHash: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	collector.Replace(snapshot)
	original := newPlatform
	t.Cleanup(func() { newPlatform = original })
	called := false
	newPlatform = func(platform.Config) (platform.Platform, error) {
		called = true
		return nil, errors.New("unexpected platform construction")
	}
	e, err := New(context.Background(), "not-read.wasm", &Options{AtomicGenerations: true, RequireLSM: true, Telemetry: collector})
	if e != nil || !errors.Is(err, errGenerationTelemetryUnsupported) || called || collector.Snapshot() != nil {
		t.Fatalf("unsupported collector reached generation startup or retained evidence: enforcer=%v err=%v platform=%v", e, err, called)
	}
}

func TestGenerationTelemetryCannotPublishOrMisattributeLeasedWork(t *testing.T) {
	for _, apiPath := range []string{"telemetry", "generic"} {
		t.Run(apiPath, func(t *testing.T) {
			e, kernel := generationEnforcer(t)
			old := &api.Event{UID: 1000, Filename: "/bin/old"}
			if !e.captureGeneration(old) {
				t.Fatal("old lease not captured")
			}
			defer old.GenerationContext.Complete()
			a, revision := attachTestTelemetry(t, e)
			snapshot, err := e.telemetry.Prepare(a, revision)
			if err != nil {
				t.Fatal(err)
			}
			committed := false
			commit := func() error { committed = true; return nil }
			if apiPath == "telemetry" {
				err = e.ActivatePolicyTelemetry("not-read.wasm", commit, a, revision)
			} else {
				err = e.ActivatePolicy("not-read.wasm", commit)
			}
			if !errors.Is(err, errGenerationTelemetryUnsupported) || committed || len(kernel.prepared) != 1 || kernel.active != 1 || e.telemetry.Snapshot() != nil {
				t.Fatalf("unsupported telemetry crossed publication or retained evidence: %v", err)
			}
			// Even an internal late collector attachment cannot attribute old
			// generation decisions to an unrelated legacy assignment snapshot.
			e.telemetry.Replace(snapshot)
			e.recordTelemetryDecision(&api.ActionResult{Action: api.ActionAllow}, nil)
			if got := e.telemetry.Snapshot(); got == nil || got.Total != 0 || got.Denied != 0 || got.Errors != 0 {
				t.Fatalf("generation work entered legacy collector: %+v", got)
			}
		})
	}
}
