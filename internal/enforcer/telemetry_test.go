package enforcer

import (
	"errors"
	"strings"
	"testing"

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
