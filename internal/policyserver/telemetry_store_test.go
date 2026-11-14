package policyserver

import (
	"errors"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/telemetry"
)

func testTelemetryConfig() TelemetryConfig {
	return TelemetryConfig{Window: time.Minute, MaxGap: 10 * time.Second, Observation: time.Second, Lease: time.Hour, MinSamples: 1, MinSources: 1, MaxDenyDelta: .1, MaxSources: 10, MaxRollouts: 2}
}

func telemetryTestSource(t *testing.T, store *TelemetryStore, now time.Time, id string, canary bool) (telemetry.Snapshot, *Agent) {
	t.Helper()
	lease, err := store.AuthorizeSession(id)
	if err != nil {
		t.Fatal(err)
	}
	b := telemetryBinding{Revision: telemetry.Revision{PolicyID: "p", PolicyVersion: 1, PolicyHash: strings.Repeat("a", 64)}, RolloutID: "r", Generation: "g", Canary: canary, AssignmentKey: id}
	a, err := store.issueAssignment(id, lease, b)
	if err != nil {
		t.Fatal(err)
	}
	r := b.Revision
	r.AssignmentRevision, r.ActivationID = a.AssignmentRevision, "activation-"+id
	return telemetry.Snapshot{SchemaVersion: 1, Session: lease, Revision: r, Sequence: 1}, &Agent{ID: id, PolicyID: r.PolicyID, PolicyVersion: r.PolicyVersion, PolicyHash: r.PolicyHash, LastHeartbeat: now}
}

func TestTelemetryAtomicDuplicatesOrderingAndValidation(t *testing.T) {
	store, err := NewTelemetryStore(testTelemetryConfig())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	store.clock = func() time.Time { return now }
	if err := store.ConfigureGeneration("r", "g"); err != nil {
		t.Fatal(err)
	}
	s, ack := telemetryTestSource(t, store, now, "agent", true)
	s.Total, s.Denied = 100, 90
	if r, err := store.ingest("agent", ack, s); err != nil || r.Status != "bootstrap" || r.Total != 0 {
		t.Fatalf("bootstrap: %+v %v", r, err)
	}
	now = now.Add(2 * time.Second)
	ack.LastHeartbeat = now
	s.Sequence, s.Total, s.Denied = 4, 110, 99 // cumulative gaps are safe
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.ingest("agent", ack, s); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if r := store.Report("r"); r.Canary.Total != 10 || r.Canary.Denied != 9 || r.Verdict != "pending" {
		t.Fatalf("duplicate counted or missing baseline healthy: %+v", r)
	}
	stale := s
	stale.Sequence = 2
	if r, err := store.ingest("agent", ack, stale); err != nil || r.Status != "stale" {
		t.Fatalf("stale: %+v %v", r, err)
	}
	conflict := s
	conflict.Total++
	if _, err := store.ingest("agent", ack, conflict); err == nil {
		t.Fatal("conflicting duplicate accepted")
	}
	for _, alter := range []func(*telemetry.Snapshot){
		func(s *telemetry.Snapshot) { s.Total-- },
		func(s *telemetry.Snapshot) { s.Denied += 2; s.Total++ },
		func(s *telemetry.Snapshot) { s.Epoch = "" },
		func(s *telemetry.Snapshot) { s.Revision.PolicyID = "other" },
		func(s *telemetry.Snapshot) { s.Revision.ActivationID = "old" },
	} {
		bad := s
		bad.Sequence++
		alter(&bad)
		if _, err := store.ingest("agent", ack, bad); err == nil {
			t.Fatalf("malformed accepted: %+v", bad)
		}
		if store.state.Sources["agent"].Cursor.Sequence != 4 {
			t.Fatal("invalid report advanced cursor")
		}
	}
	if _, err := store.ingest("another-agent", ack, s); err == nil {
		t.Fatal("another agent forged totals")
	}
	failure := s
	failure.Sequence++
	failure.Total++
	store.persist = func([]byte) error { return errors.New("disk full") }
	if _, err := store.ingest("agent", ack, failure); !errors.Is(err, ErrStatePersistence) {
		t.Fatal(err)
	}
	if store.state.Sources["agent"].Cursor.Sequence != 4 || store.Report("r").Canary.Total != 10 {
		t.Fatal("failed transaction partially committed")
	}
	store.persist = nil
	if r, err := store.ingest("agent", ack, failure); err != nil || r.Total != 1 {
		t.Fatalf("retry lost delta: %+v %v", r, err)
	}
}

func TestTelemetryReportOnlyCoverageExpiryAndQuality(t *testing.T) {
	store, _ := NewTelemetryStore(testTelemetryConfig())
	now := time.Now()
	store.clock = func() time.Time { return now }
	if err := store.ConfigureGeneration("r", "g"); err != nil {
		t.Fatal(err)
	}
	b, ba := telemetryTestSource(t, store, now, "baseline", false)
	c, ca := telemetryTestSource(t, store, now, "canary", true)
	for _, pair := range []struct {
		s telemetry.Snapshot
		a *Agent
	}{{b, ba}, {c, ca}} {
		if _, err := store.ingest(pair.a.ID, pair.a, pair.s); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(2 * time.Second)
	ba.LastHeartbeat, ca.LastHeartbeat = now, now
	b.Sequence++
	b.Total = 10
	c.Sequence++
	c.Total, c.Denied = 10, 10
	if _, err := store.ingest(ba.ID, ba, b); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ingest(ca.ID, ca, c); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if r := store.Report("r"); r.Verdict != "degraded" || !r.ReportOnly {
		t.Fatalf("missing report-only degradation: %+v", r)
	}
	if err := store.observeAcknowledgement(HeartbeatRequest{AgentID: "canary", PolicyID: ca.PolicyID, PolicyVersion: ca.PolicyVersion, PolicyHash: ca.PolicyHash, ActivationError: "failed candidate"}); err != nil {
		t.Fatal(err)
	}
	if store.Report("r").Verdict != "pending" {
		t.Fatal("failed acknowledgement kept old healthy evidence")
	}
	c.Sequence++
	c.Total++
	c.Denied++
	ca.LastHeartbeat = now
	if result, err := store.ingest(ca.ID, ca, c); err != nil || result.Status != "bootstrap" {
		t.Fatalf("recovery did not rebaseline: %+v %v", result, err)
	}
	// An assigned but offline node cannot be omitted from coverage.
	if _, err := store.issueAssignment("baseline", b.Session, *store.state.Sources["baseline"].Desired); err != nil {
		t.Fatal(err)
	}
	store.state.Rosters["r"] = map[string]bool{"baseline": false, "canary": true, "offline": true}
	if r := store.Report("r"); r.Verdict != "pending" || r.Canary.Assigned != 2 {
		t.Fatalf("offline coverage: %+v", r)
	}
	delete(store.state.Rosters["r"], "offline")
	now = now.Add(time.Second)
	ca.LastHeartbeat = now
	c.Sequence++
	c.Errors++
	if r, err := store.ingest(ca.ID, ca, c); err != nil || r.Reason != "unreliable-population" {
		t.Fatalf("quality: %+v %v", r, err)
	}
	if store.Report("r").Verdict != "pending" {
		t.Fatal("errors yielded health")
	}
	now = now.Add(time.Minute)
	ca.LastHeartbeat = now
	c.Sequence++
	c.Total += 1000
	if r, err := store.ingest(ca.ID, ca, c); err != nil || r.Reason != "reporting-gap" || r.Total != 0 {
		t.Fatalf("backlog admitted: %+v %v", r, err)
	}
	if r := store.Report("r"); r.Baseline.Total != 0 || r.Canary.Total != 0 {
		t.Fatalf("resurrected expired samples: %+v", r)
	}
}

func TestTelemetryRestartEpochAndLeaseRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telemetry.json")
	cfg := testTelemetryConfig()
	store, err := OpenTelemetryStore(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	store.clock = func() time.Time { return now }
	if err := store.ConfigureGeneration("r", "g"); err != nil {
		t.Fatal(err)
	}
	s, ack := telemetryTestSource(t, store, now, "a", true)
	if _, err := store.ingest("a", ack, s); err != nil {
		t.Fatal(err)
	}
	next, err := store.AuthorizeSession("a")
	if err != nil {
		t.Fatal(err)
	}
	if next == s.Session {
		t.Fatal("lease reused")
	}
	s.Sequence++
	if _, err := store.ingest("a", ack, s); !errors.Is(err, ErrTelemetryFence) {
		t.Fatal("revoked lease accepted", err)
	}
	oldEpoch := store.state.Epoch
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenTelemetryStore(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if store.state.Epoch == oldEpoch || len(store.state.Sources) != 0 || store.Report("r").Verdict != "pending" {
		t.Fatal("restart restored partial evidence")
	}
	if _, err := store.ingest("a", ack, s); !errors.Is(err, ErrTelemetryFence) {
		t.Fatal("old epoch accepted", err)
	}
}

func TestTelemetryFiniteConfigBoundsAndGenerationHistory(t *testing.T) {
	for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -1, 2} {
		c := testTelemetryConfig()
		c.MaxDenyDelta = value
		if _, err := NewTelemetryStore(c); err == nil {
			t.Fatalf("accepted %v", value)
		}
	}
	cfg := testTelemetryConfig()
	cfg.MaxSources = 1
	cfg.MaxRollouts = 1
	store, _ := NewTelemetryStore(cfg)
	now := time.Now()
	store.clock = func() time.Time { return now }
	if _, err := store.AuthorizeSession("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthorizeSession("b"); !errors.Is(err, ErrStateLimit) {
		t.Fatal(err)
	}
	a, err := store.configureDomain("r", "domain-a", map[string]bool{"a": true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.configureDomain("r", "domain-b", map[string]bool{"a": false}); err != nil {
		t.Fatal(err)
	}
	again, err := store.configureDomain("r", "domain-a", map[string]bool{"a": true})
	if err != nil {
		t.Fatal(err)
	}
	if a == again {
		t.Fatal("A -> B -> A reused historical generation")
	}
	if _, err := store.configureDomain("other", "domain", nil); !errors.Is(err, ErrStateLimit) {
		t.Fatal(err)
	}
}
