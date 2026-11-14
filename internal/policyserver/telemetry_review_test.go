package policyserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/telemetry"
)

func TestTelemetryFailedAcknowledgementInvalidationFailsReportsClosed(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("artifact-mismatch=%t", mismatch), func(t *testing.T) {
			dir := t.TempDir()
			fleetPath := filepath.Join(dir, "fleet.json")
			fleet := openTestStore(t, fleetPath, StoreOptions{})
			if err := fleet.CreatePolicy(&Policy{ID: "p"}, writeWASM(t, dir, "base.wasm", "base")); err != nil {
				t.Fatal(err)
			}
			if err := fleet.StagePolicy("p", writeWASM(t, dir, "target.wasm", "target")); err != nil {
				t.Fatal(err)
			}
			if _, err := NewRolloutManager(fleet).CreateRollout(RolloutConfig{ID: "r", PolicyID: "p", Percentage: 50}); err != nil {
				t.Fatal(err)
			}
			telemetryPath := filepath.Join(dir, "telemetry.json")
			store, err := OpenTelemetryStore(telemetryPath, testTelemetryConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			// Fleet acknowledgements use real receipt time. Follow that clock
			// plus explicit warm-up advances instead of a fixed future anchor
			// that synced writes/race CI can overtake during fixture setup.
			advance := time.Duration(0)
			store.clock = func() time.Time { return time.Now().Add(advance) }
			server := NewServer(ServerConfig{Store: fleet, JWTSecret: testJWTSecret, Telemetry: store})
			ids := map[bool]string{}
			for i := 0; len(ids) < 2; i++ {
				id := fmt.Sprintf("agent-%d", i)
				ids[consistentBucket("r", id) < 50] = id
			}
			for _, id := range ids {
				if _, err := fleet.RegisterAgentChecked(&RegisterRequest{ID: id}); err != nil {
					t.Fatal(err)
				}
			}
			post := func(req HeartbeatRequest) *httptest.ResponseRecorder {
				body, err := json.Marshal(req)
				if err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest(http.MethodPost, "/api/v1/heartbeat", bytes.NewReader(body))
				r.Header.Set("Authorization", "Bearer "+telemetryToken(t, RoleAgent, req.AgentID))
				w := httptest.NewRecorder()
				server.Handler().ServeHTTP(w, r)
				return w
			}
			requests := map[bool]HeartbeatRequest{}
			for canary, id := range ids {
				lease, err := store.AuthorizeSession(id)
				if err != nil {
					t.Fatal(err)
				}
				fleet.mu.RLock()
				assignment, binding, err := server.telemetryAssignmentLocked(id)
				if err == nil {
					binding.Generation, err = server.refreshTelemetryDomainLocked(binding)
				}
				fleet.mu.RUnlock()
				if err != nil {
					t.Fatal(err)
				}
				a, err := store.issueAssignment(id, lease, binding)
				if err != nil {
					t.Fatal(err)
				}
				revision := binding.Revision
				revision.AssignmentRevision, revision.ActivationID = a.AssignmentRevision, "activation-"+id
				snapshot := &telemetry.Snapshot{SchemaVersion: telemetry.SchemaVersion, Session: lease, Revision: revision, Sequence: 1}
				req := HeartbeatRequest{AgentID: id, PolicyID: assignment.PolicyID, PolicyVersion: assignment.Version, PolicyHash: assignment.WASMHash, Telemetry: snapshot}
				if w := post(req); w.Code != http.StatusOK {
					t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
				}
				requests[canary] = req
			}
			advance += time.Second
			for _, req := range requests {
				req.Telemetry.Sequence++
				req.Telemetry.Total = 10
				if w := post(req); w.Code != http.StatusOK {
					t.Fatalf("samples: %d %s", w.Code, w.Body.String())
				}
			}
			advance += time.Second
			if report := store.Report("r"); report.Verdict != "healthy" {
				t.Fatalf("fixture not healthy: %+v", report)
			}
			before, err := os.ReadFile(telemetryPath)
			if err != nil {
				t.Fatal(err)
			}
			writes := 0
			store.persist = func([]byte) error { writes++; return syscall.ENOSPC }
			failed := requests[true]
			failed.Telemetry = nil // ordinary heartbeat, not malformed telemetry
			if mismatch {
				failed.PolicyHash = requests[false].PolicyHash
			} else {
				failed.ActivationError = "candidate activation failed"
			}
			if w := post(failed); w.Code != http.StatusServiceUnavailable {
				t.Fatalf("failed invalidation: %d %s", w.Code, w.Body.String())
			}
			if writes != 1 || store.fault == nil || store.state.Sources[failed.AgentID].Suspended {
				t.Fatal("expected definite precommit failure with poisoned old view")
			}
			after, err := os.ReadFile(telemetryPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("precommit failure changed telemetry disk: %v", err)
			}
			if report := store.Report("r"); report.Verdict != "pending" || !report.ReportOnly || report.Canary.Total != 0 {
				t.Fatalf("failed invalidation left report healthy: %+v", report)
			}
			// Restoring disk space or refreshing the unchanged assignment domain
			// must not clear the poison and expose the old healthy buckets.
			store.persist = store.write
			r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/telemetry?rollout_id=r", nil)
			r.Header.Set("Authorization", "Bearer "+telemetryToken(t, RoleAdmin, "admin"))
			w := httptest.NewRecorder()
			server.Handler().ServeHTTP(w, r)
			var report TelemetryReport
			if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil || w.Code != http.StatusOK || report.Verdict != "pending" {
				t.Fatalf("admin refresh revived evidence: %d %s %v", w.Code, w.Body.String(), err)
			}
			if _, err := store.AuthorizeSession(failed.AgentID); !errors.Is(err, ErrStatePersistence) {
				t.Fatal("new lease cleared invalidation poison", err)
			}
			rollout, _ := server.rollouts.GetRollout("r")
			if rollout.Status != "active" {
				t.Fatal("report path performed automatic rollout action")
			}
			// The ordinary acknowledgement really was durable, despite the
			// telemetry transaction failing independently before rename.
			if err := fleet.Close(); err != nil {
				t.Fatal(err)
			}
			reopened := openTestStore(t, fleetPath, StoreOptions{})
			ack, _ := reopened.GetAgent(failed.AgentID)
			if ack.ActivationError != failed.ActivationError || ack.PolicyHash != failed.PolicyHash {
				t.Fatalf("fleet ack was not durable: %+v", ack)
			}
		})
	}
}

func TestTelemetryLongGapCannotRefreshOldHealthyEvidence(t *testing.T) {
	for _, quality := range []string{"clean", "overflow", "errors", "excluded", "lost"} {
		t.Run(quality, func(t *testing.T) {
			store, err := NewTelemetryStore(testTelemetryConfig()) // window=60s, gap=10s
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			store.clock = func() time.Time { return now }
			if err := store.ConfigureGeneration("r", "g"); err != nil {
				t.Fatal(err)
			}
			baseline, baselineAck := telemetryTestSource(t, store, now, "baseline", false)
			canary, canaryAck := telemetryTestSource(t, store, now, "canary", true)
			snapshots := []*telemetry.Snapshot{&baseline, &canary}
			acks := []*Agent{baselineAck, canaryAck}
			for i, snapshot := range snapshots {
				if _, err := store.ingest(acks[i].ID, acks[i], *snapshot); err != nil {
					t.Fatal(err)
				}
			}
			now = now.Add(time.Second)
			for i, snapshot := range snapshots {
				acks[i].LastHeartbeat = now
				snapshot.Sequence++
				snapshot.Total = 10
				if result, err := store.ingest(acks[i].ID, acks[i], *snapshot); err != nil || result.Total != 10 {
					t.Fatalf("fresh samples: %+v %v", result, err)
				}
			}
			now = now.Add(time.Second)
			if report := store.Report("r"); report.Verdict != "healthy" {
				t.Fatalf("fixture not healthy: %+v", report)
			}
			// Both reporters return after 11s, while their pre-gap buckets are
			// still well within the 60s retention window. A cursor-only update
			// must not make those old healthy observations fresh again.
			now = now.Add(10 * time.Second)
			switch quality {
			case "overflow":
				canary.Overflow = true
			case "errors":
				canary.Errors++
			case "excluded":
				canary.Excluded++
			case "lost":
				canary.Lost++
			}
			for i, snapshot := range snapshots {
				acks[i].LastHeartbeat = now
				snapshot.Sequence++
				snapshot.Total += 1000
				if result, err := store.ingest(acks[i].ID, acks[i], *snapshot); err != nil || result.Status != "cursor-only" || result.Reason != "reporting-gap" || result.Total != 0 {
					t.Fatalf("gap result: %+v %v", result, err)
				}
			}
			assertPending := func() {
				t.Helper()
				report := store.Report("r")
				if report.Verdict != "pending" || !report.ReportOnly || report.Baseline.Total != 0 || report.Canary.Total != 0 || report.Baseline.Sources != 0 || report.Canary.Sources != 0 || report.ObservedFor != 0 {
					t.Fatalf("gap revived old healthy evidence: %+v", report)
				}
			}
			assertPending()
			for i, snapshot := range snapshots {
				if result, err := store.ingest(acks[i].ID, acks[i], *snapshot); err != nil || result.Status != "duplicate" {
					t.Fatalf("gap retry: %+v %v", result, err)
				}
			}
			assertPending()
			if store.state.Sources["canary"].Cursor.Total != 1010 || store.state.Sources["canary"].Cursor.Lost != canary.Lost || store.state.Sources["canary"].Cursor.Overflow != canary.Overflow {
				t.Fatal("gap failed to baseline cumulative/quality counters")
			}
			now = now.Add(time.Second)
			for i, snapshot := range snapshots {
				acks[i].LastHeartbeat = now
				snapshot.Sequence++
				snapshot.Total++
				if _, err := store.ingest(acks[i].ID, acks[i], *snapshot); err != nil {
					t.Fatal(err)
				}
			}
			if report := store.Report("r"); report.Verdict != "pending" {
				t.Fatalf("gap bypassed fresh warm-up: %+v", report)
			}
			now = now.Add(time.Second)
			report := store.Report("r")
			if quality == "overflow" {
				if report.Verdict != "pending" || report.Reason != "unreliable-or-overflow" {
					t.Fatalf("sticky overflow became healthy: %+v", report)
				}
			} else if report.Verdict != "healthy" || report.Baseline.Total != 1 || report.Canary.Total != 1 {
				t.Fatalf("recovery counted old evidence/backlog instead of fresh decisions: %+v", report)
			}
		})
	}
}
