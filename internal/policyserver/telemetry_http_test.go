package policyserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/telemetry"
)

func telemetryToken(t *testing.T, role, subject string) string {
	t.Helper()
	token, err := newJWTIssuerFromSecret(testJWTSecret).Issue(subject, role, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestTelemetryClientInFlightSameArtifactKeepsHeartbeatAndAckTruthful(t *testing.T) {
	// Use ordinary mock distribution to exercise a same-artifact activation
	// whose collector swap finishes before the durable callback returns.
	collector := &telemetry.Collector{}
	lease := telemetry.Session{Epoch: "epoch", SessionID: "session"}
	if err := collector.SetSession(lease); err != nil {
		t.Fatal(err)
	}
	var received HeartbeatRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := NewClient(ClientConfig{ServerURL: server.URL, AgentID: "agent", Telemetry: collector})
	revision := telemetry.Revision{PolicyID: "p", PolicyVersion: 1, PolicyHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	a := telemetry.Assignment{Session: lease, AssignmentRevision: 1}
	first, err := collector.Prepare(a, revision)
	if err != nil {
		t.Fatal(err)
	}
	collector.Replace(first)
	client.policyID, client.policyVersion, client.policyHash = revision.PolicyID, revision.PolicyVersion, revision.PolicyHash
	client.telemetryRevision = collector.ActiveRevision()
	// Simulate an in-flight OnUpdate under the same poll lock used in the real
	// client. Heartbeat must neither deadlock nor borrow the new activation ID.
	client.pollMu.Lock()
	a.AssignmentRevision++
	next, err := collector.Prepare(a, revision)
	if err != nil {
		t.Fatal(err)
	}
	collector.Replace(next)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.SendHeartbeat(ctx); err != nil {
		client.pollMu.Unlock()
		t.Fatal(err)
	}
	client.pollMu.Unlock()
	if received.Telemetry != nil || received.PolicyID != revision.PolicyID || received.PolicyVersion != revision.PolicyVersion || received.PolicyHash != revision.PolicyHash {
		t.Fatalf("in-flight activation weakened acknowledgement: %+v", received)
	}
	client.mu.Lock()
	client.telemetryRevision = collector.ActiveRevision()
	client.mu.Unlock()
	if err := client.SendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if received.Telemetry == nil || received.Telemetry.Revision.AssignmentRevision != 2 {
		t.Fatalf("completed activation telemetry missing: %+v", received)
	}
}

func TestTelemetryHTTPAuthenticatedAcknowledgementAndHistoricalCohorts(t *testing.T) {
	fleet, rm, _ := setupRolloutTest(t)
	if _, err := rm.CreateRollout(RolloutConfig{ID: "r", PolicyID: "web-policy", Percentage: 50}); err != nil {
		t.Fatal(err)
	}
	store, _ := NewTelemetryStore(testTelemetryConfig())
	server := NewServer(ServerConfig{Store: fleet, JWTSecret: testJWTSecret, Telemetry: store})
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	var baseID, canaryID string
	for i := 0; baseID == "" || canaryID == ""; i++ {
		id := fmt.Sprintf("agent-%d", i)
		if consistentBucket("r", id) < 50 {
			canaryID = id
		} else {
			baseID = id
		}
	}
	clients := map[string]*Client{}
	collectors := map[string]*telemetry.Collector{}
	failed := false
	updates := map[string]int{}
	for _, id := range []string{baseID, canaryID} {
		id := id
		collector := &telemetry.Collector{}
		collectors[id] = collector
		client := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: id, Token: telemetryToken(t, RoleAgent, id), Labels: map[string]string{"tier": "web"}, Telemetry: collector, OnUpdate: func(a *PolicyAssignment, _ []byte) error {
			updates[id]++
			if failed {
				return errors.New("activation failed")
			}
			if a.Telemetry == nil {
				collector.Seal()
				return nil
			}
			s, err := collector.Prepare(*a.Telemetry, telemetry.Revision{PolicyID: a.PolicyID, PolicyVersion: a.Version, PolicyHash: a.WASMHash})
			if err == nil {
				collector.Replace(s)
			}
			return err
		}})
		clients[id] = client
		if err := client.Register(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := client.AuthorizeTelemetry(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// Register both nodes before resolving the common generation.
	for _, c := range clients {
		c.poll(context.Background())
		if err := c.SendHeartbeat(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	store.clock = func() time.Time { return time.Now().Add(2 * time.Second) }
	collectors[baseID].Record(false, false, false)
	collectors[canaryID].Record(true, false, false)
	for _, c := range clients {
		if err := c.SendHeartbeat(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	store.clock = func() time.Time { return time.Now().Add(4 * time.Second) }
	r := store.Report("r")
	if r.Verdict != "degraded" || r.Baseline.Total != 1 || r.Canary.Total != 1 || !r.ReportOnly {
		t.Fatalf("report: %+v", r)
	}
	// A valid token from the other agent cannot carry the victim's snapshot,
	// even if the request's ordinary artifact acknowledgement is forged to match.
	victim := collectors[canaryID].Snapshot()
	post := func(token, id string, snapshot *telemetry.Snapshot) *httptest.ResponseRecorder {
		body, _ := json.Marshal(HeartbeatRequest{AgentID: id, PolicyID: victim.Revision.PolicyID, PolicyVersion: victim.Revision.PolicyVersion, PolicyHash: victim.Revision.PolicyHash, Telemetry: snapshot})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/heartbeat", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, req)
		return w
	}
	if w := post(clients[baseID].token, canaryID, victim); w.Code != http.StatusForbidden {
		t.Fatalf("cross-principal accepted: %d", w.Code)
	}
	if w := post(clients[baseID].token, baseID, victim); w.Code != http.StatusConflict {
		t.Fatalf("cross-session accepted: %d %s", w.Code, w.Body.String())
	}
	if w := post(telemetryToken(t, RoleAdmin, "admin"), canaryID, victim); w.Code != http.StatusConflict {
		t.Fatalf("admin telemetry impersonation accepted: %d", w.Code)
	}
	// A missing epoch never uses a default/legacy cursor.
	missing := *victim
	missing.Epoch = ""
	if w := post(clients[canaryID].token, canaryID, &missing); w.Code != http.StatusConflict {
		t.Fatalf("missing epoch accepted: %d", w.Code)
	}
	// Changing a percentage invalidates the old generation; it must not
	// reattribute late counts to the newly computed cohort.
	oldGeneration := r.Generation
	if err := rm.UpdatePercentage("r", 75); err != nil {
		t.Fatal(err)
	}
	collectors[canaryID].Record(true, false, false)
	if err := clients[canaryID].SendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	r = store.Report("r")
	if r.Generation == oldGeneration || r.Canary.Total != 0 || r.Baseline.Total != 0 || r.Verdict != "pending" {
		t.Fatalf("historical cohorts moved: %+v", r)
	}
	// Same artifact with a new assignment revision MUST invoke OnUpdate again.
	before := updates[canaryID]
	failed = true
	clients[canaryID].poll(context.Background())
	if updates[canaryID] != before+1 {
		t.Fatal("same artifact hid assignment revision change")
	}
	if err := clients[canaryID].SendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	a, _ := fleet.GetAgent(canaryID)
	if a.ActivationError == "" || store.Report("r").Verdict != "pending" {
		t.Fatal("failed activation fabricated eligibility")
	}
	failed = false
	clients[canaryID].poll(context.Background())
	if err := clients[canaryID].SendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.Report("r").Verdict != "pending" {
		t.Fatal("missing/offline baseline yielded health")
	}
	rollout, _ := rm.GetRollout("r")
	if rollout.Status != "active" {
		t.Fatal("report-only analyzer performed rollout action")
	}
}
