package policyserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/drift"
	"github.com/yasindce1998/warmor/internal/telemetry"
)

// The shared heartbeat still has three distinct admission/commit boundaries:
// drift validation, durable artifact acknowledgement, then optional telemetry.
func TestTelemetryHeartbeatPreservesDriftAdmissionAndDurableAcknowledgement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.json")
	fleet := openTestStore(t, path, StoreOptions{})
	store, err := NewTelemetryStore(testTelemetryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := NewServer(ServerConfig{Store: fleet, JWTSecret: testJWTSecret, Telemetry: store})
	server.drift = drift.NewDetector(drift.DetectorConfig{MaxPatterns: 1})
	if _, err := fleet.RegisterAgentChecked(&RegisterRequest{ID: "agent"}); err != nil {
		t.Fatal(err)
	}
	post := func(req HeartbeatRequest) *httptest.ResponseRecorder {
		t.Helper()
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
	req := HeartbeatRequest{AgentID: "agent", PolicyID: "p", PolicyVersion: 1, PolicyHash: strings.Repeat("a", 64)}
	req.Fingerprint = &drift.BehaviorFingerprint{AgentID: "untrusted", ImageHash: "workload-image", Window: time.Minute, Warmup: true, Vectors: map[string]float64{"exec:a": 1, "exec:b": 1}}
	if w := post(req); w.Code != http.StatusBadRequest {
		t.Fatalf("configured drift rejection hidden: %d %s", w.Code, w.Body.String())
	}
	if ack, _ := fleet.GetAgent("agent"); ack.PolicyID != "" || ack.PolicyVersion != 0 {
		t.Fatalf("rejected fingerprint committed acknowledgement: %+v", ack)
	}
	delete(req.Fingerprint.Vectors, "exec:b")
	if w := post(req); w.Code != http.StatusOK {
		t.Fatalf("ordinary heartbeat failed with telemetry enabled: %d %s", w.Code, w.Body.String())
	}
	if server.drift.AgentCount("workload-image") != 1 || server.drift.AgentCount(req.PolicyHash) != 0 {
		t.Fatal("telemetry replaced or fabricated workload image identity")
	}
	if report := store.Report("unknown"); report.Verdict != "pending" || !report.ReportOnly || report.Baseline.Total != 0 || report.Canary.Total != 0 {
		t.Fatalf("plain heartbeat created evidence: %+v", report)
	}
	// Malformed optional evidence returns a conflict AFTER the ordinary ack
	// commits. A non-2xx response must not be mistaken for an ack rollback.
	req.Fingerprint = nil
	req.PolicyVersion = 2
	req.PolicyHash = strings.Repeat("b", 64)
	req.ActivationError = "candidate activation failed"
	req.Telemetry = &telemetry.Snapshot{}
	if w := post(req); w.Code != http.StatusConflict {
		t.Fatalf("invalid telemetry was not surfaced: %d %s", w.Code, w.Body.String())
	}
	if err := fleet.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestStore(t, path, StoreOptions{})
	ack, _ := reopened.GetAgent("agent")
	if ack.PolicyID != req.PolicyID || ack.PolicyVersion != req.PolicyVersion || ack.PolicyHash != req.PolicyHash || ack.ActivationError != req.ActivationError {
		t.Fatalf("telemetry failure replaced durable ack: %+v", ack)
	}
}
