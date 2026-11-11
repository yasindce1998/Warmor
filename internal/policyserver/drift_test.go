package policyserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/drift"
)

// newDriftTestServer returns an insecure test server (agent and admin
// endpoints open) plus the underlying Server for direct inspection.
func newDriftTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	srv := NewServer(ServerConfig{Addr: "127.0.0.1:0", Insecure: true, DriftThreshold: 2.0})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

// postHeartbeat sends a heartbeat for agentID, optionally with a
// fingerprint, and returns the response status code.
func postHeartbeat(t *testing.T, ts *httptest.Server, agentID string, fp *drift.BehaviorFingerprint) int {
	t.Helper()
	req := HeartbeatRequest{AgentID: agentID, PolicyVersion: 1, Fingerprint: fp}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(ts.URL+"/api/v1/heartbeat", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func registerAgent(t *testing.T, ts *httptest.Server, id string) {
	t.Helper()
	resp, err := http.Post(ts.URL+"/api/v1/register", "application/json",
		bytes.NewBufferString(`{"id":"`+id+`","hostname":"`+id+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register %s: status %d", id, resp.StatusCode)
	}
}

// getDrift fetches the admin drift view.
func getDrift(t *testing.T, ts *httptest.Server, query string) (int, driftStatusResponse) {
	t.Helper()
	resp, err := http.Get(ts.URL + "/api/v1/admin/drift" + query)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out driftStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode drift response: %v", err)
	}
	return resp.StatusCode, out
}

func TestHeartbeatSubmitsFingerprint(t *testing.T) {
	srv, ts := newDriftTestServer(t)
	registerAgent(t, ts, "a1")
	registerAgent(t, ts, "a2")

	// a1 claims a different AgentID inside the fingerprint; the server
	// must key it under the authenticated heartbeat identity instead.
	if code := postHeartbeat(t, ts, "a1", &drift.BehaviorFingerprint{
		AgentID:   "someone-else",
		ImageHash: "img",
		Vectors:   map[string]float64{"exec:bash": 10},
		Timestamp: time.Now(),
	}); code != http.StatusOK {
		t.Fatalf("a1 heartbeat: status %d", code)
	}
	if code := postHeartbeat(t, ts, "a2", &drift.BehaviorFingerprint{
		AgentID:   "a2",
		ImageHash: "img",
		Vectors:   map[string]float64{"exec:bash": 10, "exec:curl": 5},
		Timestamp: time.Now(),
	}); code != http.StatusOK {
		t.Fatalf("a2 heartbeat: status %d", code)
	}

	if got := srv.drift.AgentCount("img"); got != 2 {
		t.Fatalf("agent count = %d, want 2", got)
	}
	// The fingerprint must be stored under a1, not the spoofed ID.
	if anomalies := srv.drift.AnomaliesForAgent("someone-else", "img"); len(anomalies) != 0 {
		t.Errorf("anomalies attributed to spoofed agent ID: %+v", anomalies)
	}

	code, view := getDrift(t, ts, "")
	if code != http.StatusOK {
		t.Fatalf("admin drift: status %d", code)
	}
	if len(view.Images) != 1 || view.Images[0].AgentCount != 2 {
		t.Errorf("images = %+v, want one image with 2 agents", view.Images)
	}
	// a2's exec:curl is unique to it → at least one anomaly for a2.
	foundA2 := false
	for _, a := range view.Anomalies {
		if a.AgentID == "someone-else" {
			t.Errorf("anomaly attributed to spoofed agent ID: %+v", a)
		}
		if a.AgentID == "a2" && a.Pattern == "exec:curl" && a.Direction == "unique" {
			foundA2 = true
		}
	}
	if !foundA2 {
		t.Errorf("no unique-pattern anomaly for a2 in %+v", view.Anomalies)
	}

	// The agent_id filter narrows the anomaly view.
	_, filtered := getDrift(t, ts, "?agent_id=a1")
	for _, a := range filtered.Anomalies {
		if a.AgentID != "a1" {
			t.Errorf("filtered view leaked anomaly for %s", a.AgentID)
		}
	}
}

func TestHeartbeatRejectsInvalidFingerprint(t *testing.T) {
	_, ts := newDriftTestServer(t)
	registerAgent(t, ts, "a1")

	cases := []struct {
		name string
		fp   *drift.BehaviorFingerprint
	}{
		{"missing image hash", &drift.BehaviorFingerprint{Vectors: map[string]float64{"exec:bash": 1}}},
		{"image hash too long", &drift.BehaviorFingerprint{
			ImageHash: string(bytes.Repeat([]byte("x"), MaxFingerprintImageKeyLen+1)),
			Vectors:   map[string]float64{"exec:bash": 1},
		}},
		{"too many patterns", &drift.BehaviorFingerprint{
			ImageHash: "img",
			Vectors: func() map[string]float64 {
				v := make(map[string]float64, MaxFingerprintPatterns+1)
				for i := 0; i <= MaxFingerprintPatterns; i++ {
					v[fmt.Sprintf("exec:p%d", i)] = 1
				}
				return v
			}(),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code := postHeartbeat(t, ts, "a1", tc.fp); code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", code)
			}
		})
	}

	// A plain heartbeat (no fingerprint) is still accepted.
	if code := postHeartbeat(t, ts, "a1", nil); code != http.StatusOK {
		t.Errorf("plain heartbeat status = %d, want 200", code)
	}
}

func TestAdminDriftMethodNotAllowed(t *testing.T) {
	_, ts := newDriftTestServer(t)
	resp, err := http.Post(ts.URL+"/api/v1/admin/drift", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

// TestClientSendsFingerprint checks the client side: the fingerprint
// source is called for each heartbeat and its AgentID is stamped with the
// client's own agent ID.
func TestClientSendsFingerprint(t *testing.T) {
	srv, ts := newDriftTestServer(t)

	// A baseline peer so the detector actually compares (it needs at
	// least two fingerprints per image).
	registerAgent(t, ts, "peer")
	if code := postHeartbeat(t, ts, "peer", &drift.BehaviorFingerprint{
		AgentID:   "peer",
		ImageHash: "img",
		Vectors:   map[string]float64{"exec:bash": 3},
		Timestamp: time.Now(),
	}); code != http.StatusOK {
		t.Fatalf("peer heartbeat: status %d", code)
	}

	calls := 0
	c := NewClient(ClientConfig{
		ServerURL: ts.URL,
		AgentID:   "agent-x",
		Hostname:  "host-x",
		Fingerprint: func() *drift.BehaviorFingerprint {
			calls++
			return &drift.BehaviorFingerprint{
				AgentID:   "ignored",
				ImageHash: "img",
				Vectors:   map[string]float64{"exec:bash": 3, "exec:sh": 1},
				Timestamp: time.Now(),
			}
		},
	})
	if err := c.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.SendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("fingerprint source called %d times, want 1", calls)
	}
	if got := srv.drift.AgentCount("img"); got != 2 {
		t.Fatalf("agent count = %d, want 2", got)
	}
	// exec:sh is unique to the client → an anomaly stored under its own
	// agent ID, not the one the source tried to set.
	if anomalies := srv.drift.AnomaliesForAgent("agent-x", "img"); len(anomalies) == 0 {
		t.Error("fingerprint not stored under the client's agent ID")
	}
	if anomalies := srv.drift.AnomaliesForAgent("ignored", "img"); len(anomalies) != 0 {
		t.Errorf("fingerprint stored under source's agent ID: %+v", anomalies)
	}
}
