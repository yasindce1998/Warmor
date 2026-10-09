package policyserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func setupTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	srv := NewServer(ServerConfig{Addr: ":0", Insecure: true, PolicyDir: t.TempDir()})
	ts := httptest.NewServer(srv.httpServer.Handler)
	return srv, ts
}

func TestRegisterAndHeartbeat(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	// Register agent
	body, _ := json.Marshal(RegisterRequest{
		ID:       "agent-1",
		Hostname: "node-1",
		Labels:   map[string]string{"env": "prod", "region": "us-east"},
	})
	resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register: status %d", resp.StatusCode)
	}

	// Verify agent exists
	agent, ok := srv.store.GetAgent("agent-1")
	if !ok {
		t.Fatal("agent not found after register")
	}
	if agent.Hostname != "node-1" {
		t.Errorf("expected hostname=node-1, got %s", agent.Hostname)
	}
	if agent.Status != AgentStatusActive {
		t.Errorf("expected status=active, got %s", agent.Status)
	}

	// Heartbeat
	hb, _ := json.Marshal(HeartbeatRequest{AgentID: "agent-1", PolicyVersion: 1})
	resp, err = http.Post(ts.URL+"/api/v1/heartbeat", "application/json", bytes.NewReader(hb))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat: status %d", resp.StatusCode)
	}
}

func TestPolicyCRUD(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	// Create a WASM file in the server's policy directory
	dir := srv.policyDir
	wasmPath := filepath.Join(dir, "test.wasm")
	_ = os.WriteFile(wasmPath, []byte("fake-wasm-binary"), 0644)

	// Create policy
	p := Policy{
		ID:       "default-deny",
		Name:     "Default Deny",
		WASMPath: wasmPath,
		Selector: map[string]string{"env": "prod"},
		Priority: 10,
	}
	body, _ := json.Marshal(p)
	resp, err := http.Post(ts.URL+"/api/v1/admin/policies", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create policy: status %d", resp.StatusCode)
	}

	// List policies
	resp, err = http.Get(ts.URL + "/api/v1/admin/policies")
	if err != nil {
		t.Fatal(err)
	}
	var policies []*Policy
	_ = json.NewDecoder(resp.Body).Decode(&policies)
	resp.Body.Close()
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if policies[0].Version != 1 {
		t.Errorf("expected version=1, got %d", policies[0].Version)
	}
	if policies[0].WASMHash == "" {
		t.Error("expected non-empty wasm hash")
	}

	// Get specific policy
	resp, err = http.Get(ts.URL + "/api/v1/admin/policies/default-deny")
	if err != nil {
		t.Fatal(err)
	}
	var got Policy
	_ = json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if got.ID != "default-deny" {
		t.Errorf("expected id=default-deny, got %s", got.ID)
	}

	// Delete policy
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/policies/default-deny", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: status %d", resp.StatusCode)
	}

	// Verify gone
	resp, _ = http.Get(ts.URL + "/api/v1/admin/policies/default-deny")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", resp.StatusCode)
	}
}

func TestPolicyMatching(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	// Create WASM file
	dir := t.TempDir()
	wasmPath := filepath.Join(dir, "policy.wasm")
	_ = os.WriteFile(wasmPath, []byte("wasm-bytes"), 0644)

	// Create a policy targeting env=prod
	_ = srv.store.CreatePolicy(&Policy{
		ID:       "prod-policy",
		Name:     "Prod Policy",
		Selector: map[string]string{"env": "prod"},
		Priority: 10,
	}, wasmPath)

	// Register an agent with matching labels
	body, _ := json.Marshal(RegisterRequest{
		ID:       "agent-prod",
		Hostname: "prod-node",
		Labels:   map[string]string{"env": "prod", "tier": "web"},
	})
	_, _ = http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))

	// Get policy for agent
	resp, err := http.Get(ts.URL + "/api/v1/policy?agent_id=agent-prod")
	if err != nil {
		t.Fatal(err)
	}
	var assignment PolicyAssignment
	_ = json.NewDecoder(resp.Body).Decode(&assignment)
	resp.Body.Close()

	if assignment.PolicyID != "prod-policy" {
		t.Errorf("expected policy=prod-policy, got %s", assignment.PolicyID)
	}
	if assignment.Version != 1 {
		t.Errorf("expected version=1, got %d", assignment.Version)
	}

	// Version-based long-poll: should return 304 if agent already has version 1
	resp, err = http.Get(ts.URL + "/api/v1/policy?agent_id=agent-prod&if_version=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("expected 304, got %d", resp.StatusCode)
	}

	// No matching policy for non-prod agent
	body, _ = json.Marshal(RegisterRequest{
		ID:       "agent-dev",
		Hostname: "dev-node",
		Labels:   map[string]string{"env": "dev"},
	})
	_, _ = http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))

	resp, _ = http.Get(ts.URL + "/api/v1/policy?agent_id=agent-dev")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for non-matching agent, got %d", resp.StatusCode)
	}
}

func TestWASMDownload(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	dir := t.TempDir()
	wasmPath := filepath.Join(dir, "test.wasm")
	wasmContent := []byte{0x00, 0x61, 0x73, 0x6d} // WASM magic bytes
	_ = os.WriteFile(wasmPath, wasmContent, 0644)

	_ = srv.store.CreatePolicy(&Policy{
		ID:   "my-policy",
		Name: "Test",
	}, wasmPath)

	resp, err := http.Get(ts.URL + "/api/v1/policy/wasm?policy_id=my-policy")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/wasm" {
		t.Errorf("expected content-type=application/wasm, got %s", resp.Header.Get("Content-Type"))
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	if !bytes.Equal(buf.Bytes(), wasmContent) {
		t.Error("wasm content mismatch")
	}
}

func TestRolloutHTTPEndpoints(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	// Create a policy first
	dir := t.TempDir()
	wasmPath := filepath.Join(dir, "policy.wasm")
	_ = os.WriteFile(wasmPath, []byte("wasm-data"), 0644)
	_ = srv.Store().CreatePolicy(&Policy{
		ID:       "web-policy",
		Name:     "Web Policy",
		Selector: map[string]string{"tier": "web"},
		Priority: 10,
	}, wasmPath)
	_ = srv.Store().UpdatePolicy("web-policy", wasmPath)

	// Create rollout
	cfg, _ := json.Marshal(RolloutConfig{
		ID:            "canary-1",
		PolicyID:      "web-policy",
		TargetVersion: 2,
		Percentage:    25,
	})
	resp, err := http.Post(ts.URL+"/api/v1/admin/rollouts", "application/json", bytes.NewReader(cfg))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create rollout: status %d", resp.StatusCode)
	}

	// List rollouts
	resp, err = http.Get(ts.URL + "/api/v1/admin/rollouts")
	if err != nil {
		t.Fatal(err)
	}
	var rollouts []*RolloutState
	_ = json.NewDecoder(resp.Body).Decode(&rollouts)
	resp.Body.Close()
	if len(rollouts) != 1 {
		t.Fatalf("expected 1 rollout, got %d", len(rollouts))
	}
	if rollouts[0].ID != "canary-1" {
		t.Errorf("expected id=canary-1, got %s", rollouts[0].ID)
	}

	// Get specific rollout
	resp, err = http.Get(ts.URL + "/api/v1/admin/rollouts/canary-1")
	if err != nil {
		t.Fatal(err)
	}
	var state RolloutState
	_ = json.NewDecoder(resp.Body).Decode(&state)
	resp.Body.Close()
	if state.Percentage != 25 {
		t.Errorf("expected percentage=25, got %d", state.Percentage)
	}

	// Update percentage
	update, _ := json.Marshal(map[string]int{"percentage": 75})
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/rollouts/canary-1", bytes.NewReader(update))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewDecoder(resp.Body).Decode(&state)
	resp.Body.Close()
	if state.Percentage != 75 {
		t.Errorf("expected percentage=75 after update, got %d", state.Percentage)
	}

	// Abort rollout
	req, _ = http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/rollouts/canary-1", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("abort rollout: status %d", resp.StatusCode)
	}

	// Verify aborted
	resp, _ = http.Get(ts.URL + "/api/v1/admin/rollouts/canary-1")
	_ = json.NewDecoder(resp.Body).Decode(&state)
	resp.Body.Close()
	if state.Status != "aborted" {
		t.Errorf("expected status=aborted, got %s", state.Status)
	}

	// An aborted rollout can't be ramped again or re-aborted.
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		req, _ = http.NewRequest(method, ts.URL+"/api/v1/admin/rollouts/canary-1", bytes.NewReader(update))
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusConflict {
			t.Errorf("%s on aborted rollout: expected 409, got %d", method, resp.StatusCode)
		}
	}
}

func TestRolloutAffectsPolicyDistribution(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	dir := t.TempDir()
	wasmPath := filepath.Join(dir, "policy.wasm")
	_ = os.WriteFile(wasmPath, []byte("wasm-v1"), 0644)

	_ = srv.Store().CreatePolicy(&Policy{
		ID:       "app-policy",
		Name:     "App Policy",
		Selector: map[string]string{"app": "web"},
		Priority: 10,
	}, wasmPath)

	// Update policy to v2
	_ = os.WriteFile(wasmPath, []byte("wasm-v2"), 0644)
	_ = srv.Store().UpdatePolicy("app-policy", wasmPath)

	// Register agent
	body, _ := json.Marshal(RegisterRequest{
		ID:     "agent-1",
		Labels: map[string]string{"app": "web"},
	})
	_, _ = http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))

	// Create rollout at 100% targeting v2
	_, _ = srv.Rollouts().CreateRollout(RolloutConfig{
		ID:            "full-rollout",
		PolicyID:      "app-policy",
		TargetVersion: 2,
		Percentage:    100,
	})

	// Agent should get v2 via rollout
	resp, err := http.Get(ts.URL + "/api/v1/policy?agent_id=agent-1")
	if err != nil {
		t.Fatal(err)
	}
	var assignment PolicyAssignment
	_ = json.NewDecoder(resp.Body).Decode(&assignment)
	resp.Body.Close()

	if assignment.Version != 2 {
		t.Errorf("expected version=2 with 100%% rollout, got %d", assignment.Version)
	}
}
