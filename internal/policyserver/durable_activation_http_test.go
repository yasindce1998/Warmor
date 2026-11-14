package policyserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func sameFleetAgent(a, b *Agent) bool {
	if a == nil || b == nil {
		return a == b
	}
	ac, bc := *a, *b
	ac.LastHeartbeat, bc.LastHeartbeat = time.Time{}, time.Time{}
	return a.LastHeartbeat.Equal(b.LastHeartbeat) && reflect.DeepEqual(ac, bc)
}

func postFleetJSON(t *testing.T, handler http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data)))
	return w
}

func TestFleetRegistrationHTTPCapacityFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	opts := StoreOptions{Limits: StoreLimits{MaxAgents: 1}}
	s := openTestStore(t, path, opts)
	handler := NewServer(ServerConfig{Store: s, Insecure: true}).Handler()
	w := postFleetJSON(t, handler, "/api/v1/register", RegisterRequest{ID: "first"})
	if w.Code != http.StatusOK {
		t.Fatalf("first registration: %d %s", w.Code, w.Body.String())
	}
	var agent *Agent
	if err := json.Unmarshal(w.Body.Bytes(), &agent); err != nil || agent == nil || agent.ID != "first" {
		t.Fatalf("registration did not return committed agent: %+v %v", agent, err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w = postFleetJSON(t, handler, "/api/v1/register", RegisterRequest{ID: "overflow"})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("uncommitted registration returned success: %d %s", w.Code, w.Body.String())
	}
	if _, ok := s.GetAgent("overflow"); ok {
		t.Fatal("capacity failure leaked registration into memory")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("capacity failure changed durable snapshot: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTestStore(t, path, opts)
	if agents := s.ListAgents(); len(agents) != 1 || agents[0].ID != "first" {
		t.Fatalf("capacity failure changed restored agents: %+v", agents)
	}
}

func TestFleetRegistrationHTTPWriteFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := openTestStore(t, path, StoreOptions{})
	handler := NewServer(ServerConfig{Store: s, Insecure: true}).Handler()
	if w := postFleetJSON(t, handler, "/api/v1/register", RegisterRequest{
		ID: "existing", Hostname: "old-host", Labels: map[string]string{"env": "prod"},
	}); w.Code != http.StatusOK {
		t.Fatalf("initial registration: %d %s", w.Code, w.Body.String())
	}
	before, _ := s.GetAgent("existing")
	s.backend.path = filepath.Join(t.TempDir(), "missing", "state.json")
	for _, req := range []RegisterRequest{
		{ID: "existing", Hostname: "new-host", Labels: map[string]string{"env": "staging"}},
		{ID: "new"},
	} {
		w := postFleetJSON(t, handler, "/api/v1/register", req)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("unpersisted registration returned success: %d %s", w.Code, w.Body.String())
		}
	}
	after, _ := s.GetAgent("existing")
	if !sameFleetAgent(before, after) {
		t.Fatalf("failed re-registration changed stored agent: %+v -> %+v", before, after)
	}
	if _, ok := s.GetAgent("new"); ok {
		t.Fatal("failed registration leaked into memory")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTestStore(t, path, StoreOptions{})
	if agents := s.ListAgents(); len(agents) != 1 || !sameFleetAgent(before, agents[0]) {
		t.Fatalf("failed registration changed restored state: %+v", agents)
	}
}

func TestFleetClientActivationAndDurableAcknowledgementRecovery(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := openTestStore(t, path, StoreOptions{})
	if err := s.CreatePolicy(&Policy{ID: "original"}, writeWASM(t, dir, "old.wasm", "old module")); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(NewServer(ServerConfig{Store: s, Insecure: true}).Handler())
	t.Cleanup(ts.Close)
	failActivation, activations := false, 0
	c := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: "agent", OnUpdate: func(*PolicyAssignment, []byte) error {
		activations++
		if failActivation {
			return errors.New("candidate load/publication failed")
		}
		return nil
	}})
	if err := c.Register(ctx); err != nil {
		t.Fatal(err)
	}
	c.poll(ctx)
	if err := c.SendHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	old, _ := s.GetAgent("agent")
	if old.PolicyID != "original" || old.PolicyVersion != 1 || old.PolicyHash == "" || old.ActivationError != "" {
		t.Fatalf("missing initial active acknowledgement: %+v", old)
	}
	if err := s.CreatePolicy(&Policy{ID: "replacement", Priority: 100}, writeWASM(t, dir, "new.wasm", "new module")); err != nil {
		t.Fatal(err)
	}
	failActivation = true
	c.poll(ctx)
	if err := c.SendHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	failed, _ := s.GetAgent("agent")
	if failed.PolicyID != old.PolicyID || failed.PolicyVersion != old.PolicyVersion || failed.PolicyHash != old.PolicyHash || failed.ActivationError == "" {
		t.Fatalf("failed activation acknowledged candidate: %+v", failed)
	}
	ts.Close()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTestStore(t, path, StoreOptions{})
	if restored, _ := s.GetAgent("agent"); !sameFleetAgent(restored, failed) {
		t.Fatalf("restart lost failure/active identity: %+v", restored)
	}
	ts = httptest.NewServer(NewServer(ServerConfig{Store: s, Insecure: true}).Handler())
	t.Cleanup(ts.Close)
	c.baseURL = ts.URL
	failActivation = false
	c.poll(ctx)
	// Activation succeeded, but the server must not acknowledge a heartbeat
	// whose own durable write fails. The client can retry without reactivation.
	s.backend.path = filepath.Join(dir, "missing", "state.json")
	if err := c.SendHeartbeat(ctx); err == nil {
		t.Fatal("heartbeat client accepted an unpersisted acknowledgement")
	}
	if got, _ := s.GetAgent("agent"); !sameFleetAgent(got, failed) {
		t.Fatalf("failed heartbeat leaked acknowledgement: %+v", got)
	}
	ts.Close()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTestStore(t, path, StoreOptions{})
	if restored, _ := s.GetAgent("agent"); !sameFleetAgent(restored, failed) {
		t.Fatalf("failed heartbeat changed restart identity: %+v", restored)
	}
	ts = httptest.NewServer(NewServer(ServerConfig{Store: s, Insecure: true}).Handler())
	t.Cleanup(ts.Close)
	c.baseURL = ts.URL
	if err := c.SendHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	c.poll(ctx)
	accepted, _ := s.GetAgent("agent")
	if activations != 3 || accepted.PolicyID != "replacement" || accepted.PolicyVersion != 1 || accepted.PolicyHash == old.PolicyHash || accepted.PolicyHash != c.policyHash || accepted.ActivationError != "" {
		t.Fatalf("successful retry not recorded exactly: activations=%d agent=%+v", activations, accepted)
	}
	ts.Close()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTestStore(t, path, StoreOptions{})
	if restored, _ := s.GetAgent("agent"); !sameFleetAgent(restored, accepted) {
		t.Fatalf("restart lost successful acknowledgement: %+v", restored)
	}
}

func TestFleetLegacyHeartbeatClearsUnknownIdentityDurably(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := openTestStore(t, path, StoreOptions{})
	if _, err := s.RegisterAgentChecked(&RegisterRequest{ID: "agent"}); err != nil {
		t.Fatal(err)
	}
	if err := s.HeartbeatRevision(HeartbeatRequest{AgentID: "agent", PolicyID: "p", PolicyVersion: 1, PolicyHash: "digest"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Heartbeat("agent", 2); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTestStore(t, path, StoreOptions{})
	if a, _ := s.GetAgent("agent"); a.PolicyVersion != 2 || a.PolicyID != "" || a.PolicyHash != "" {
		t.Fatalf("legacy heartbeat retained a fabricated full identity: %+v", a)
	}
	w := postFleetJSON(t, NewServer(ServerConfig{Store: s, Insecure: true}).Handler(), "/api/v1/heartbeat", HeartbeatRequest{AgentID: "missing"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown agent: %d %s", w.Code, w.Body.String())
	}
}
