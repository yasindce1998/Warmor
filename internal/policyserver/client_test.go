package policyserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type updateRecorder struct {
	mu      sync.Mutex
	updates []*PolicyAssignment
	wasm    [][]byte
	notify  chan struct{}
}

func newUpdateRecorder() *updateRecorder {
	return &updateRecorder{notify: make(chan struct{}, 16)}
}

func (u *updateRecorder) onUpdate(a *PolicyAssignment, data []byte) {
	u.mu.Lock()
	u.updates = append(u.updates, a)
	u.wasm = append(u.wasm, data)
	u.mu.Unlock()
	u.notify <- struct{}{}
}

func (u *updateRecorder) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.updates)
}

// setupClientEnv starts a real policy server with one policy matching env=prod.
func setupClientEnv(t *testing.T) (*Server, *httptest.Server, string) {
	t.Helper()
	srv, ts := setupTestServer(t)
	t.Cleanup(ts.Close)

	wasmPath := filepath.Join(t.TempDir(), "p.wasm")
	if err := os.WriteFile(wasmPath, []byte("wasm-v1"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := srv.Store().CreatePolicy(&Policy{
		ID: "prod-policy", Selector: map[string]string{"env": "prod"},
	}, wasmPath); err != nil {
		t.Fatal(err)
	}
	return srv, ts, wasmPath
}

func TestClientRegisterPollAndHeartbeat(t *testing.T) {
	srv, ts, wasmPath := setupClientEnv(t)
	rec := newUpdateRecorder()

	c := NewClient(ClientConfig{
		ServerURL: ts.URL,
		AgentID:   "agent-1",
		Hostname:  "node-1",
		Labels:    map[string]string{"env": "prod"},
		OnUpdate:  rec.onUpdate,
	})
	ctx := context.Background()

	if err := c.Register(ctx); err != nil {
		t.Fatal(err)
	}
	agent, ok := srv.Store().GetAgent("agent-1")
	if !ok || agent.Hostname != "node-1" || agent.Labels["env"] != "prod" {
		t.Fatalf("agent not registered correctly: %+v", agent)
	}

	// First poll pulls version 1 and its WASM.
	c.poll(ctx)
	if rec.count() != 1 {
		t.Fatalf("expected 1 update, got %d", rec.count())
	}
	if rec.updates[0].PolicyID != "prod-policy" || rec.updates[0].Version != 1 {
		t.Errorf("unexpected assignment: %+v", rec.updates[0])
	}
	if string(rec.wasm[0]) != "wasm-v1" {
		t.Errorf("unexpected wasm data: %q", rec.wasm[0])
	}

	// Second poll: server returns 304, no callback.
	c.poll(ctx)
	if rec.count() != 1 {
		t.Fatalf("expected no update on unchanged version, got %d", rec.count())
	}

	// Heartbeat reports the applied version.
	if err := c.SendHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	agent, _ = srv.Store().GetAgent("agent-1")
	if agent.PolicyVersion != 1 {
		t.Errorf("expected heartbeat to report version 1, got %d", agent.PolicyVersion)
	}

	// Policy update bumps version; next poll picks it up.
	if err := os.WriteFile(wasmPath, []byte("wasm-v2"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := srv.Store().UpdatePolicy("prod-policy", wasmPath); err != nil {
		t.Fatal(err)
	}
	c.poll(ctx)
	if rec.count() != 2 || rec.updates[1].Version != 2 || string(rec.wasm[1]) != "wasm-v2" {
		t.Fatalf("expected v2 update, got %d updates", rec.count())
	}
}

func TestClientPollWithoutCallback(t *testing.T) {
	srv, ts, _ := setupClientEnv(t)
	srv.Store().RegisterAgent(&RegisterRequest{ID: "a", Labels: map[string]string{"env": "prod"}})

	c := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: "a"})
	c.poll(context.Background())
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.policyVersion != 1 {
		t.Errorf("expected version to advance to 1 without callback, got %d", c.policyVersion)
	}
}

func TestClientPollUnregisteredAgent(t *testing.T) {
	_, ts, _ := setupClientEnv(t)
	rec := newUpdateRecorder()
	c := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: "ghost", OnUpdate: rec.onUpdate})
	c.poll(context.Background())
	if rec.count() != 0 {
		t.Error("expected no update for unregistered agent")
	}
}

func TestClientPollErrorPaths(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "invalid JSON",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("{not json"))
			},
		},
		{
			name: "stale version",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, http.StatusOK, PolicyAssignment{PolicyID: "p", Version: 0})
			},
		},
		{
			name: "wasm fetch fails",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/wasm") {
					http.Error(w, "gone", http.StatusInternalServerError)
					return
				}
				writeJSON(w, http.StatusOK, PolicyAssignment{PolicyID: "p", Version: 5})
			},
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "boom", http.StatusInternalServerError)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(tc.handler)
			defer ts.Close()
			rec := newUpdateRecorder()
			c := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: "a", OnUpdate: rec.onUpdate})
			c.poll(context.Background())
			if rec.count() != 0 {
				t.Errorf("expected no update, got %d", rec.count())
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.policyVersion != 0 {
				t.Errorf("expected version unchanged, got %d", c.policyVersion)
			}
		})
	}
}

func TestClientPollSendsCurrentVersion(t *testing.T) {
	gotVersion := make(chan string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion <- r.URL.Query().Get("if_version") + "/" + r.URL.Query().Get("agent_id")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer ts.Close()

	c := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: "agent-x"})
	c.policyVersion = 7
	c.poll(context.Background())
	if got := <-gotVersion; got != "7/agent-x" {
		t.Errorf("expected if_version=7 agent_id=agent-x, got %s", got)
	}
}

func TestClientNetworkErrors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := ts.URL
	ts.Close()

	c := NewClient(ClientConfig{ServerURL: url, AgentID: "a"})
	ctx := context.Background()
	if err := c.Register(ctx); err == nil || !strings.Contains(err.Error(), "register") {
		t.Errorf("expected register network error, got %v", err)
	}
	if err := c.SendHeartbeat(ctx); err == nil || !strings.Contains(err.Error(), "heartbeat") {
		t.Errorf("expected heartbeat network error, got %v", err)
	}
	if _, err := c.fetchWASM(ctx, "p"); err == nil || !strings.Contains(err.Error(), "fetch wasm") {
		t.Errorf("expected fetch wasm network error, got %v", err)
	}
	c.poll(ctx) // must not panic
}

func TestClientInvalidURL(t *testing.T) {
	c := NewClient(ClientConfig{ServerURL: "http://bad\x7fhost", AgentID: "a"})
	ctx := context.Background()
	if err := c.Register(ctx); err == nil {
		t.Error("expected register request construction error")
	}
	if err := c.SendHeartbeat(ctx); err == nil {
		t.Error("expected heartbeat request construction error")
	}
	if _, err := c.fetchWASM(ctx, "p"); err == nil {
		t.Error("expected fetchWASM request construction error")
	}
	c.poll(ctx) // must not panic
}

func TestClientRegisterRejected(t *testing.T) {
	_, ts, _ := setupClientEnv(t)
	c := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: ""}) // server requires id
	err := c.Register(context.Background())
	if err == nil || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("expected status 400 error, got %v", err)
	}
}

func TestClientFetchWASMNotFound(t *testing.T) {
	_, ts, _ := setupClientEnv(t)
	c := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: "a"})
	_, err := c.fetchWASM(context.Background(), "missing")
	if err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("expected 404 error, got %v", err)
	}
}

func TestClientPollLoop(t *testing.T) {
	srv, ts, _ := setupClientEnv(t)
	srv.Store().RegisterAgent(&RegisterRequest{ID: "loop", Labels: map[string]string{"env": "prod"}})

	rec := newUpdateRecorder()
	c := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: "loop", OnUpdate: rec.onUpdate})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.PollLoop(ctx, time.Millisecond)
		close(done)
	}()

	select {
	case <-rec.notify:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for poll loop update")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("PollLoop did not return after cancel")
	}
}

func TestClientHeartbeatLoop(t *testing.T) {
	beats := make(chan HeartbeatRequest, 16)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var hb HeartbeatRequest
		_ = json.NewDecoder(r.Body).Decode(&hb)
		select {
		case beats <- hb:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: "hb-agent"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.HeartbeatLoop(ctx, time.Millisecond)
		close(done)
	}()

	select {
	case hb := <-beats:
		if hb.AgentID != "hb-agent" {
			t.Errorf("unexpected heartbeat agent id: %s", hb.AgentID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for heartbeat")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("HeartbeatLoop did not return after cancel")
	}
}

func TestNewClientTransport(t *testing.T) {
	c := NewClient(ClientConfig{ServerURL: "http://x"})
	tr, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if tr.TLSClientConfig != nil {
		t.Error("expected no TLS config when none provided")
	}
	if c.httpClient.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", c.httpClient.Timeout)
	}
}
