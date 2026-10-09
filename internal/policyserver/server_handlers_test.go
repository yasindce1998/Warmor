package policyserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

type handlerCase struct {
	name   string
	method string
	path   string
	body   string
	want   int
}

func runHandlerCases(t *testing.T, ts *httptest.Server, cases []handlerCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body io.Reader
			if tc.body != "" {
				body = bytes.NewBufferString(tc.body)
			}
			req, err := http.NewRequest(tc.method, ts.URL+tc.path, body)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Errorf("%s %s: expected %d, got %d", tc.method, tc.path, tc.want, resp.StatusCode)
			}
		})
	}
}

func TestNewServerDefaults(t *testing.T) {
	srv := NewServer(ServerConfig{})
	if srv.addr != ":8443" || srv.httpServer.Addr != ":8443" {
		t.Errorf("expected default addr :8443, got %s", srv.addr)
	}
	if srv.staleCheck != 90*time.Second {
		t.Errorf("expected default stale threshold 90s, got %v", srv.staleCheck)
	}
	if srv.Store() == nil || srv.Rollouts() == nil {
		t.Error("expected store and rollout manager")
	}
	if srv.httpServer.ReadTimeout == 0 || srv.httpServer.WriteTimeout == 0 {
		t.Error("expected HTTP timeouts to be set")
	}

	srv = NewServer(ServerConfig{Addr: "127.0.0.1:0", StaleThreshold: time.Second})
	if srv.addr != "127.0.0.1:0" || srv.staleCheck != time.Second {
		t.Errorf("custom config not applied: %s %v", srv.addr, srv.staleCheck)
	}
}

func TestServerStartShutdown(t *testing.T) {
	for _, withTLS := range []bool{false, true} {
		name := "plain"
		if withTLS {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) {
			cfg := ServerConfig{Addr: "127.0.0.1:0"}
			if withTLS {
				pki := newTestPKI(t)
				tlsCfg, err := newServerTLS(pki)
				if err != nil {
					t.Fatal(err)
				}
				cfg.TLSConfig = tlsCfg
			}
			srv := NewServer(cfg)
			errCh := make(chan error, 1)
			go func() { errCh <- srv.Start() }()

			// Shutdown either interrupts the running listener or, if it wins the
			// race, causes Start to return ErrServerClosed immediately. Both
			// paths must yield a nil error from Start.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				t.Fatalf("shutdown: %v", err)
			}
			select {
			case err := <-errCh:
				if err != nil {
					t.Errorf("expected nil error from Start after Shutdown, got %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Start did not return after Shutdown")
			}
		})
	}
}

func TestServerStartListenError(t *testing.T) {
	srv := NewServer(ServerConfig{Addr: "256.256.256.256:99999"})
	if err := srv.Start(); err == nil {
		t.Fatal("expected listen error for invalid address")
	}
}

func TestAgentEndpointErrors(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	srv.Store().RegisterAgent(&RegisterRequest{ID: "no-policy", Labels: map[string]string{"env": "none"}})

	runHandlerCases(t, ts, []handlerCase{
		{"register GET", http.MethodGet, "/api/v1/register", "", http.StatusMethodNotAllowed},
		{"register bad json", http.MethodPost, "/api/v1/register", "{", http.StatusBadRequest},
		{"register missing id", http.MethodPost, "/api/v1/register", `{"hostname":"h"}`, http.StatusBadRequest},
		{"heartbeat GET", http.MethodGet, "/api/v1/heartbeat", "", http.StatusMethodNotAllowed},
		{"heartbeat bad json", http.MethodPost, "/api/v1/heartbeat", "nope", http.StatusBadRequest},
		{"heartbeat unknown agent", http.MethodPost, "/api/v1/heartbeat", `{"agent_id":"ghost"}`, http.StatusNotFound},
		{"policy POST", http.MethodPost, "/api/v1/policy", "", http.StatusMethodNotAllowed},
		{"policy missing agent_id", http.MethodGet, "/api/v1/policy", "", http.StatusBadRequest},
		{"policy unknown agent", http.MethodGet, "/api/v1/policy?agent_id=ghost", "", http.StatusNotFound},
		{"policy no match", http.MethodGet, "/api/v1/policy?agent_id=no-policy", "", http.StatusNotFound},
		{"wasm POST", http.MethodPost, "/api/v1/policy/wasm", "", http.StatusMethodNotAllowed},
		{"wasm missing id", http.MethodGet, "/api/v1/policy/wasm", "", http.StatusBadRequest},
		{"wasm unknown", http.MethodGet, "/api/v1/policy/wasm?policy_id=nope", "", http.StatusNotFound},
	})
}

func TestHeartbeatResponses(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	srv.Store().RegisterAgent(&RegisterRequest{ID: "a1", Labels: map[string]string{"env": "prod"}})

	post := func() map[string]any {
		t.Helper()
		resp, err := http.Post(ts.URL+"/api/v1/heartbeat", "application/json",
			bytes.NewBufferString(`{"agent_id":"a1","policy_version":0}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("heartbeat: status %d", resp.StatusCode)
		}
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}

	if out := post(); out["policy"] != "none" || out["status"] != "ok" {
		t.Errorf("expected no-policy response, got %v", out)
	}

	w := writeWASM(t, t.TempDir(), "p.wasm", "x")
	_ = srv.Store().CreatePolicy(&Policy{ID: "prod", Selector: map[string]string{"env": "prod"}}, w)
	if out := post(); out["policy_id"] != "prod" || out["version"] != float64(1) {
		t.Errorf("expected assignment in heartbeat response, got %v", out)
	}
}

func TestGetPolicyIfVersion(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	w := writeWASM(t, t.TempDir(), "p.wasm", "x")
	_ = srv.Store().CreatePolicy(&Policy{ID: "p"}, w)
	_ = srv.Store().UpdatePolicy("p", w) // version 2
	srv.Store().RegisterAgent(&RegisterRequest{ID: "a"})

	tests := []struct {
		query string
		want  int
	}{
		{"", http.StatusOK},
		{"&if_version=1", http.StatusOK},
		{"&if_version=2", http.StatusNotModified},
		{"&if_version=3", http.StatusNotModified},
		{"&if_version=garbage", http.StatusOK},
	}
	for _, tc := range tests {
		resp, err := http.Get(ts.URL + "/api/v1/policy?agent_id=a" + tc.query)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("query %q: expected %d, got %d", tc.query, tc.want, resp.StatusCode)
		}
	}
}

func TestAdminPolicyEndpoints(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dir := t.TempDir()
	w1 := writeWASM(t, dir, "v1.wasm", "one")
	w2 := writeWASM(t, dir, "v2.wasm", "two")
	missing := filepath.Join(dir, "missing.wasm")

	create, _ := json.Marshal(Policy{ID: "p1", WASMPath: w1})
	createMissing, _ := json.Marshal(Policy{ID: "p2", WASMPath: missing})
	update, _ := json.Marshal(map[string]string{"wasm_path": w2})
	updateMissing, _ := json.Marshal(map[string]string{"wasm_path": missing})

	runHandlerCases(t, ts, []handlerCase{
		{"policies PATCH", http.MethodPatch, "/api/v1/admin/policies", "", http.StatusMethodNotAllowed},
		{"create bad json", http.MethodPost, "/api/v1/admin/policies", "{", http.StatusBadRequest},
		{"create missing id", http.MethodPost, "/api/v1/admin/policies", `{"wasm_path":"x"}`, http.StatusBadRequest},
		{"create missing wasm_path", http.MethodPost, "/api/v1/admin/policies", `{"id":"x"}`, http.StatusBadRequest},
		{"create unreadable wasm", http.MethodPost, "/api/v1/admin/policies", string(createMissing), http.StatusConflict},
		{"create ok", http.MethodPost, "/api/v1/admin/policies", string(create), http.StatusCreated},
		{"create duplicate", http.MethodPost, "/api/v1/admin/policies", string(create), http.StatusConflict},
		{"policy empty id", http.MethodGet, "/api/v1/admin/policies/", "", http.StatusBadRequest},
		{"policy get missing", http.MethodGet, "/api/v1/admin/policies/nope", "", http.StatusNotFound},
		{"policy PATCH", http.MethodPatch, "/api/v1/admin/policies/p1", "", http.StatusMethodNotAllowed},
		{"update bad json", http.MethodPut, "/api/v1/admin/policies/p1", "{", http.StatusBadRequest},
		{"update unknown", http.MethodPut, "/api/v1/admin/policies/nope", string(update), http.StatusNotFound},
		{"update unreadable wasm", http.MethodPut, "/api/v1/admin/policies/p1", string(updateMissing), http.StatusNotFound},
		{"update ok", http.MethodPut, "/api/v1/admin/policies/p1", string(update), http.StatusOK},
		{"delete unknown", http.MethodDelete, "/api/v1/admin/policies/nope", "", http.StatusNotFound},
	})

	p, ok := srv.Store().GetPolicy("p1")
	if !ok || p.Version != 2 {
		t.Fatalf("expected p1 at version 2 after update, got %+v", p)
	}
	if data, _ := srv.Store().GetWASM("p1"); string(data) != "two" {
		t.Errorf("expected updated wasm, got %q", data)
	}

	// PUT returns the updated policy body.
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/policies/p1", bytes.NewReader(update))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var got Policy
	_ = json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if got.ID != "p1" || got.Version != 3 {
		t.Errorf("unexpected PUT response: %+v", got)
	}
}

func TestAdminAgentsEndpoint(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	srv.Store().RegisterAgent(&RegisterRequest{ID: "a1", Hostname: "h1"})
	srv.Store().RegisterAgent(&RegisterRequest{ID: "a2", Hostname: "h2"})

	resp, err := http.Get(ts.URL + "/api/v1/admin/agents")
	if err != nil {
		t.Fatal(err)
	}
	var agents []*Agent
	_ = json.NewDecoder(resp.Body).Decode(&agents)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(agents) != 2 {
		t.Fatalf("expected 2 agents, got %d (status %d)", len(agents), resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("expected JSON content type, got %s", resp.Header.Get("Content-Type"))
	}

	runHandlerCases(t, ts, []handlerCase{
		{"agents POST", http.MethodPost, "/api/v1/admin/agents", "", http.StatusMethodNotAllowed},
	})
}

func TestAdminRolloutEndpointErrors(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	w := writeWASM(t, t.TempDir(), "p.wasm", "x")
	_ = srv.Store().CreatePolicy(&Policy{ID: "p"}, w)
	if _, err := srv.Rollouts().CreateRollout(RolloutConfig{ID: "r1", PolicyID: "p", TargetVersion: 2, Percentage: 10}); err != nil {
		t.Fatal(err)
	}

	runHandlerCases(t, ts, []handlerCase{
		{"rollouts PATCH", http.MethodPatch, "/api/v1/admin/rollouts", "", http.StatusMethodNotAllowed},
		{"create bad json", http.MethodPost, "/api/v1/admin/rollouts", "{", http.StatusBadRequest},
		{"create missing id", http.MethodPost, "/api/v1/admin/rollouts", `{"policy_id":"p"}`, http.StatusBadRequest},
		{"create missing policy", http.MethodPost, "/api/v1/admin/rollouts", `{"id":"r2"}`, http.StatusBadRequest},
		{"create unknown policy", http.MethodPost, "/api/v1/admin/rollouts", `{"id":"r2","policy_id":"nope"}`, http.StatusConflict},
		{"create duplicate", http.MethodPost, "/api/v1/admin/rollouts", `{"id":"r1","policy_id":"p"}`, http.StatusConflict},
		{"create bad percentage", http.MethodPost, "/api/v1/admin/rollouts", `{"id":"r3","policy_id":"p","percentage":101}`, http.StatusConflict},
		{"rollout empty id", http.MethodGet, "/api/v1/admin/rollouts/", "", http.StatusBadRequest},
		{"rollout get missing", http.MethodGet, "/api/v1/admin/rollouts/nope", "", http.StatusNotFound},
		{"rollout PATCH", http.MethodPatch, "/api/v1/admin/rollouts/r1", "", http.StatusMethodNotAllowed},
		{"update bad json", http.MethodPut, "/api/v1/admin/rollouts/r1", "{", http.StatusBadRequest},
		{"update unknown", http.MethodPut, "/api/v1/admin/rollouts/nope", `{"percentage":5}`, http.StatusNotFound},
		{"update out of range", http.MethodPut, "/api/v1/admin/rollouts/r1", `{"percentage":-1}`, http.StatusNotFound},
		{"abort unknown", http.MethodDelete, "/api/v1/admin/rollouts/nope", "", http.StatusNotFound},
	})

	if r, _ := srv.Rollouts().GetRollout("r1"); r.Percentage != 10 || r.Status != "active" {
		t.Errorf("rejected requests must not modify rollout: %+v", r)
	}
	if len(srv.Rollouts().ListRollouts()) != 1 {
		t.Error("rejected creates must not add rollouts")
	}
}
