package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixtures holds the canned admin API responses served by fakeServer.
type fixtures struct {
	agents   []agentInfo
	policies []policyInfo
	rollouts []rolloutInfo
	// failPath, when set, makes that path return 500.
	failPath string
}

// fakeServer is an httptest server that serves canned admin API responses
// and records the Authorization header and paths of requests. Fixtures are
// fixed at construction so the handler goroutines never race with the test.
type fakeServer struct {
	*httptest.Server
	mu       sync.Mutex
	lastAuth string
	hits     []string
}

func (fs *fakeServer) auth() string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.lastAuth
}

func (fs *fakeServer) paths() []string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return append([]string(nil), fs.hits...)
}

func newFakeServer(t *testing.T, fx fixtures) *fakeServer {
	t.Helper()
	fs := &fakeServer{}
	fs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		fs.lastAuth = r.Header.Get("Authorization")
		fs.hits = append(fs.hits, r.URL.Path)
		fs.mu.Unlock()
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if fx.failPath != "" && r.URL.Path == fx.failPath {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		var out any
		switch r.URL.Path {
		case "/api/v1/admin/agents":
			out = fx.agents
		case "/api/v1/admin/policies":
			out = fx.policies
		case "/api/v1/admin/rollouts":
			out = fx.rollouts
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(fs.Close)
	return fs
}

func TestAPIClientGet_DecodesAndSendsToken(t *testing.T) {
	hb := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fs := newFakeServer(t, fixtures{agents: []agentInfo{{
		ID: "a1", Hostname: "h1", Status: "online", PolicyVersion: 7,
		Labels: map[string]string{"env": "prod"}, LastHeartbeat: hb,
	}}})

	c := newAPIClient(fs.URL, "secret-token")
	var got []agentInfo
	if err := c.get("/api/v1/admin/agents", &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if fs.auth() != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want Bearer secret-token", fs.auth())
	}
	if len(got) != 1 || got[0].ID != "a1" || got[0].PolicyVersion != 7 ||
		got[0].Labels["env"] != "prod" || !got[0].LastHeartbeat.Equal(hb) {
		t.Errorf("decoded agents = %+v", got)
	}
}

func TestAPIClientGet_NoTokenOmitsHeader(t *testing.T) {
	fs := newFakeServer(t, fixtures{})
	c := newAPIClient(fs.URL, "")
	var got []policyInfo
	if err := c.get("/api/v1/admin/policies", &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if fs.auth() != "" {
		t.Errorf("Authorization header should be empty, got %q", fs.auth())
	}
}

func TestAPIClientGet_HTTPErrorIncludesStatusAndBody(t *testing.T) {
	fs := newFakeServer(t, fixtures{failPath: "/api/v1/admin/rollouts"})
	c := newAPIClient(fs.URL, "")
	var got []rolloutInfo
	err := c.get("/api/v1/admin/rollouts", &got)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "HTTP 500") || !strings.Contains(err.Error(), "boom") {
		t.Errorf("error = %q, want HTTP 500 with body", err)
	}
}

func TestAPIClientGet_NotFound(t *testing.T) {
	fs := newFakeServer(t, fixtures{})
	c := newAPIClient(fs.URL, "")
	var out any
	if err := c.get("/nope", &out); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("err = %v, want HTTP 404", err)
	}
}

func TestAPIClientGet_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	defer srv.Close()
	c := newAPIClient(srv.URL, "")
	var out []agentInfo
	if err := c.get("/x", &out); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestAPIClientGet_ConnectionRefused(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listening any more

	c := newAPIClient(url, "")
	var out any
	err := c.get("/x", &out)
	if err == nil || !strings.Contains(err.Error(), "request failed") {
		t.Errorf("err = %v, want request failed", err)
	}
}

func TestAPIClientGet_BadURL(t *testing.T) {
	c := newAPIClient("http://bad url with spaces", "")
	var out any
	if err := c.get("/x", &out); err == nil {
		t.Fatal("expected error for malformed URL")
	}
}

func TestNewAPIClientTimeout(t *testing.T) {
	c := newAPIClient("http://example.invalid", "tok")
	if c.http.Timeout != 10*time.Second {
		t.Errorf("timeout = %v, want 10s", c.http.Timeout)
	}
	if c.baseURL != "http://example.invalid" || c.token != "tok" {
		t.Errorf("client fields = %+v", c)
	}
}
