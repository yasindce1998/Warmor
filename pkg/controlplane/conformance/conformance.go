// Package conformance provides an executable version of the agent-facing
// control-plane contract defined by pkg/controlplane.
//
// A hosted control plane imports this package and calls Run from one of its Go
// tests. Passing means a stock warmor-daemon can register, receive a policy,
// conditionally poll it, download the WASM module and send heartbeats against
// that implementation without code changes.
//
// The suite assumes a policy assigned to the agent already exists. The
// in-tree reference server test provisions one through its store; an external
// implementation can pre-provision through its own admin API or fixtures.
package conformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/pkg/controlplane"
)

// Config describes the control plane under test.
type Config struct {
	// BaseURL is the agent-facing API root, e.g. http://127.0.0.1:8080.
	BaseURL string
	// AgentID is registered by the suite and used for all requests. Defaults
	// to "conformance-agent".
	AgentID string
	// AgentID labels are optional; a control plane may require labels to
	// select the pre-provisioned policy.
	Labels map[string]string
	// Token, if set, is sent as a Bearer token on every request.
	Token string
	// PolicyID is the pre-provisioned policy expected to be assigned to the
	// agent. When empty, the suite only checks that some valid assignment is
	// returned.
	PolicyID string
	// Client, if set, overrides the HTTP client (TLS, proxies, timeouts).
	Client *http.Client
}

type runner struct {
	cfg Config
	c   *http.Client
	t   *testing.T
}

func (r *runner) do(method, path string, body []byte) *http.Response {
	r.t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, r.cfg.BaseURL+path, reader)
	if err != nil {
		r.t.Fatalf("build %s %s: %v", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if r.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.cfg.Token)
	}
	resp, err := r.c.Do(req)
	if err != nil {
		r.t.Fatalf("%s %s: %v", method, path, err)
	}
	if got := resp.Header.Get(controlplane.HeaderProtocolVersion); got != controlplane.ProtocolVersionString {
		r.t.Errorf("%s %s: %s = %q, want %q", method, path, controlplane.HeaderProtocolVersion, got, controlplane.ProtocolVersionString)
	}
	return resp
}

func (r *runner) expectStatus(resp *http.Response, want int) {
	r.t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != want {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		r.t.Fatalf("status %d, want %d (body: %s)", resp.StatusCode, want, body)
	}
}

func encode(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// Run executes the full agent-facing conformance suite against cfg.BaseURL.
// It must be called from a Go test with a reachable control plane and a
// pre-provisioned policy assigned to cfg.AgentID (via its labels or selector).
func Run(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.BaseURL == "" {
		t.Fatal("conformance: BaseURL is required")
	}
	if cfg.AgentID == "" {
		cfg.AgentID = "conformance-agent"
	}
	c := cfg.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	r := &runner{cfg: cfg, c: c, t: t}

	var assignment controlplane.PolicyAssignment

	t.Run("register", func(t *testing.T) {
		r.t = t
		body := controlplane.RegisterRequest{ID: cfg.AgentID, Hostname: "conformance-host", Labels: cfg.Labels}
		r.expectStatus(r.do(http.MethodPost, controlplane.RouteRegister, encode(body)), http.StatusOK)
	})

	t.Run("register rejects wrong method", func(t *testing.T) {
		r.t = t
		r.expectStatus(r.do(http.MethodGet, controlplane.RouteRegister, nil), http.StatusMethodNotAllowed)
	})

	t.Run("register rejects malformed body", func(t *testing.T) {
		r.t = t
		r.expectStatus(r.do(http.MethodPost, controlplane.RouteRegister, []byte("{")), http.StatusBadRequest)
	})

	t.Run("register rejects empty id", func(t *testing.T) {
		r.t = t
		r.expectStatus(r.do(http.MethodPost, controlplane.RouteRegister, []byte(`{"hostname":"h"}`)), http.StatusBadRequest)
	})

	t.Run("heartbeat", func(t *testing.T) {
		r.t = t
		body := controlplane.HeartbeatRequest{AgentID: cfg.AgentID, PolicyVersion: 1}
		r.expectStatus(r.do(http.MethodPost, controlplane.RouteHeartbeat, encode(body)), http.StatusOK)
	})

	t.Run("heartbeat rejects wrong method", func(t *testing.T) {
		r.t = t
		r.expectStatus(r.do(http.MethodGet, controlplane.RouteHeartbeat, nil), http.StatusMethodNotAllowed)
	})

	t.Run("heartbeat rejects malformed body", func(t *testing.T) {
		r.t = t
		r.expectStatus(r.do(http.MethodPost, controlplane.RouteHeartbeat, []byte("{")), http.StatusBadRequest)
	})

	q := url.Values{}
	q.Set(controlplane.QueryAgentID, cfg.AgentID)
	q.Set(controlplane.QueryIfVersion, "0")
	q.Set(controlplane.QueryIfPolicyID, "")
	q.Set(controlplane.QueryIfHash, "")

	t.Run("policy assignment", func(t *testing.T) {
		r.t = t
		resp := r.do(http.MethodGet, controlplane.RoutePolicy+"?"+q.Encode(), nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			t.Fatalf("status %d, want 200 (body: %s)", resp.StatusCode, body)
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&assignment); err != nil {
			t.Fatalf("decode assignment: %v", err)
		}
		if cfg.PolicyID != "" && assignment.PolicyID != cfg.PolicyID {
			t.Errorf("policy_id = %q, want %q", assignment.PolicyID, cfg.PolicyID)
		}
		if assignment.Version <= 0 {
			t.Errorf("version = %d, want > 0", assignment.Version)
		}
		raw, err := hex.DecodeString(assignment.WASMHash)
		if err != nil || len(raw) != sha256.Size {
			t.Errorf("wasm_hash = %q, want 32-byte hex SHA-256", assignment.WASMHash)
		}
	})

	t.Run("conditional policy request", func(t *testing.T) {
		r.t = t
		if assignment.PolicyID == "" || assignment.Version == 0 {
			t.Skip("no assignment returned by previous check")
		}
		cq := url.Values{}
		cq.Set(controlplane.QueryAgentID, cfg.AgentID)
		cq.Set(controlplane.QueryIfVersion, strconv.FormatInt(assignment.Version, 10))
		cq.Set(controlplane.QueryIfPolicyID, assignment.PolicyID)
		cq.Set(controlplane.QueryIfHash, assignment.WASMHash)
		resp := r.do(http.MethodGet, controlplane.RoutePolicy+"?"+cq.Encode(), nil)
		defer resp.Body.Close()
		if got := resp.Header.Get(controlplane.HeaderRevisionIdentity); got != "1" {
			t.Errorf("%s = %q, want 1", controlplane.HeaderRevisionIdentity, got)
		}
		if resp.StatusCode != http.StatusNotModified {
			t.Errorf("status %d, want 304 for full-identity conditional request", resp.StatusCode)
		}
	})

	t.Run("policy requires agent_id", func(t *testing.T) {
		r.t = t
		r.expectStatus(r.do(http.MethodGet, controlplane.RoutePolicy, nil), http.StatusBadRequest)
	})

	t.Run("policy rejects wrong method", func(t *testing.T) {
		r.t = t
		r.expectStatus(r.do(http.MethodPost, controlplane.RoutePolicy, nil), http.StatusMethodNotAllowed)
	})

	t.Run("wasm download", func(t *testing.T) {
		r.t = t
		if assignment.PolicyID == "" || assignment.Version == 0 {
			t.Skip("no assignment returned by previous check")
		}
		wq := url.Values{}
		wq.Set(controlplane.QueryPolicyID, assignment.PolicyID)
		wq.Set(controlplane.QueryVersion, strconv.FormatInt(assignment.Version, 10))
		resp := r.do(http.MethodGet, controlplane.RoutePolicyWASM+"?"+wq.Encode(), nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			t.Fatalf("status %d, want 200 (body: %s)", resp.StatusCode, body)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/wasm" {
			t.Errorf("Content-Type = %q, want application/wasm", ct)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, controlplane.MaxWASMDownloadSize+1))
		if err != nil {
			t.Fatalf("read wasm: %v", err)
		}
		if len(data) > controlplane.MaxWASMDownloadSize {
			t.Fatalf("wasm larger than %d bytes", controlplane.MaxWASMDownloadSize)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != assignment.WASMHash {
			t.Errorf("downloaded wasm digest %s != assignment hash %s", got, assignment.WASMHash)
		}
		if enc := resp.Header.Get(controlplane.HeaderPolicySignature); enc != "" {
			if _, err := base64.StdEncoding.DecodeString(enc); err != nil {
				t.Errorf("invalid %s: %v", controlplane.HeaderPolicySignature, err)
			}
		}
	})

	t.Run("wasm requires policy_id", func(t *testing.T) {
		r.t = t
		r.expectStatus(r.do(http.MethodGet, controlplane.RoutePolicyWASM, nil), http.StatusBadRequest)
	})

	t.Run("wasm rejects wrong method", func(t *testing.T) {
		r.t = t
		r.expectStatus(r.do(http.MethodPost, controlplane.RoutePolicyWASM, nil), http.StatusMethodNotAllowed)
	})

	t.Run("unknown agent", func(t *testing.T) {
		r.t = t
		uq := url.Values{}
		uq.Set(controlplane.QueryAgentID, fmt.Sprintf("%s-unknown", cfg.AgentID))
		r.expectStatus(r.do(http.MethodGet, controlplane.RoutePolicy+"?"+uq.Encode(), nil), http.StatusNotFound)
	})
}
