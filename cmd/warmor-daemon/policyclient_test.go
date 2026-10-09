package main

import (
	"context"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/policyserver"
)

func TestNewPolicyClientValidation(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.pem")
	garbage := writeFile(t, filepath.Join(dir, "garbage.pem"), "not pem")

	tests := []struct {
		name string
		cfg  policyClientConfig
		want string
	}{
		{"bad scheme", policyClientConfig{ServerURL: "ftp://x"}, "http:// or https://"},
		{"cert without key", policyClientConfig{ServerURL: "https://x", CertFile: garbage}, "must be given together"},
		{"key without cert", policyClientConfig{ServerURL: "https://x", KeyFile: garbage}, "must be given together"},
		{"tls over http", policyClientConfig{ServerURL: "http://x", CAFile: garbage}, "require an https://"},
		{"missing ca", policyClientConfig{ServerURL: "https://x", CAFile: missing}, "read tls ca"},
		{"garbage ca", policyClientConfig{ServerURL: "https://x", CAFile: garbage}, "no certificates found"},
		{"bad keypair", policyClientConfig{ServerURL: "https://x", CertFile: garbage, KeyFile: garbage}, "load client certificate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newPolicyClient(tc.cfg, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestWritePolicyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.wasm")
	writeFile(t, path, "old")
	if err := writePolicyFile(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "new" {
		t.Errorf("policy file = %q", data)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
	if err := writePolicyFile(filepath.Join(path, "nope", "p.wasm"), nil); err == nil {
		t.Error("expected error for unwritable path")
	}
}

type received struct {
	mu   sync.Mutex
	data []byte
	got  chan struct{}
}

func (r *received) onUpdate(_ *policyserver.PolicyAssignment, data []byte) {
	r.mu.Lock()
	r.data = data
	r.mu.Unlock()
	select {
	case r.got <- struct{}{}:
	default:
	}
}

// startPolicyServer runs a policy server with one policy matching env=prod.
func startPolicyServer(t *testing.T, cfg policyserver.ServerConfig, tlsCfg bool) (*policyserver.Server, *httptest.Server) {
	t.Helper()
	srv := policyserver.NewServer(cfg)
	w := writeFile(t, filepath.Join(t.TempDir(), "p.wasm"), "server-wasm")
	if err := srv.Store().CreatePolicy(&policyserver.Policy{ID: "p", Selector: map[string]string{"env": "prod"}}, w); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	var ts *httptest.Server
	if tlsCfg {
		ts = httptest.NewUnstartedServer(h)
		ts.TLS = cfg.TLSConfig
		ts.StartTLS()
	} else {
		ts = httptest.NewServer(h)
	}
	t.Cleanup(ts.Close)
	return srv, ts
}

func waitReceived(t *testing.T, r *received) string {
	t.Helper()
	select {
	case <-r.got:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for policy")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(r.data)
}

func TestPolicyClientWithToken(t *testing.T) {
	secret := []byte("daemon-test-secret")
	srv, ts := startPolicyServer(t, policyserver.ServerConfig{JWTSecret: secret}, false)
	tok, err := crypto.NewJWTIssuer(secret).Issue("agent-1", policyserver.RoleAgent, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Token comes from the environment when --server-token is unset.
	t.Setenv(serverTokenEnv, tok)
	r := &received{got: make(chan struct{}, 1)}
	c, err := newPolicyClient(policyClientConfig{ServerURL: ts.URL + "/", AgentID: "agent-1", Labels: map[string]string{"env": "prod"}}, r.onUpdate)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { runPolicyClient(ctx, c, 10*time.Millisecond); close(done) }()

	if got := waitReceived(t, r); got != "server-wasm" {
		t.Errorf("received %q", got)
	}
	if a, ok := srv.Store().GetAgent("agent-1"); !ok || a.Labels["env"] != "prod" {
		t.Errorf("agent not registered with labels: %+v", a)
	}
	cancel()
	<-done
}

func TestPolicyClientWithoutCredentialsIsRejected(t *testing.T) {
	_, ts := startPolicyServer(t, policyserver.ServerConfig{JWTSecret: []byte("s")}, false)
	t.Setenv(serverTokenEnv, "")
	c, err := newPolicyClient(policyClientConfig{ServerURL: ts.URL, AgentID: "a"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Register(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401, got %v", err)
	}
	// runPolicyClient keeps retrying and returns on cancel.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	runPolicyClient(ctx, c, 5*time.Millisecond)
}

func TestPolicyClientWithMTLS(t *testing.T) {
	dir := t.TempDir()
	ca, err := crypto.GenerateCA(crypto.CertConfig{CommonName: "ca", ValidFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sc, sk, err := ca.IssueCert(crypto.CertConfig{CommonName: "server", IPs: []net.IP{net.ParseIP("127.0.0.1")}, ValidFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	cc, ck, err := ca.IssueCert(crypto.CertConfig{CommonName: "agent", ValidFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := crypto.NewServerTLSConfig(sc, sk, ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	_, ts := startPolicyServer(t, policyserver.ServerConfig{TLSConfig: serverTLS}, true)

	caFile := writeFile(t, filepath.Join(dir, "ca.crt"), string(ca.CertPEM))
	certFile := writeFile(t, filepath.Join(dir, "agent.crt"), string(cc))
	keyFile := writeFile(t, filepath.Join(dir, "agent.key"), string(ck))

	t.Setenv(serverTokenEnv, "")
	r := &received{got: make(chan struct{}, 1)}
	c, err := newPolicyClient(policyClientConfig{
		ServerURL: ts.URL, CAFile: caFile, CertFile: certFile, KeyFile: keyFile,
		AgentID: "agent-1", Labels: map[string]string{"env": "prod"},
	}, r.onUpdate)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runPolicyClient(ctx, c, 10*time.Millisecond)
	if got := waitReceived(t, r); got != "server-wasm" {
		t.Errorf("received %q", got)
	}

	// Without the client certificate the handshake fails.
	noCert, err := newPolicyClient(policyClientConfig{ServerURL: ts.URL, CAFile: caFile, AgentID: "x"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := noCert.Register(context.Background()); err == nil {
		t.Error("expected registration without a client certificate to fail")
	}
}
