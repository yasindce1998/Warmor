package policyserver

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/crypto"
)

var testJWTSecret = []byte("test-secret-for-policyserver")

func setupAuthServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	srv := NewServer(ServerConfig{Addr: ":0", JWTSecret: testJWTSecret})
	ts := httptest.NewServer(srv.httpServer.Handler)
	t.Cleanup(ts.Close)
	return srv, ts
}

func issueToken(t *testing.T, secret []byte, role string, ttl time.Duration) string {
	t.Helper()
	tok, err := newJWTIssuerFromSecret(secret).Issue("tester", role, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func doAuthRequest(t *testing.T, method, url, authHeader string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

var adminRoutes = []struct {
	method string
	path   string
}{
	{http.MethodGet, "/api/v1/admin/policies"},
	{http.MethodPost, "/api/v1/admin/policies"},
	{http.MethodGet, "/api/v1/admin/policies/some-id"},
	{http.MethodPut, "/api/v1/admin/policies/some-id"},
	{http.MethodDelete, "/api/v1/admin/policies/some-id"},
	{http.MethodGet, "/api/v1/admin/agents"},
	{http.MethodGet, "/api/v1/admin/rollouts"},
	{http.MethodPost, "/api/v1/admin/rollouts"},
	{http.MethodGet, "/api/v1/admin/rollouts/some-id"},
	{http.MethodPut, "/api/v1/admin/rollouts/some-id"},
	{http.MethodDelete, "/api/v1/admin/rollouts/some-id"},
}

func TestJWTIssuerWrapperRoundtrip(t *testing.T) {
	iss := newJWTIssuerFromSecret(testJWTSecret)
	tok, err := iss.Issue("alice", "admin", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := iss.Validate(tok)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "alice" || claims.Role != "admin" {
		t.Errorf("unexpected claims: %+v", claims)
	}
	if _, err := newJWTIssuerFromSecret([]byte("other")).Validate(tok); err == nil {
		t.Error("expected validation failure with a different secret")
	}
}

func TestAdminRejectsUnauthenticated(t *testing.T) {
	_, ts := setupAuthServer(t)

	wrongSecret := issueToken(t, []byte("attacker-secret"), "admin", time.Hour)
	expired := issueToken(t, testJWTSecret, "admin", -time.Hour)
	valid := issueToken(t, testJWTSecret, "admin", time.Hour)
	// Tamper with the payload of a valid token while keeping its signature.
	parts := strings.Split(valid, ".")
	tampered := parts[0] + "." + parts[1] + "x." + parts[2]

	cases := []struct {
		name   string
		header string
	}{
		{"no header", ""},
		{"basic scheme", "Basic YWRtaW46YWRtaW4="},
		{"lowercase bearer", "bearer " + valid},
		{"empty bearer", "Bearer "},
		{"garbage token", "Bearer not-a-jwt"},
		{"two-part token", "Bearer a.b"},
		{"bad signature encoding", "Bearer " + parts[0] + "." + parts[1] + ".!!!"},
		{"tampered payload", "Bearer " + tampered},
		{"wrong secret", "Bearer " + wrongSecret},
		{"expired", "Bearer " + expired},
	}

	for _, route := range adminRoutes {
		for _, tc := range cases {
			t.Run(route.method+" "+route.path+"/"+tc.name, func(t *testing.T) {
				resp := doAuthRequest(t, route.method, ts.URL+route.path, tc.header)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("expected 401, got %d", resp.StatusCode)
				}
			})
		}
	}
}

func TestAdminRejectsNonAdminRole(t *testing.T) {
	_, ts := setupAuthServer(t)
	for _, role := range []string{"agent", "viewer", "", "Admin", "admin "} {
		tok := issueToken(t, testJWTSecret, role, time.Hour)
		for _, route := range adminRoutes {
			resp := doAuthRequest(t, route.method, ts.URL+route.path, "Bearer "+tok)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("role %q %s %s: expected 403, got %d", role, route.method, route.path, resp.StatusCode)
			}
		}
	}
}

func TestAdminAcceptsAdminToken(t *testing.T) {
	_, ts := setupAuthServer(t)
	tok := issueToken(t, testJWTSecret, "admin", time.Hour)

	for _, path := range []string{"/api/v1/admin/policies", "/api/v1/admin/agents", "/api/v1/admin/rollouts"} {
		resp := doAuthRequest(t, http.MethodGet, ts.URL+path, "Bearer "+tok)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s with admin token: expected 200, got %d", path, resp.StatusCode)
		}
	}
	// Authenticated request reaches the handler (404 from handler, not 401/403).
	resp := doAuthRequest(t, http.MethodGet, ts.URL+"/api/v1/admin/policies/missing", "Bearer "+tok)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected handler 404 for missing policy, got %d", resp.StatusCode)
	}
}

func TestAdminOpenWithoutJWTSecret(t *testing.T) {
	// Documented behavior: with no JWT secret, admin endpoints are not protected.
	_, ts := setupTestServer(t)
	defer ts.Close()
	resp := doAuthRequest(t, http.MethodGet, ts.URL+"/api/v1/admin/agents", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 without secret configured, got %d", resp.StatusCode)
	}
}

// --- mTLS ---

type testPKI struct {
	caPEM                 []byte
	serverCert, serverKey []byte
	clientCert, clientKey []byte
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	ca, err := crypto.GenerateCA(crypto.CertConfig{CommonName: "warmor-test-ca", ValidFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sc, sk, err := ca.IssueCert(crypto.CertConfig{
		CommonName: "policy-server",
		DNSNames:   []string{"localhost"},
		IPs:        []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		ValidFor:   time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	cc, ck, err := ca.IssueCert(crypto.CertConfig{CommonName: "agent-1", ValidFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return testPKI{caPEM: ca.CertPEM, serverCert: sc, serverKey: sk, clientCert: cc, clientKey: ck}
}

func startMTLSServer(t *testing.T, pki testPKI) (*Server, *httptest.Server) {
	t.Helper()
	serverTLS, err := crypto.NewServerTLSConfig(pki.serverCert, pki.serverKey, pki.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(ServerConfig{Addr: ":0", TLSConfig: serverTLS})
	ts := httptest.NewUnstartedServer(srv.httpServer.Handler)
	ts.TLS = srv.tlsConfig
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return srv, ts
}

func TestMTLSClientWithValidCert(t *testing.T) {
	pki := newTestPKI(t)
	srv, ts := startMTLSServer(t, pki)

	clientTLS, err := crypto.NewClientTLSConfig(pki.clientCert, pki.clientKey, pki.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: "agent-1", Hostname: "n1", TLSConfig: clientTLS})
	if err := c.Register(context.Background()); err != nil {
		t.Fatalf("register over mTLS: %v", err)
	}
	if _, ok := srv.Store().GetAgent("agent-1"); !ok {
		t.Error("agent not registered after mTLS register")
	}
}

func TestMTLSRejectsClientWithoutCert(t *testing.T) {
	pki := newTestPKI(t)
	_, ts := startMTLSServer(t, pki)

	// Trusts the server CA but presents no client certificate.
	clientTLS, err := crypto.NewClientTLSConfig(pki.clientCert, pki.clientKey, pki.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	noCert := &tls.Config{RootCAs: clientTLS.RootCAs, MinVersion: tls.VersionTLS13}

	c := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: "anon", TLSConfig: noCert})
	if err := c.Register(context.Background()); err == nil {
		t.Fatal("expected register to fail without a client certificate")
	}
}

func TestMTLSRejectsCertFromUntrustedCA(t *testing.T) {
	pki := newTestPKI(t)
	_, ts := startMTLSServer(t, pki)

	rogue := newTestPKI(t)
	// Rogue client cert, but trusts the real server CA so only client auth can fail.
	clientTLS, err := crypto.NewClientTLSConfig(rogue.clientCert, rogue.clientKey, pki.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: "rogue", TLSConfig: clientTLS})
	if err := c.Register(context.Background()); err == nil {
		t.Fatal("expected register to fail with a certificate from an untrusted CA")
	}
}

func TestMTLSClientRejectsUntrustedServer(t *testing.T) {
	pki := newTestPKI(t)
	_, ts := startMTLSServer(t, pki)

	other := newTestPKI(t)
	// Valid client cert for the server, but the client trusts a different CA.
	clientTLS, err := crypto.NewClientTLSConfig(pki.clientCert, pki.clientKey, other.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: "agent-1", TLSConfig: clientTLS})
	if err := c.Register(context.Background()); err == nil {
		t.Fatal("expected client to reject a server certificate from an unknown CA")
	}
}

func TestMTLSRejectsPlaintext(t *testing.T) {
	pki := newTestPKI(t)
	_, ts := startMTLSServer(t, pki)

	plainURL := "http://" + strings.TrimPrefix(ts.URL, "https://")
	c := NewClient(ClientConfig{ServerURL: plainURL, AgentID: "plain"})
	if err := c.Register(context.Background()); err == nil {
		t.Fatal("expected plaintext HTTP to an mTLS server to fail")
	}
}

func newServerTLS(pki testPKI) (*tls.Config, error) {
	return crypto.NewServerTLSConfig(pki.serverCert, pki.serverKey, pki.caPEM)
}
