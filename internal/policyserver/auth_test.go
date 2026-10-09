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

type route struct {
	method string
	path   string
}

var adminRoutes = []route{
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

var agentRoutes = []route{
	{http.MethodPost, "/api/v1/register"},
	{http.MethodPost, "/api/v1/heartbeat"},
	{http.MethodGet, "/api/v1/policy?agent_id=a"},
	{http.MethodGet, "/api/v1/policy/wasm?policy_id=p"},
}

var containerRoutes = []route{
	{http.MethodPost, "/api/v1/containers/bind"},
	{http.MethodDelete, "/api/v1/containers/c1"},
}

// Without a JWT secret, mTLS or insecure mode every route must be closed.
func TestNoAuthConfiguredRejectsEverything(t *testing.T) {
	srv := NewServer(ServerConfig{Addr: ":0"})
	ts := httptest.NewServer(srv.httpServer.Handler)
	defer ts.Close()

	tok := issueToken(t, testJWTSecret, "admin", time.Hour)
	all := append(append(append([]route{}, agentRoutes...), containerRoutes...), adminRoutes...)
	for _, route := range all {
		for _, header := range []string{"", "Bearer " + tok} {
			resp := doAuthRequest(t, route.method, ts.URL+route.path, header)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s (header %q): expected 401, got %d", route.method, route.path, header, resp.StatusCode)
			}
		}
	}
}

func TestStartRefusesWithoutAuth(t *testing.T) {
	pki := newTestPKI(t)
	cert, err := tls.X509KeyPair(pki.serverCert, pki.serverKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]ServerConfig{
		"plaintext":           {Addr: "127.0.0.1:0"},
		"tls without clients": {Addr: "127.0.0.1:0", TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}},
	} {
		t.Run(name, func(t *testing.T) {
			err := NewServer(cfg).Start()
			if err == nil || !strings.Contains(err.Error(), "no authentication configured") {
				t.Fatalf("expected refusal to start, got %v", err)
			}
		})
	}
}

func TestInsecureModeAllowsUnauthenticated(t *testing.T) {
	srv := NewServer(ServerConfig{Addr: ":0", Insecure: true})
	ts := httptest.NewServer(srv.httpServer.Handler)
	defer ts.Close()
	srv.Store().RegisterAgent(&RegisterRequest{ID: "a"})

	for _, path := range []string{"/api/v1/admin/agents", "/api/v1/policy?agent_id=a"} {
		resp := doAuthRequest(t, http.MethodGet, ts.URL+path, "")
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			t.Errorf("GET %s in insecure mode: got %d", path, resp.StatusCode)
		}
	}
}

// Insecure mode does not switch off a configured JWT secret.
func TestInsecureModeStillEnforcesConfiguredJWT(t *testing.T) {
	srv := NewServer(ServerConfig{Addr: ":0", Insecure: true, JWTSecret: testJWTSecret})
	ts := httptest.NewServer(srv.httpServer.Handler)
	defer ts.Close()
	for _, path := range []string{"/api/v1/admin/agents", "/api/v1/policy?agent_id=a"} {
		if resp := doAuthRequest(t, http.MethodGet, ts.URL+path, ""); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s: expected 401, got %d", path, resp.StatusCode)
		}
	}
}

func TestAgentAndContainerRoutesRejectUnauthenticated(t *testing.T) {
	_, ts := setupAuthServer(t)

	valid := issueToken(t, testJWTSecret, "agent", time.Hour)
	parts := strings.Split(valid, ".")
	cases := map[string]string{
		"no header":      "",
		"basic scheme":   "Basic YWdlbnQ6YWdlbnQ=",
		"empty bearer":   "Bearer ",
		"garbage token":  "Bearer not-a-jwt",
		"tampered":       "Bearer " + parts[0] + "." + parts[1] + "x." + parts[2],
		"wrong secret":   "Bearer " + issueToken(t, []byte("attacker-secret"), "agent", time.Hour),
		"expired":        "Bearer " + issueToken(t, testJWTSecret, "agent", -time.Hour),
		"lowercase auth": "bearer " + valid,
	}
	for _, route := range append(append([]route{}, agentRoutes...), containerRoutes...) {
		for name, header := range cases {
			resp := doAuthRequest(t, route.method, ts.URL+route.path, header)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s/%s: expected 401, got %d", route.method, route.path, name, resp.StatusCode)
			}
		}
	}
}

func TestAgentAndContainerRouteRoles(t *testing.T) {
	_, ts := setupAuthServer(t)
	authorized := func(code int) bool { return code != http.StatusUnauthorized && code != http.StatusForbidden }

	for _, tc := range []struct {
		role                      string
		agentOK, containerOK, adm bool
	}{
		{"agent", true, false, false},
		{"runtime", false, true, false},
		{"admin", true, true, true},
		{"viewer", false, false, false},
	} {
		tok := "Bearer " + issueToken(t, testJWTSecret, tc.role, time.Hour)
		check := func(routes []route, wantOK bool) {
			for _, r := range routes {
				code := doAuthRequest(t, r.method, ts.URL+r.path, tok).StatusCode
				if wantOK && !authorized(code) {
					t.Errorf("role %s %s %s: expected access, got %d", tc.role, r.method, r.path, code)
				}
				if !wantOK && code != http.StatusForbidden {
					t.Errorf("role %s %s %s: expected 403, got %d", tc.role, r.method, r.path, code)
				}
			}
		}
		check(agentRoutes, tc.agentOK)
		check(containerRoutes, tc.containerOK)
		check(adminRoutes, tc.adm)
	}
}

// The policy client authenticates with an agent token.
func TestClientSendsAgentToken(t *testing.T) {
	srv, ts := setupAuthServer(t)
	srv.policyDir = t.TempDir()
	w := writeWASM(t, srv.policyDir, "p.wasm", "wasm-v1")
	if err := srv.Store().CreatePolicy(&Policy{ID: "p"}, w); err != nil {
		t.Fatal(err)
	}

	rec := newUpdateRecorder()
	ctx := context.Background()
	c := NewClient(ClientConfig{
		ServerURL: ts.URL, AgentID: "a1", Token: issueToken(t, testJWTSecret, "agent", time.Hour), OnUpdate: rec.onUpdate,
	})
	if err := c.Register(ctx); err != nil {
		t.Fatalf("register with agent token: %v", err)
	}
	c.poll(ctx)
	if rec.count() != 1 || string(rec.wasm[0]) != "wasm-v1" {
		t.Fatalf("expected policy delivered with agent token, got %d updates", rec.count())
	}
	if err := c.SendHeartbeat(ctx); err != nil {
		t.Fatalf("heartbeat with agent token: %v", err)
	}

	anon := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: "a2"})
	if err := anon.Register(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("expected 401 without token, got %v", err)
	}
	if err := anon.SendHeartbeat(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("expected heartbeat 401 without token, got %v", err)
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

// A verified client certificate authenticates agent and runtime routes, but
// never the admin API.
func TestMTLSCertAuthenticatesAgentAndRuntimeRoutes(t *testing.T) {
	pki := newTestPKI(t)
	_, ts := startMTLSServer(t, pki)

	clientTLS, err := crypto.NewClientTLSConfig(pki.clientCert, pki.clientKey, pki.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}, Timeout: 5 * time.Second}
	do := func(method, path, body string) int {
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if code := do(http.MethodPost, "/api/v1/register", `{"id":"a1"}`); code != http.StatusOK {
		t.Errorf("register over mTLS: %d", code)
	}
	if code := do(http.MethodPost, "/api/v1/containers/bind", `{"container_id":"c","policy_id":"p"}`); code != http.StatusOK {
		t.Errorf("container bind over mTLS: %d", code)
	}
	if code := do(http.MethodDelete, "/api/v1/containers/c", ""); code != http.StatusNoContent {
		t.Errorf("container delete over mTLS: %d", code)
	}
	for _, r := range adminRoutes {
		if code := do(r.method, r.path, ""); code != http.StatusUnauthorized {
			t.Errorf("admin %s %s over mTLS without JWT: expected 401, got %d", r.method, r.path, code)
		}
	}
}

func newServerTLS(pki testPKI) (*tls.Config, error) {
	return crypto.NewServerTLSConfig(pki.serverCert, pki.serverKey, pki.caPEM)
}
