package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/crypto"
)

// mtlsFixture writes a CA, server and client keypair to a temp dir and starts
// an httptest server that requires a client certificate signed by the CA.
type mtlsFixture struct {
	srv                       *httptest.Server
	caFile, certFile, keyFile string
	auth                      chan string
}

func newMTLSFixture(t *testing.T) *mtlsFixture {
	t.Helper()
	dir := t.TempDir()
	ca, err := crypto.GenerateCA(crypto.CertConfig{CommonName: "test-ca"})
	if err != nil {
		t.Fatal(err)
	}
	srvCert, srvKey, err := ca.IssueCert(crypto.CertConfig{CommonName: "localhost", IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	cliCert, cliKey, err := ca.IssueCert(crypto.CertConfig{CommonName: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	f := &mtlsFixture{
		caFile:   filepath.Join(dir, "ca.crt"),
		certFile: filepath.Join(dir, "client.crt"),
		keyFile:  filepath.Join(dir, "client.key"),
		auth:     make(chan string, 10),
	}
	for path, data := range map[string][]byte{f.caFile: ca.CertPEM, f.certFile: cliCert, f.keyFile: cliKey} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	serverTLS, err := crypto.NewServerTLSConfig(srvCert, srvKey, ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.auth <- r.Header.Get("Authorization")
		_, _ = w.Write([]byte("[]"))
	}))
	f.srv.TLS = serverTLS
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func useTLSConfig(t *testing.T, ca, cert, key string) {
	t.Helper()
	cfg, err := loadTLSConfig(ca, cert, key)
	if err != nil {
		t.Fatalf("loadTLSConfig: %v", err)
	}
	old := apiTLSConfig
	apiTLSConfig = cfg
	t.Cleanup(func() { apiTLSConfig = old })
}

func TestAPIClient_MTLSWithAdminToken(t *testing.T) {
	f := newMTLSFixture(t)
	useTLSConfig(t, f.caFile, f.certFile, f.keyFile)

	var agents []agentInfo
	if err := newAPIClient(f.srv.URL, "admin-jwt").get("/api/v1/admin/agents", &agents); err != nil {
		t.Fatalf("get over mTLS: %v", err)
	}
	if got := <-f.auth; got != "Bearer admin-jwt" {
		t.Errorf("Authorization = %q", got)
	}
}

func TestAPIClient_TLSFailures(t *testing.T) {
	f := newMTLSFixture(t)

	// Without --ca-cert the server's private CA is not trusted.
	if err := newAPIClient(f.srv.URL, "").get("/", &[]agentInfo{}); err == nil {
		t.Error("expected certificate verification failure without --ca-cert")
	}

	// Trusting the CA is not enough when the server requires a client cert.
	useTLSConfig(t, f.caFile, "", "")
	if err := newAPIClient(f.srv.URL, "").get("/", &[]agentInfo{}); err == nil {
		t.Error("expected handshake failure without a client certificate")
	}
}

func TestLoadTLSConfig(t *testing.T) {
	f := newMTLSFixture(t)
	notPEM := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(notPEM, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}

	if cfg, err := loadTLSConfig("", "", ""); cfg != nil || err != nil {
		t.Errorf("no flags = %v, %v; want nil, nil", cfg, err)
	}
	cfg, err := loadTLSConfig(f.caFile, f.certFile, f.keyFile)
	if err != nil || cfg.RootCAs == nil || len(cfg.Certificates) != 1 {
		t.Fatalf("full config = %+v, %v", cfg, err)
	}
	// A client cert without --ca-cert falls back to the system roots.
	if cfg, err := loadTLSConfig("", f.certFile, f.keyFile); err != nil || cfg.RootCAs != nil {
		t.Errorf("cert-only config = %+v, %v", cfg, err)
	}

	tests := []struct {
		name            string
		ca, cert, key   string
		wantErrContains string
	}{
		{"cert without key", "", f.certFile, "", "must be set together"},
		{"key without cert", "", "", f.keyFile, "must be set together"},
		{"missing ca", filepath.Join(t.TempDir(), "nope"), "", "", "read ca cert"},
		{"ca not pem", notPEM, "", "", "no certificates found"},
		{"bad keypair", "", notPEM, notPEM, "load client keypair"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadTLSConfig(tt.ca, tt.cert, tt.key)
			if err == nil || !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf("err = %v, want %q", err, tt.wantErrContains)
			}
		})
	}
}
