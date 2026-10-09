//go:build !windows

package main

import (
	"bytes"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/crypto"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// freeAddr reserves an ephemeral loopback port and releases it for the server.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// runServer runs main() in-process, calls probe once the server is listening,
// then sends SIGTERM to this process (which main's handler intercepts) and
// waits for main to return. It returns the captured log output.
func runServer(t *testing.T, probe func(addr string), extraArgs ...string) string {
	t.Helper()
	addr := freeAddr(t)
	logs := &syncBuffer{}

	oldArgs := os.Args
	os.Args = append([]string{"warmor-server", "-addr", addr}, extraArgs...)
	resetFlags()
	log.SetOutput(logs)
	defer func() {
		os.Args = oldArgs
		log.SetOutput(os.Stderr)
		resetFlags()
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		main()
	}()

	// "listening" is logged after main has installed its signal handler,
	// so SIGTERM below is guaranteed to be intercepted.
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(logs.String(), "policy server listening on "+addr) {
		if time.Now().After(deadline) {
			t.Fatalf("server did not start; logs:\n%s", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Wait for the socket to accept connections.
	for {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server not accepting on %s: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	if probe != nil {
		probe(addr)
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("main did not return after SIGTERM; logs:\n%s", logs.String())
	}
	return logs.String()
}

func TestServer_PlainHTTPWithJWT(t *testing.T) {
	logs := runServer(t, func(addr string) {
		resp, err := http.Get("http://" + addr + "/api/v1/admin/agents")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("admin API without token: status %d, want 401", resp.StatusCode)
		}
	}, "-jwt-secret", "s3cret")

	assertContains(t, "logs", logs, "JWT admin auth enabled", "shutting down policy server")
	if strings.Contains(logs, "mTLS enabled") {
		t.Errorf("mTLS should be off:\n%s", logs)
	}
}

func TestServer_NoJWTAdminAPIIsOpen(t *testing.T) {
	logs := runServer(t, func(addr string) {
		resp, err := http.Get("http://" + addr + "/api/v1/admin/agents")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		resp.Body.Close()
		// Without --jwt-secret the admin API is unauthenticated.
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status %d, want 200", resp.StatusCode)
		}
	})
	if strings.Contains(logs, "JWT admin auth enabled") {
		t.Errorf("JWT should be off:\n%s", logs)
	}
}

type pki struct {
	caCert, serverCert, serverKey, clientCert, clientKey string
	caPEM, clientCertPEM, clientKeyPEM                   []byte
}

func writePKI(t *testing.T) pki {
	t.Helper()
	dir := t.TempDir()
	ca, err := crypto.GenerateCA(crypto.CertConfig{CommonName: "test-ca"})
	if err != nil {
		t.Fatal(err)
	}
	sCert, sKey, err := ca.IssueCert(crypto.CertConfig{CommonName: "server", IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	cCert, cKey, err := ca.IssueCert(crypto.CertConfig{CommonName: "client"})
	if err != nil {
		t.Fatal(err)
	}
	p := pki{
		caCert:     filepath.Join(dir, "ca.crt"),
		serverCert: filepath.Join(dir, "server.crt"),
		serverKey:  filepath.Join(dir, "server.key"),
		caPEM:      ca.CertPEM, clientCertPEM: cCert, clientKeyPEM: cKey,
	}
	for path, data := range map[string][]byte{p.caCert: ca.CertPEM, p.serverCert: sCert, p.serverKey: sKey} {
		if err := crypto.WritePEM(path, data); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func TestServer_MTLS(t *testing.T) {
	p := writePKI(t)
	logs := runServer(t, func(addr string) {
		cfg, err := crypto.NewClientTLSConfig(p.clientCertPEM, p.clientKeyPEM, p.caPEM)
		if err != nil {
			t.Fatal(err)
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
		resp, err := client.Get("https://" + addr + "/api/v1/admin/agents")
		if err != nil {
			t.Fatalf("mTLS GET: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("mTLS status %d, want 200", resp.StatusCode)
		}

		// A client without a certificate must be rejected.
		noCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: cfg.RootCAs}}, Timeout: 5 * time.Second}
		if resp, err := noCert.Get("https://" + addr + "/api/v1/admin/agents"); err == nil {
			resp.Body.Close()
			t.Error("request without client cert should fail")
		}
	}, "-ca-cert", p.caCert, "-tls-cert", p.serverCert, "-tls-key", p.serverKey)

	assertContains(t, "logs", logs, "mTLS enabled", "(mTLS)")
}

// Supplying only some of the TLS flags silently falls back to plaintext HTTP
// (see report). This pins that behaviour.
func TestServer_PartialTLSFlagsFallBackToPlaintext(t *testing.T) {
	p := writePKI(t)
	logs := runServer(t, func(addr string) {
		resp, err := http.Get("http://" + addr + "/api/v1/admin/agents")
		if err != nil {
			t.Fatalf("plaintext GET: %v", err)
		}
		resp.Body.Close()
	}, "-tls-cert", p.serverCert, "-tls-key", p.serverKey)
	if strings.Contains(logs, "mTLS enabled") {
		t.Errorf("unexpected mTLS with missing --ca-cert:\n%s", logs)
	}
}

func TestServer_Failures(t *testing.T) {
	p := writePKI(t)
	missing := filepath.Join(t.TempDir(), "missing.pem")
	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing tls cert", []string{"-ca-cert", p.caCert, "-tls-cert", missing, "-tls-key", p.serverKey}, "read tls cert"},
		{"missing tls key", []string{"-ca-cert", p.caCert, "-tls-cert", p.serverCert, "-tls-key", missing}, "read tls key"},
		{"missing ca", []string{"-ca-cert", missing, "-tls-cert", p.serverCert, "-tls-key", p.serverKey}, "read ca cert"},
		{"bad keypair", []string{"-ca-cert", p.caCert, "-tls-cert", garbage, "-tls-key", p.serverKey}, "configure mTLS"},
		{"bad addr", []string{"-addr", "127.0.0.1:notaport"}, "policy server:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runChild(t, nil, tt.args...)
			if r.code != 1 {
				t.Errorf("exit = %d, want 1 (stderr: %s)", r.code, r.stderr)
			}
			assertContains(t, "stderr", r.stderr, tt.want)
		})
	}
}
