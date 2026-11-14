package dashboard

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServerBindValidation(t *testing.T) {
	for _, tc := range []struct {
		bind string
		want string
	}{
		{DefaultBind, "127.0.0.1:8080"},
		{"localhost", "127.0.0.1:8080"},
		{"::1", "[::1]:8080"},
		// Validate explicit remote binds without opening a public listener.
		{"0.0.0.0", "0.0.0.0:8080"},
		{"::", "[::]:8080"},
		{"192.0.2.10", "192.0.2.10:8080"},
	} {
		t.Run(tc.bind, func(t *testing.T) {
			srv, err := NewServer(ServerConfig{Bind: tc.bind, Port: 8080}, New(1))
			if err != nil {
				t.Fatal(err)
			}
			if srv.Addr != tc.want {
				t.Errorf("Addr = %q, want %q", srv.Addr, tc.want)
			}
			if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.IdleTimeout <= 0 || srv.MaxHeaderBytes <= 0 {
				t.Error("request timeouts and header size must be bounded")
			}
			if srv.WriteTimeout != 0 {
				t.Error("WriteTimeout must be zero for long-lived SSE streams")
			}
		})
	}
	for _, bind := range []string{"", ":8080", "127.0.0.1:8080", "[::1]", "*", "example.com", "127.0.0.1\n"} {
		if _, err := NewServer(ServerConfig{Bind: bind, Port: 8080}, New(1)); err == nil {
			t.Errorf("accepted invalid bind %q", bind)
		}
	}
	for _, port := range []int{-1, 0, 65536} {
		if _, err := NewServer(ServerConfig{Bind: DefaultBind, Port: port}, New(1)); err == nil {
			t.Errorf("accepted invalid port %d", port)
		}
	}
}

func clearTokenEnv(t *testing.T) {
	t.Helper()
	// Setenv registers restoration even when the caller originally had a token.
	t.Setenv(TokenEnv, "")
	if err := os.Unsetenv(TokenEnv); err != nil {
		t.Fatal(err)
	}
}

func TestLoadToken(t *testing.T) {
	clearTokenEnv(t)
	if token, err := LoadToken(""); err != nil || token != "" {
		t.Fatalf("unconfigured auth = %q, %v", token, err)
	}
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("test-secret\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if token, err := LoadToken(path); err != nil || token != "test-secret" {
		t.Fatalf("file token = %q, %v", token, err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxTokenLen)+"\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if token, err := LoadToken(path); err != nil || len(token) != maxTokenLen {
		t.Fatalf("maximum-length file token: len = %d, err = %v", len(token), err)
	}
	t.Setenv(TokenEnv, "environment-secret")
	if token, err := LoadToken(""); err != nil || token != "environment-secret" {
		t.Fatalf("environment token = %q, %v", token, err)
	}
	if _, err := LoadToken(path); err == nil {
		t.Error("accepted conflicting token sources")
	}
}

func TestLoadTokenRejectsInvalidSecrets(t *testing.T) {
	for _, token := range []string{"", "\n", " leading", "embedded\nnewline", "trailing\r", "tab\t", "control\x00", strings.Repeat("x", maxTokenLen+1)} {
		t.Run(fmt.Sprintf("length-%d", len(token)), func(t *testing.T) {
			clearTokenEnv(t)
			if !strings.ContainsRune(token, '\x00') {
				t.Setenv(TokenEnv, token)
				if _, err := LoadToken(""); err == nil {
					t.Error("accepted invalid environment secret")
				}
				if err := os.Unsetenv(TokenEnv); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(path, []byte(token), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadToken(path); err == nil {
				t.Error("accepted invalid token file")
			}
		})
	}
	clearTokenEnv(t)
	if _, err := LoadToken(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("accepted missing token file")
	}
	if _, err := NewServer(ServerConfig{Bind: DefaultBind, Port: 8080, Token: "invalid secret"}, New(1)); err == nil {
		t.Error("accepted invalid directly configured token")
	}
}

func startTestServer(t *testing.T, srv *http.Server) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(srv.Handler)
	ts.Config = srv
	ts.Start() // httptest only listens on an ephemeral loopback port.
	ts.Client().Timeout = 3 * time.Second
	t.Cleanup(func() {
		ts.CloseClientConnections()
		ts.Close()
	})
	return ts
}

func TestServerAuthenticationAndHeaders(t *testing.T) {
	h := New(10)
	h.Publish(Event{PID: 42, Reason: "private-history"})
	srv, err := NewServer(ServerConfig{Bind: DefaultBind, Port: 8080, Token: "test-secret"}, h)
	if err != nil {
		t.Fatal(err)
	}
	ts := startTestServer(t, srv)
	for _, path := range []string{"/dashboard", "/dashboard/events"} {
		for _, auth := range []string{"missing", "wrong-token", "wrong-user", "query-token", "bearer-token"} {
			t.Run(path+"/"+auth, func(t *testing.T) {
				url := ts.URL + path
				if auth == "query-token" {
					url += "?token=test-secret"
				}
				req, err := http.NewRequest(http.MethodGet, url, nil)
				if err != nil {
					t.Fatal(err)
				}
				switch auth {
				case "wrong-token":
					req.SetBasicAuth("warmor", "incorrect")
				case "wrong-user":
					req.SetBasicAuth("other", "test-secret")
				case "bearer-token":
					req.Header.Set("Authorization", "Bearer test-secret")
				}
				resp, err := ts.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("status = %d, want 401", resp.StatusCode)
				}
				if !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic ") {
					t.Error("missing browser Basic authentication challenge")
				}
				checkSecurityHeaders(t, resp.Header)
				if strings.Contains(string(body), "private-history") || strings.Contains(string(body), "test-secret") {
					t.Error("unauthorized response disclosed events or credentials")
				}
			})
		}
	}
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/dashboard", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("warmor", "test-secret")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated index status = %d", resp.StatusCode)
	}
	checkSecurityHeaders(t, resp.Header)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "new EventSource('/dashboard/events')") || strings.Contains(string(body), "innerHTML") {
		t.Error("UI must use same-origin EventSource without URL secrets and render event values as text")
	}
	if len(h.clients) != 0 {
		t.Error("unauthorized SSE requests registered clients")
	}
}

func checkSecurityHeaders(t *testing.T, header http.Header) {
	t.Helper()
	for name, want := range map[string]string{
		"Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
		"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
	} {
		if got := header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("dashboard must not enable cross-origin reads")
	}
}

func TestAuthenticatedSSESurvivesRequestTimeouts(t *testing.T) {
	h := New(10)
	srv, err := NewServer(ServerConfig{Bind: DefaultBind, Port: 8080, Token: "test-secret"}, h)
	if err != nil {
		t.Fatal(err)
	}
	srv.ReadHeaderTimeout = 25 * time.Millisecond
	srv.ReadTimeout = 50 * time.Millisecond
	srv.IdleTimeout = 50 * time.Millisecond
	ts := startTestServer(t, srv)
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/dashboard/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("warmor", "test-secret")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("SSE response: %s, %v", resp.Status, resp.Header)
	}
	checkSecurityHeaders(t, resp.Header)
	if resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Error("missing reverse proxy buffering opt-out")
	}
	// Read/header/idle timeouts must not impose a lifetime on an active SSE response.
	time.Sleep(150 * time.Millisecond)
	h.Publish(Event{PID: 4242, Action: "ALLOW"})
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "data: ") {
			if !strings.Contains(scanner.Text(), `"pid":4242`) {
				t.Fatalf("unexpected SSE event: %s", scanner.Text())
			}
			return
		}
	}
	t.Fatalf("stream ended before event after request timeouts: %v", scanner.Err())
}

func TestServerWithoutAuthentication(t *testing.T) {
	srv, err := NewServer(ServerConfig{Bind: DefaultBind, Port: 8080}, New(1))
	if err != nil {
		t.Fatal(err)
	}
	ts := startTestServer(t, srv)
	for _, path := range []string{"/dashboard", "/dashboard/events"} {
		resp, err := ts.Client().Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("optional auth disabled: %s status = %d", path, resp.StatusCode)
		}
		checkSecurityHeaders(t, resp.Header)
	}
}

func TestServerHeaderTimeout(t *testing.T) {
	srv, err := NewServer(ServerConfig{Bind: DefaultBind, Port: 8080}, New(1))
	if err != nil {
		t.Fatal(err)
	}
	srv.ReadHeaderTimeout = 50 * time.Millisecond
	ts := startTestServer(t, srv)
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "GET /dashboard HTTP/1.1\r\nHost: localhost\r\nX-Slow: "); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := conn.Read(b[:]); err != io.EOF {
		t.Fatalf("incomplete headers should close connection, got %v", err)
	}
}
