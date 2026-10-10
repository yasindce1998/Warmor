package metrics

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func doGet(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, string(body)
}

func TestNewServer_Addr(t *testing.T) {
	s := NewServer(9123)
	if s.server.Addr != ":9123" {
		t.Errorf("Addr = %q, want %q", s.server.Addr, ":9123")
	}
	if s.server.ReadTimeout != 5*time.Second {
		t.Errorf("ReadTimeout = %v, want 5s", s.server.ReadTimeout)
	}
	if s.server.WriteTimeout != 10*time.Second {
		t.Errorf("WriteTimeout = %v, want 10s", s.server.WriteTimeout)
	}
	if s.server.IdleTimeout != 60*time.Second {
		t.Errorf("IdleTimeout = %v, want 60s", s.server.IdleTimeout)
	}
}

func TestServer_Routes(t *testing.T) {
	RecordEvent("allow")
	s := NewServer(0)

	tests := []struct {
		path     string
		wantCode int
		contains string
	}{
		{"/health", http.StatusOK, "OK"},
		{"/ready", http.StatusOK, "READY"},
		{"/metrics", http.StatusOK, "warmor_events_total"},
		{"/nope", http.StatusNotFound, ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			code, body := doGet(t, s.server.Handler, tt.path)
			if code != tt.wantCode {
				t.Errorf("status = %d, want %d", code, tt.wantCode)
			}
			if tt.contains != "" && !strings.Contains(body, tt.contains) {
				t.Errorf("body does not contain %q", tt.contains)
			}
		})
	}
}

func TestServer_StartStop(t *testing.T) {
	s := NewServer(0)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestServer_StartListenError(t *testing.T) {
	s := NewServer(-1)
	if err := s.Start(); err == nil {
		_ = s.Stop(context.Background())
		t.Fatal("expected error for invalid port, got nil")
	}
}

func TestServer_StopWithoutStart(t *testing.T) {
	s := NewServer(0)
	if err := s.Stop(context.Background()); err != nil {
		t.Errorf("Stop on unstarted server: %v", err)
	}
}

func TestHealthAndReadyHandlers(t *testing.T) {
	code, body := doGet(t, http.HandlerFunc(healthHandler), "/health")
	if code != http.StatusOK || body != "OK" {
		t.Errorf("healthHandler = %d %q, want 200 \"OK\"", code, body)
	}
	code, body = doGet(t, http.HandlerFunc(readyHandler), "/ready")
	if code != http.StatusOK || body != "READY" {
		t.Errorf("readyHandler = %d %q, want 200 \"READY\"", code, body)
	}
}

func TestServer_AddrAfterStart(t *testing.T) {
	s := NewServer(0)
	if s.Addr() != "" {
		t.Errorf("Addr before Start = %q, want empty", s.Addr())
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = s.Stop(context.Background()) }()

	addr := s.Addr()
	if addr == "" || strings.HasSuffix(addr, ":0") {
		t.Fatalf("Addr = %q, want resolved port", addr)
	}
	resp, err := http.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if body, _ := io.ReadAll(resp.Body); resp.StatusCode != http.StatusOK || string(body) != "OK" {
		t.Errorf("GET /health = %d %q", resp.StatusCode, body)
	}
}

// syncBuffer is a goroutine-safe log sink.
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

func TestServer_ServeErrorLogged(t *testing.T) {
	var out syncBuffer
	prev := log.Writer()
	log.SetOutput(&out)
	defer log.SetOutput(prev)

	s := NewServer(0)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Closing the listener behind the server's back makes Serve fail with
	// an error other than ErrServerClosed.
	_ = s.listener.Close()

	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(out.String(), "metrics: server error:") {
		if time.Now().After(deadline) {
			t.Fatalf("serve error not logged; log output: %q", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = s.Stop(context.Background())
}

func TestServer_StopDoesNotLog(t *testing.T) {
	var out syncBuffer
	prev := log.Writer()
	log.SetOutput(&out)
	defer log.SetOutput(prev)

	s := NewServer(0)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := s.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if out.String() != "" {
		t.Errorf("graceful stop logged: %q", out.String())
	}
}
