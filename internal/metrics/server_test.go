package metrics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
