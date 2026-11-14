package metrics

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server serves Prometheus metrics
type Server struct {
	server   *http.Server
	listener net.Listener
	mu       sync.RWMutex
	ready    func() error
}

// NewServer creates a new metrics server
func NewServer(port int) *Server {
	return NewServerAddress(fmt.Sprintf(":%d", port))
}

// NewServerAddress permits an explicit metrics/probes bind address.
func NewServerAddress(address string) *Server {
	s := &Server{}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/ready", s.readyHandler)

	s.server = &http.Server{
		Addr:         address,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return s
}

// Start starts the metrics server and returns an error if port binding fails
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.server.Addr, err)
	}

	s.listener = listener

	go func() {
		if err := s.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("metrics: server error: %v", err)
		}
	}()

	return nil
}

// Addr returns the address the server is listening on, which is useful when
// it was created with port 0. It returns "" before a successful Start.
func (s *Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Stop gracefully stops the metrics server
func (s *Server) Stop(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// SetReadinessCheck installs a concurrency-safe local readiness source. A
// server without an initialized source is NOT ready. Liveness stays independent.
func (s *Server) SetReadinessCheck(check func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready = check
}
func (s *Server) readyHandler(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	check := s.ready
	s.mu.RUnlock()
	if check == nil {
		http.Error(w, "readiness is not initialized", http.StatusServiceUnavailable)
		return
	}
	if err := check(); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("READY"))
}
