package policyserver

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/crypto"
)

// Server is the central policy management HTTP server.
type Server struct {
	store      *Store
	rollouts   *RolloutManager
	containers *containerStore
	httpServer *http.Server
	addr       string
	staleCheck time.Duration
	tlsConfig  *tls.Config
	jwtSecret  []byte
	jwt        *jwtIssuer
	insecure   bool
	policyDir  string

	// Background loop lifecycle; stopped by Shutdown.
	staleInterval time.Duration
	loopMu        sync.Mutex
	stopped       bool
	stop          chan struct{}
	loops         sync.WaitGroup
}

// ServerConfig configures the policy management server.
type ServerConfig struct {
	Addr           string
	StaleThreshold time.Duration
	// TLSConfig enables TLS. If it verifies client certificates (mTLS), a
	// verified certificate authenticates agent and container runtime calls.
	TLSConfig *tls.Config
	// JWTSecret enables bearer-token authentication. Admin endpoints are
	// only reachable with an admin token.
	JWTSecret []byte
	// Insecure allows serving without any authentication when neither
	// JWTSecret nor mTLS is configured. Development only.
	Insecure bool
	// PolicyDir is the only directory admin requests may load WASM from.
	// If empty, policies cannot be created or updated over the API.
	PolicyDir string
	// VerifyKey, if set, makes the server refuse policy uploads without a
	// detached signature that verifies against it. Signatures are always
	// served to agents when present; agents verify them independently.
	VerifyKey ed25519.PublicKey
}

// NewServer creates a policy management server.
func NewServer(cfg ServerConfig) *Server {
	if cfg.Addr == "" {
		cfg.Addr = ":8443"
	}
	if cfg.StaleThreshold <= 0 {
		cfg.StaleThreshold = 90 * time.Second
	}

	store := NewStore()
	if cfg.VerifyKey != nil {
		store.SetVerifyKey(cfg.VerifyKey)
	}
	s := &Server{
		store:      store,
		rollouts:   NewRolloutManager(store),
		addr:       cfg.Addr,
		staleCheck: cfg.StaleThreshold,
		containers: newContainerStore(),
		tlsConfig:  cfg.TLSConfig,
		jwtSecret:  cfg.JWTSecret,
		insecure:   cfg.Insecure,
		policyDir:  cfg.PolicyDir,

		staleInterval: 30 * time.Second,
		stop:          make(chan struct{}),
	}
	if len(cfg.JWTSecret) > 0 {
		s.jwt = newJWTIssuerFromSecret(cfg.JWTSecret)
	}

	mux := http.NewServeMux()

	// Agent-facing endpoints (mTLS client cert or agent token)
	mux.HandleFunc("/api/v1/register", s.requireAgent(s.handleRegister))
	mux.HandleFunc("/api/v1/heartbeat", s.requireAgent(s.handleHeartbeat))
	mux.HandleFunc("/api/v1/policy", s.requireAgent(s.handleGetPolicy))
	mux.HandleFunc("/api/v1/policy/wasm", s.requireAgent(s.handleGetWASM))

	// Container runtime endpoints (mTLS client cert or runtime token)
	mux.HandleFunc("/api/v1/containers/bind", s.requireRuntime(s.handleContainerBind))
	mux.HandleFunc("/api/v1/containers/", s.requireRuntime(s.handleContainerDelete))

	// Admin endpoints (admin token)
	mux.HandleFunc("/api/v1/admin/policies", s.requireJWT(s.handleAdminPolicies))
	mux.HandleFunc("/api/v1/admin/policies/", s.requireJWT(s.handleAdminPolicy))
	mux.HandleFunc("/api/v1/admin/agents", s.requireJWT(s.handleAdminAgents))
	mux.HandleFunc("/api/v1/admin/rollouts", s.requireJWT(s.handleAdminRollouts))
	mux.HandleFunc("/api/v1/admin/rollouts/", s.requireJWT(s.handleAdminRollout))

	s.httpServer = &http.Server{
		Addr:         cfg.Addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// Store returns the underlying store for direct manipulation in tests.
func (s *Server) Store() *Store {
	return s.store
}

// Handler returns the server's HTTP handler, including authentication.
func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}

// Rollouts returns the rollout manager.
func (s *Server) Rollouts() *RolloutManager {
	return s.rollouts
}

// Start begins listening and serving. Blocks until shutdown. It refuses to
// serve without authentication unless the server is in insecure mode.
func (s *Server) Start() error {
	if err := s.checkAuthConfig(); err != nil {
		return err
	}
	if len(s.jwtSecret) == 0 {
		if s.mtlsEnabled() {
			log.Printf("WARNING: no JWT secret configured; admin API is disabled")
		} else {
			log.Printf("WARNING: INSECURE MODE: policy server API is unauthenticated; do not use in production")
		}
	}

	s.loopMu.Lock()
	if s.stopped {
		s.loopMu.Unlock()
		return nil
	}
	s.loops.Add(1)
	s.loopMu.Unlock()
	go s.staleLoop()

	if s.tlsConfig != nil {
		s.httpServer.TLSConfig = s.tlsConfig
		mode := "TLS"
		if s.mtlsEnabled() {
			mode = "mTLS"
		}
		log.Printf("policy server listening on %s (%s)", s.addr, mode)
		if err := s.httpServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			return err
		}
	} else {
		log.Printf("policy server listening on %s", s.addr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return err
		}
	}
	return nil
}

// Shutdown gracefully stops the server and its background loops.
func (s *Server) Shutdown(ctx context.Context) error {
	s.loopMu.Lock()
	if !s.stopped {
		s.stopped = true
		close(s.stop)
	}
	s.loopMu.Unlock()

	err := s.httpServer.Shutdown(ctx)
	s.loops.Wait()
	return err
}

func (s *Server) staleLoop() {
	defer s.loops.Done()
	ticker := time.NewTicker(s.staleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.store.MarkStaleAgents(s.staleCheck)
		}
	}
}

// --- Agent endpoints ---

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.ID == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}

	agent := s.store.RegisterAgent(&req)
	writeJSON(w, http.StatusOK, agent)
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := s.store.Heartbeat(req.AgentID, req.PolicyVersion); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Return the agent's current policy assignment via rollout-aware resolution
	agent, _ := s.store.GetAgent(req.AgentID)
	assignment := s.rollouts.ResolvePolicy(req.AgentID, agent.Labels)
	if assignment == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "policy": "none"})
		return
	}
	writeJSON(w, http.StatusOK, assignment)
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		http.Error(w, "agent_id required", http.StatusBadRequest)
		return
	}

	agent, ok := s.store.GetAgent(agentID)
	if !ok {
		http.Error(w, "agent not registered", http.StatusNotFound)
		return
	}

	assignment := s.rollouts.ResolvePolicy(agentID, agent.Labels)
	if assignment == nil {
		http.Error(w, "no matching policy", http.StatusNotFound)
		return
	}

	// Version-based long-poll: if agent already has this version, return 304.
	// Any other version (including a newer one after a rollback) is re-sent.
	ifVersion := r.URL.Query().Get("if_version")
	if ifVersion != "" {
		var v int64
		_, _ = fmt.Sscanf(ifVersion, "%d", &v)
		if v == assignment.Version {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	writeJSON(w, http.StatusOK, assignment)
}

func (s *Server) handleGetWASM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	policyID := r.URL.Query().Get("policy_id")
	if policyID == "" {
		http.Error(w, "policy_id required", http.StatusBadRequest)
		return
	}

	// Without a version the active one is served; agents pass the version
	// from their assignment so rollout cohorts get the right binary.
	var version int64
	if vs := r.URL.Query().Get("version"); vs != "" {
		v, err := strconv.ParseInt(vs, 10, 64)
		if err != nil || v <= 0 {
			http.Error(w, "invalid version", http.StatusBadRequest)
			return
		}
		version = v
	}
	data, sig, ok := s.store.GetSignedWASM(policyID, version)
	if !ok {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}

	// The signature travels with the module it covers so an agent can never
	// pair bytes and signature from different versions.
	if sig != nil {
		w.Header().Set(SignatureHeader, base64.StdEncoding.EncodeToString(sig))
	}
	w.Header().Set("Content-Type", "application/wasm")
	_, _ = w.Write(data)
}

// --- Admin endpoints ---

func (s *Server) handleAdminPolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		policies := s.store.ListPolicies()
		writeJSON(w, http.StatusOK, policies)

	case http.MethodPost:
		var req struct {
			Policy
			// Signature is an optional detached signature (base64) for
			// the WASM; otherwise <wasm_path>.sig is used if present.
			Signature string `json:"signature"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		p := req.Policy
		if p.ID == "" || p.WASMPath == "" {
			http.Error(w, "id and wasm_path required", http.StatusBadRequest)
			return
		}
		path, err := s.resolveWASMPath(p.WASMPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sig, err := s.uploadSignature(path, req.Signature)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.store.CreateSignedPolicy(&p, path, sig); err != nil {
			http.Error(w, err.Error(), uploadErrorStatus(err, http.StatusConflict))
			return
		}
		writeJSON(w, http.StatusCreated, &p)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminPolicy(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/policies/")
	if id == "" {
		http.Error(w, "policy id required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		p, ok := s.store.GetPolicy(id)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, p)

	case http.MethodPut:
		var req struct {
			WASMPath string `json:"wasm_path"`
			// Stage uploads the version without activating it, for use as
			// a rollout target.
			Stage bool `json:"stage"`
			// Signature is an optional detached signature (base64); see
			// the POST handler.
			Signature string `json:"signature"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if _, ok := s.store.GetPolicy(id); !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		path, err := s.resolveWASMPath(req.WASMPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sig, err := s.uploadSignature(path, req.Signature)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.store.AddVersion(id, path, sig, !req.Stage); err != nil {
			http.Error(w, err.Error(), uploadErrorStatus(err, http.StatusNotFound))
			return
		}
		p, _ := s.store.GetPolicy(id)
		writeJSON(w, http.StatusOK, p)

	case http.MethodDelete:
		if err := s.store.DeletePolicy(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agents := s.store.ListAgents()
	writeJSON(w, http.StatusOK, agents)
}

func (s *Server) handleAdminRollouts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rollouts := s.rollouts.ListRollouts()
		writeJSON(w, http.StatusOK, rollouts)

	case http.MethodPost:
		var cfg RolloutConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if cfg.ID == "" || cfg.PolicyID == "" {
			http.Error(w, "id and policy_id required", http.StatusBadRequest)
			return
		}
		state, err := s.rollouts.CreateRollout(cfg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, http.StatusCreated, state)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminRollout(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/rollouts/")
	if id == "" {
		http.Error(w, "rollout id required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		state, ok := s.rollouts.GetRollout(id)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, state)

	case http.MethodPut:
		var req struct {
			Percentage int `json:"percentage"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := s.rollouts.UpdatePercentage(id, req.Percentage); err != nil {
			http.Error(w, err.Error(), rolloutErrorStatus(err))
			return
		}
		state, _ := s.rollouts.GetRollout(id)
		writeJSON(w, http.StatusOK, state)

	case http.MethodDelete:
		if err := s.rollouts.AbortRollout(id); err != nil {
			http.Error(w, err.Error(), rolloutErrorStatus(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// uploadSignature returns the detached signature for an uploaded policy:
// the request's base64 signature if given, else the contents of
// <wasm>.sig next to the resolved WASM file (confined to the policy
// directory like the WASM itself), else nil.
func (s *Server) uploadSignature(wasmPath, inline string) ([]byte, error) {
	if inline != "" {
		return crypto.DecodePolicySignature([]byte(inline))
	}
	sigPath, err := s.resolveWASMPath(crypto.PolicySignaturePath(wasmPath))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("signature: %w", err)
	}
	data, err := crypto.ReadFileLimited(sigPath, crypto.MaxPolicySignatureFileSize)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	return data, nil
}

// uploadErrorStatus maps a policy upload error to an HTTP status:
// signature problems are the client's fault (422), anything else gets
// fallback.
func uploadErrorStatus(err error, fallback int) int {
	if errors.Is(err, crypto.ErrPolicyUnsigned) || errors.Is(err, crypto.ErrPolicySignatureInvalid) {
		return http.StatusUnprocessableEntity
	}
	return fallback
}

func rolloutErrorStatus(err error) int {
	if errors.Is(err, ErrRolloutNotActive) {
		return http.StatusConflict
	}
	return http.StatusNotFound
}

// resolveWASMPath confines an admin-supplied wasm_path to the configured
// policy directory. Relative paths are taken relative to that directory;
// symlinks are resolved before the containment check.
func (s *Server) resolveWASMPath(p string) (string, error) {
	if s.policyDir == "" {
		return "", errors.New("server has no policy directory configured")
	}
	root, err := filepath.EvalSymlinks(s.policyDir)
	if err != nil {
		return "", fmt.Errorf("policy directory: %w", err)
	}
	if root, err = filepath.Abs(root); err != nil {
		return "", fmt.Errorf("policy directory: %w", err)
	}

	candidate := p
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("wasm_path: %w", err)
	}
	if resolved, err = filepath.Abs(resolved); err != nil {
		return "", fmt.Errorf("wasm_path: %w", err)
	}

	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("wasm_path %q is outside the policy directory", p)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("wasm_path: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("wasm_path %q is not a regular file", p)
	}
	return resolved, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
