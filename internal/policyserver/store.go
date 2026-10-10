package policyserver

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"
)

// Store manages policies and agent registrations in memory.
type Store struct {
	mu       sync.RWMutex
	policies map[string]*Policy
	agents   map[string]*Agent
	// versions keeps every uploaded WASM binary so that rollouts can serve
	// both their base and target versions: policyID -> version -> binary.
	versions map[string]map[int64]*policyVersion
}

// policyVersion is one immutable uploaded revision of a policy's WASM.
type policyVersion struct {
	data []byte
	hash string
	path string
}

func NewStore() *Store {
	return &Store{
		policies: make(map[string]*Policy),
		agents:   make(map[string]*Agent),
		versions: make(map[string]map[int64]*policyVersion),
	}
}

func readPolicyVersion(wasmPath string) (*policyVersion, error) {
	data, err := os.ReadFile(wasmPath)
	if err != nil {
		return nil, fmt.Errorf("read wasm: %w", err)
	}
	h := sha256.Sum256(data)
	return &policyVersion{data: data, hash: hex.EncodeToString(h[:]), path: wasmPath}, nil
}

func (s *Store) CreatePolicy(p *Policy, wasmPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.policies[p.ID]; exists {
		return fmt.Errorf("policy %s already exists", p.ID)
	}

	v, err := readPolicyVersion(wasmPath)
	if err != nil {
		return err
	}

	p.WASMHash = v.hash
	p.WASMPath = v.path
	p.Version = 1
	p.ActiveVersion = 1
	p.CreatedAt = time.Now()
	p.UpdatedAt = p.CreatedAt

	s.policies[p.ID] = p
	s.versions[p.ID] = map[int64]*policyVersion{1: v}
	return nil
}

// UpdatePolicy uploads a new version of a policy and makes it the active
// version served to agents outside of a rollout.
func (s *Store) UpdatePolicy(id string, wasmPath string) error {
	return s.addVersion(id, wasmPath, true)
}

// StagePolicy uploads a new version of a policy without activating it, so
// it can be introduced gradually through a rollout.
func (s *Store) StagePolicy(id string, wasmPath string) error {
	return s.addVersion(id, wasmPath, false)
}

func (s *Store) addVersion(id, wasmPath string, activate bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.policies[id]
	if !ok {
		return fmt.Errorf("policy %s not found", id)
	}

	v, err := readPolicyVersion(wasmPath)
	if err != nil {
		return err
	}

	p.WASMHash = v.hash
	p.WASMPath = v.path
	p.Version++
	p.UpdatedAt = time.Now()
	if activate {
		p.ActiveVersion = p.Version
	}

	s.versions[id][p.Version] = v
	return nil
}

// SetActiveVersion changes which stored version of a policy is served to
// agents that are not part of an active rollout.
func (s *Store) SetActiveVersion(id string, version int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.policies[id]
	if !ok {
		return fmt.Errorf("policy %s not found", id)
	}
	if _, ok := s.versions[id][version]; !ok {
		return fmt.Errorf("policy %s has no version %d", id, version)
	}
	p.ActiveVersion = version
	p.UpdatedAt = time.Now()
	return nil
}

// HasVersion reports whether the given version of a policy is stored.
func (s *Store) HasVersion(id string, version int64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.versions[id][version]
	return ok
}

// previousVersion returns the newest stored version of a policy older than
// version, or 0 if there is none.
func (s *Store) previousVersion(id string, version int64) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var prev int64
	for v := range s.versions[id] {
		if v < version && v > prev {
			prev = v
		}
	}
	return prev
}

// assignment builds the agent-facing assignment for a stored policy version.
func (s *Store) assignment(id string, version int64) (*PolicyAssignment, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.versions[id][version]
	if !ok {
		return nil, false
	}
	return &PolicyAssignment{
		PolicyID: id,
		Version:  version,
		WASMHash: v.hash,
		WASMPath: v.path,
	}, true
}

func (s *Store) DeletePolicy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.policies[id]; !ok {
		return fmt.Errorf("policy %s not found", id)
	}
	delete(s.policies, id)
	delete(s.versions, id)
	return nil
}

func (s *Store) GetPolicy(id string) (*Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[id]
	if !ok {
		return nil, false
	}
	cp := *p
	return &cp, true
}

func (s *Store) ListPolicies() []*Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Policy, 0, len(s.policies))
	for _, p := range s.policies {
		cp := *p
		result = append(result, &cp)
	}
	return result
}

// GetWASM returns the WASM binary of a policy's active version.
func (s *Store) GetWASM(policyID string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[policyID]
	if !ok {
		return nil, false
	}
	v, ok := s.versions[policyID][p.ActiveVersion]
	if !ok {
		return nil, false
	}
	return v.data, true
}

// GetWASMVersion returns the WASM binary of a specific policy version.
func (s *Store) GetWASMVersion(policyID string, version int64) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.versions[policyID][version]
	if !ok {
		return nil, false
	}
	return v.data, true
}

// MatchPolicy finds the highest-priority policy whose selector matches the agent labels.
func (s *Store) MatchPolicy(labels map[string]string) *Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var best *Policy
	for _, p := range s.policies {
		if !selectorMatches(p.Selector, labels) {
			continue
		}
		if best == nil || p.Priority > best.Priority {
			best = p
		}
	}
	if best == nil {
		return nil
	}
	cp := *best
	return &cp
}

func selectorMatches(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return true
	}
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// RegisterAgent adds or updates an agent registration and returns a copy of
// the stored agent.
func (s *Store) RegisterAgent(req *RegisterRequest) *Agent {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, exists := s.agents[req.ID]
	if !exists {
		a = &Agent{
			ID: req.ID,
		}
		s.agents[req.ID] = a
	}
	a.Hostname = req.Hostname
	a.Labels = req.Labels
	a.LastHeartbeat = time.Now()
	a.Status = AgentStatusActive
	cp := *a
	return &cp
}

// Heartbeat updates an agent's last-seen time and policy version.
func (s *Store) Heartbeat(agentID string, policyVersion int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.agents[agentID]
	if !ok {
		return fmt.Errorf("agent %s not registered", agentID)
	}
	a.LastHeartbeat = time.Now()
	a.PolicyVersion = policyVersion
	a.Status = AgentStatusActive
	return nil
}

// GetAgent returns agent info.
func (s *Store) GetAgent(id string) (*Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[id]
	if !ok {
		return nil, false
	}
	cp := *a
	return &cp, true
}

// ListAgents returns all registered agents.
func (s *Store) ListAgents() []*Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Agent, 0, len(s.agents))
	for _, a := range s.agents {
		cp := *a
		result = append(result, &cp)
	}
	return result
}

// MarkStaleAgents marks agents that haven't sent a heartbeat within the threshold.
func (s *Store) MarkStaleAgents(threshold time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for _, a := range s.agents {
		if a.Status == AgentStatusActive && now.Sub(a.LastHeartbeat) > threshold {
			a.Status = AgentStatusStale
		}
		if a.Status == AgentStatusStale && now.Sub(a.LastHeartbeat) > threshold*3 {
			a.Status = AgentStatusDisconnected
		}
	}
}
