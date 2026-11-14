package policyserver

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/crypto"
)

// Store manages policies, registrations, bindings and rollouts. NewStore is
// ephemeral; OpenStore adds synchronous transactional snapshot persistence.
type Store struct {
	mu       sync.RWMutex
	policies map[string]*Policy
	agents   map[string]*Agent
	// versions keeps every uploaded WASM binary so that rollouts can serve
	// both their base and target versions: policyID -> version -> binary.
	versions map[string]map[int64]*policyVersion
	// verifyKey, if set, makes every upload require a detached signature
	// that verifies against it.
	verifyKey ed25519.PublicKey
	rollouts  map[string]*RolloutState
	bindings  map[string]*ContainerBinding
	audit     []AuditEntry
	sequence  uint64
	backend   *snapshotBackend
	limits    StoreLimits
	closed    bool
}

// policyVersion is one immutable uploaded revision of a policy's WASM.
type policyVersion struct {
	data []byte
	hash string
	path string
	// sig is the raw ed25519 signature over data, or nil if unsigned.
	sig []byte
}

func NewStore() *Store {
	return &Store{
		policies: make(map[string]*Policy),
		agents:   make(map[string]*Agent),
		versions: make(map[string]map[int64]*policyVersion),
		rollouts: make(map[string]*RolloutState),
		bindings: make(map[string]*ContainerBinding),
		limits:   DefaultStoreLimits(),
	}
}

// SetVerifyKey makes the store refuse uploads whose detached signature is
// missing or does not verify against pub. The private key never needs to
// be on the server: policies are signed offline and uploaded with their
// signature.
func (s *Store) SetVerifyKey(pub ed25519.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifyKey = slices.Clone(pub)
}

// readPolicyVersion reads a WASM upload. sigFile is its detached signature
// (the <policy>.sig file format, or a raw 64-byte signature), or nil for
// an unsigned upload. A signature that is present must be well formed; with
// a verify key it must also verify, and unsigned uploads are refused.
func readPolicyVersion(wasmPath string, sigFile []byte, pub ed25519.PublicKey, maxBytes int64) (*policyVersion, error) {
	data, err := crypto.ReadFileLimited(wasmPath, maxBytes)
	if err != nil {
		return nil, fmt.Errorf("read wasm: %w", err)
	}
	var sig []byte
	switch {
	case len(sigFile) > 0:
		if sig, err = crypto.DecodePolicySignature(sigFile); err != nil {
			return nil, err
		}
		if pub != nil {
			if err := crypto.VerifyPolicySignature(pub, data, sig); err != nil {
				return nil, fmt.Errorf("%s: %w", wasmPath, err)
			}
		}
	case pub != nil:
		return nil, fmt.Errorf("%s: %w (the server requires signed policies)", wasmPath, crypto.ErrPolicyUnsigned)
	}
	h := sha256.Sum256(data)
	return &policyVersion{data: data, hash: hex.EncodeToString(h[:]), path: wasmPath, sig: sig}, nil
}

// CreatePolicy creates an unsigned policy from wasmPath.
func (s *Store) CreatePolicy(p *Policy, wasmPath string) error {
	return s.CreateSignedPolicy(p, wasmPath, nil)
}

// CreateSignedPolicy creates a policy from wasmPath with its detached
// signature sigFile (nil for unsigned).
func (s *Store) CreateSignedPolicy(p *Policy, wasmPath string, sigFile []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p == nil || !validStateID(p.ID) {
		return fmt.Errorf("valid policy id required")
	}
	if _, exists := s.policies[p.ID]; exists {
		return fmt.Errorf("policy %s already exists", p.ID)
	}

	v, err := readPolicyVersion(wasmPath, sigFile, s.verifyKey, s.limits.MaxWASMBytes)
	if err != nil {
		return err
	}

	cp := clonePolicy(p)
	cp.WASMHash, cp.WASMPath, cp.Signed = v.hash, v.path, v.sig != nil
	cp.Version, cp.ActiveVersion = 1, 1
	cp.CreatedAt = time.Now()
	cp.UpdatedAt = cp.CreatedAt
	err = s.mutateLocked("policy.create", p.ID, func() error {
		s.policies[cp.ID] = cp
		s.versions[cp.ID] = map[int64]*policyVersion{1: v}
		return nil
	})
	if err == nil {
		*p = *clonePolicy(cp)
	}
	return err
}

// UpdatePolicy uploads a new version of a policy and makes it the active
// version served to agents outside of a rollout.
func (s *Store) UpdatePolicy(id string, wasmPath string) error {
	return s.AddVersion(id, wasmPath, nil, true)
}

// StagePolicy uploads a new version of a policy without activating it, so
// it can be introduced gradually through a rollout.
func (s *Store) StagePolicy(id string, wasmPath string) error {
	return s.AddVersion(id, wasmPath, nil, false)
}

// AddVersion uploads a new version of a policy with its detached signature
// sigFile (nil for unsigned). With activate it becomes the active version;
// otherwise it is staged as a rollout target.
func (s *Store) AddVersion(id, wasmPath string, sigFile []byte, activate bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.policies[id]
	if !ok {
		return fmt.Errorf("policy %s not found", id)
	}

	if activate && s.activeRolloutLocked(id) {
		return fmt.Errorf("policy %s has an active rollout", id)
	}
	v, err := readPolicyVersion(wasmPath, sigFile, s.verifyKey, s.limits.MaxWASMBytes)
	if err != nil {
		return err
	}

	return s.mutateLocked("policy.revise", id, func() error {
		p = clonePolicy(p)
		p.WASMHash = v.hash
		p.WASMPath = v.path
		p.Signed = v.sig != nil
		p.Version++
		p.UpdatedAt = time.Now()
		if activate {
			p.ActiveVersion = p.Version
		}

		s.versions[id][p.Version] = v
		s.policies[id] = p
		return nil
	})
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
	if s.activeRolloutLocked(id) {
		return fmt.Errorf("policy %s has an active rollout", id)
	}
	return s.mutateLocked("policy.activate", id, func() error {
		p = clonePolicy(p)
		p.ActiveVersion = version
		p.UpdatedAt = time.Now()
		s.policies[id] = p
		return nil
	})
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
	return s.assignmentLocked(id, version)
}

func (s *Store) assignmentLocked(id string, version int64) (*PolicyAssignment, bool) {
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
	if s.activeRolloutLocked(id) {
		return fmt.Errorf("policy %s has an active rollout", id)
	}
	return s.mutateLocked("policy.delete", id, func() error {
		delete(s.policies, id)
		delete(s.versions, id)
		for rid, r := range s.rollouts {
			if r.PolicyID == id {
				delete(s.rollouts, rid)
			}
		}
		return nil
	})
}

func (s *Store) GetPolicy(id string) (*Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[id]
	if !ok {
		return nil, false
	}
	return clonePolicy(p), true
}

func (s *Store) ListPolicies() []*Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Policy, 0, len(s.policies))
	for _, p := range s.policies {
		result = append(result, clonePolicy(p))
	}
	slices.SortFunc(result, func(a, b *Policy) int { return stringsCompare(a.ID, b.ID) })
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
	return slices.Clone(v.data), true
}

// GetWASMVersion returns the WASM binary of a specific policy version.
func (s *Store) GetWASMVersion(policyID string, version int64) ([]byte, bool) {
	data, _, ok := s.GetSignedWASM(policyID, version)
	return data, ok
}

// GetSignedWASM returns the WASM binary of a policy version (the active
// version if version is 0) and its raw signature (nil if unsigned).
func (s *Store) GetSignedWASM(policyID string, version int64) (data, sig []byte, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if version == 0 {
		p, found := s.policies[policyID]
		if !found {
			return nil, nil, false
		}
		version = p.ActiveVersion
	}
	v, found := s.versions[policyID][version]
	if !found {
		return nil, nil, false
	}
	return slices.Clone(v.data), slices.Clone(v.sig), true
}

// MatchPolicy finds the highest-priority policy whose selector matches the agent labels.
func (s *Store) MatchPolicy(labels map[string]string) *Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.matchPolicyLocked(labels)
}

func (s *Store) matchPolicyLocked(labels map[string]string) *Policy {

	var best *Policy
	for _, p := range s.policies {
		if !selectorMatches(p.Selector, labels) {
			continue
		}
		if best == nil || p.Priority > best.Priority || (p.Priority == best.Priority && p.ID < best.ID) {
			best = p
		}
	}
	if best == nil {
		return nil
	}
	return clonePolicy(best)
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

// RegisterAgent returns a copy of the stored agent, or nil on failure. Network
// handlers should use RegisterAgentChecked to report durability/limit errors.
func (s *Store) RegisterAgent(req *RegisterRequest) *Agent {
	a, _ := s.RegisterAgentChecked(req)
	return a
}

// RegisterAgentChecked commits an agent registration before returning success.
func (s *Store) RegisterAgentChecked(req *RegisterRequest) (*Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req == nil || !validStateID(req.ID) {
		return nil, fmt.Errorf("valid agent id required")
	}
	var result *Agent
	err := s.mutateLocked("agent.register", req.ID, func() error {
		a, exists := s.agents[req.ID]
		if !exists {
			a = &Agent{
				ID: req.ID,
			}
			s.agents[req.ID] = a
		}
		a.Hostname = req.Hostname
		a.Labels = maps.Clone(req.Labels)
		a.LastHeartbeat = time.Now()
		a.Status = AgentStatusActive
		result = cloneAgent(a)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Heartbeat updates an agent's last-seen time and policy version.
func (s *Store) Heartbeat(agentID string, policyVersion int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.agents[agentID]
	if !ok {
		return fmt.Errorf("agent %s not registered", agentID)
	}
	return s.mutateLocked("", "", func() error {
		a = cloneAgent(a)
		a.LastHeartbeat = time.Now()
		a.PolicyVersion = policyVersion
		a.Status = AgentStatusActive
		s.agents[agentID] = a
		return nil
	})
}

// GetAgent returns agent info.
func (s *Store) GetAgent(id string) (*Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[id]
	if !ok {
		return nil, false
	}
	return cloneAgent(a), true
}

// ListAgents returns all registered agents.
func (s *Store) ListAgents() []*Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Agent, 0, len(s.agents))
	for _, a := range s.agents {
		result = append(result, cloneAgent(a))
	}
	slices.SortFunc(result, func(a, b *Agent) int { return stringsCompare(a.ID, b.ID) })
	return result
}

// MarkStaleAgents marks agents that haven't sent a heartbeat within the threshold.
func (s *Store) MarkStaleAgents(threshold time.Duration) {
	_ = s.MarkStaleAgentsChecked(threshold)
}

// MarkStaleAgentsChecked persists derived liveness state if it changed.
func (s *Store) MarkStaleAgentsChecked(threshold time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	updates := make(map[string]*Agent)
	for _, a := range s.agents {
		previous := a.Status
		a = cloneAgent(a)
		if a.Status == AgentStatusActive && now.Sub(a.LastHeartbeat) > threshold {
			a.Status = AgentStatusStale
		}
		if a.Status == AgentStatusStale && now.Sub(a.LastHeartbeat) > threshold*3 {
			a.Status = AgentStatusDisconnected
		}
		if a.Status != previous {
			updates[a.ID] = a
		}
	}
	if len(updates) == 0 {
		return nil
	}
	return s.mutateLocked("", "", func() error { maps.Copy(s.agents, updates); return nil })
}

func clonePolicy(p *Policy) *Policy { cp := *p; cp.Selector = maps.Clone(p.Selector); return &cp }
func cloneAgent(a *Agent) *Agent    { cp := *a; cp.Labels = maps.Clone(a.Labels); return &cp }
