package policyserver

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// RolloutManager handles gradual policy rollouts and A/B testing.
type RolloutManager struct {
	mu       sync.RWMutex
	rollouts map[string]*RolloutState
	store    *Store
}

// RolloutState tracks a live rollout's progress.
type RolloutState struct {
	Rollout
	BaseVersion  int64  `json:"base_version"`
	BasePolicyID string `json:"base_policy_id,omitempty"`
}

// RolloutConfig defines a new rollout.
type RolloutConfig struct {
	ID       string `json:"id"`
	PolicyID string `json:"policy_id"`
	// TargetVersion is the stored policy version being rolled out; zero
	// means the policy's latest version.
	TargetVersion int64 `json:"target_version"`
	Percentage    int   `json:"percentage"`
}

// ErrRolloutNotActive is returned when modifying a rollout that has already
// completed or been aborted.
var ErrRolloutNotActive = errors.New("rollout is not active")

// NewRolloutManager creates a rollout manager backed by the given store.
func NewRolloutManager(store *Store) *RolloutManager {
	return &RolloutManager{
		rollouts: make(map[string]*RolloutState),
		store:    store,
	}
}

// CreateRollout starts a new gradual rollout.
func (rm *RolloutManager) CreateRollout(cfg RolloutConfig) (*RolloutState, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if _, exists := rm.rollouts[cfg.ID]; exists {
		return nil, fmt.Errorf("rollout %s already exists", cfg.ID)
	}

	policy, ok := rm.store.GetPolicy(cfg.PolicyID)
	if !ok {
		return nil, fmt.Errorf("policy %s not found", cfg.PolicyID)
	}

	if cfg.Percentage < 0 || cfg.Percentage > 100 {
		return nil, fmt.Errorf("percentage must be 0-100, got %d", cfg.Percentage)
	}

	for _, r := range rm.rollouts {
		if r.PolicyID == cfg.PolicyID && r.Status == "active" {
			return nil, fmt.Errorf("policy %s already has active rollout %s", cfg.PolicyID, r.ID)
		}
	}

	target := cfg.TargetVersion
	if target == 0 {
		target = policy.Version
	}
	if !rm.store.HasVersion(cfg.PolicyID, target) {
		return nil, fmt.Errorf("policy %s has no version %d", cfg.PolicyID, target)
	}

	// The base is what non-canary agents keep receiving: the active version,
	// or, if the target was already activated by a plain update, the version
	// it replaced.
	base := policy.ActiveVersion
	if base == target {
		base = rm.store.previousVersion(cfg.PolicyID, target)
	}
	if base == 0 {
		return nil, fmt.Errorf("policy %s has no version to roll out from", cfg.PolicyID)
	}

	state := &RolloutState{
		Rollout: Rollout{
			ID:            cfg.ID,
			PolicyID:      cfg.PolicyID,
			TargetVersion: target,
			Percentage:    cfg.Percentage,
			StartedAt:     time.Now(),
			Status:        "active",
		},
		BaseVersion: base,
	}

	rm.rollouts[cfg.ID] = state
	cp := *state
	return &cp, nil
}

// UpdatePercentage changes the rollout percentage (for gradual ramp-up).
// Reaching 100% completes the rollout and promotes the target version to the
// policy's active version.
func (rm *RolloutManager) UpdatePercentage(rolloutID string, pct int) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	state, ok := rm.rollouts[rolloutID]
	if !ok {
		return fmt.Errorf("rollout %s not found", rolloutID)
	}
	if state.Status != "active" {
		return fmt.Errorf("rollout %s is %s: %w", rolloutID, state.Status, ErrRolloutNotActive)
	}
	if pct < 0 || pct > 100 {
		return fmt.Errorf("percentage must be 0-100")
	}

	if pct == 100 {
		if err := rm.store.SetActiveVersion(state.PolicyID, state.TargetVersion); err != nil {
			return fmt.Errorf("promote target version: %w", err)
		}
		now := time.Now()
		state.CompletedAt = &now
		state.Status = "completed"
	}
	state.Percentage = pct
	return nil
}

// CompleteRollout marks a rollout as fully rolled out.
func (rm *RolloutManager) CompleteRollout(rolloutID string) error {
	return rm.UpdatePercentage(rolloutID, 100)
}

// AbortRollout cancels a rollout and reverts all agents to the base version.
func (rm *RolloutManager) AbortRollout(rolloutID string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	state, ok := rm.rollouts[rolloutID]
	if !ok {
		return fmt.Errorf("rollout %s not found", rolloutID)
	}
	if state.Status != "active" {
		return fmt.Errorf("rollout %s is %s: %w", rolloutID, state.Status, ErrRolloutNotActive)
	}
	// Pin the policy back to the base version. This only fails if the policy
	// was deleted, in which case there is nothing left to serve anyway.
	_ = rm.store.SetActiveVersion(state.PolicyID, state.BaseVersion)
	now := time.Now()
	state.CompletedAt = &now
	state.Status = "aborted"
	return nil
}

// GetRollout returns rollout state.
func (rm *RolloutManager) GetRollout(id string) (*RolloutState, bool) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	r, ok := rm.rollouts[id]
	if !ok {
		return nil, false
	}
	cp := *r
	return &cp, true
}

// ListRollouts returns all rollouts.
func (rm *RolloutManager) ListRollouts() []*RolloutState {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	result := make([]*RolloutState, 0, len(rm.rollouts))
	for _, r := range rm.rollouts {
		cp := *r
		result = append(result, &cp)
	}
	return result
}

// ShouldUseNewVersion determines if a given agent should receive the new
// policy version based on the rollout percentage. Uses consistent hashing
// so the same agent always gets the same decision for a given rollout.
func (rm *RolloutManager) ShouldUseNewVersion(rolloutID, agentID string) bool {
	rm.mu.RLock()
	state, ok := rm.rollouts[rolloutID]
	rm.mu.RUnlock()

	if !ok || state.Status != "active" {
		return false
	}

	if state.Percentage >= 100 {
		return true
	}
	if state.Percentage <= 0 {
		return false
	}

	bucket := consistentBucket(rolloutID, agentID)
	return bucket < state.Percentage
}

// ResolvePolicy returns the effective policy assignment for an agent,
// taking active rollouts into account: during a rollout the canary cohort
// receives the target version and everyone else the base version.
func (rm *RolloutManager) ResolvePolicy(agentID string, labels map[string]string) *PolicyAssignment {
	// Hold the rollout lock across the store reads so an abort or completion
	// (which update the store under this lock) is observed atomically.
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	basePolicy := rm.store.MatchPolicy(labels)
	if basePolicy == nil {
		return nil
	}

	version := basePolicy.ActiveVersion
	for _, state := range rm.rollouts {
		if state.Status != "active" {
			continue
		}
		if state.PolicyID != basePolicy.ID {
			continue
		}

		version = state.BaseVersion
		if consistentBucket(state.ID, agentID) < state.Percentage {
			version = state.TargetVersion
		}
		break
	}

	assignment, ok := rm.store.assignment(basePolicy.ID, version)
	if !ok {
		return nil
	}
	return assignment
}

// consistentBucket returns a stable 0-99 bucket for a (rollout, agent) pair.
func consistentBucket(rolloutID, agentID string) int {
	h := sha256.Sum256([]byte(rolloutID + ":" + agentID))
	val := binary.BigEndian.Uint32(h[:4])
	return int(val % 100)
}
