package policyserver

import (
	"errors"
	"fmt"
	"time"
)

var errAgentNotRegistered = errors.New("agent not registered")

// registeredAgent uses the checked registration API when the durable fleet
// store is integrated. The fallback supports the ephemeral foundation store.
// Never route a persistence-backed store through its error-discarding wrapper.
func registeredAgent(store *Store, req *RegisterRequest) (*Agent, error) {
	if checked, ok := any(store).(interface {
		RegisterAgentChecked(*RegisterRequest) (*Agent, error)
	}); ok {
		return checked.RegisterAgentChecked(req)
	}
	a := store.RegisterAgent(req)
	if a == nil {
		return nil, errors.New("agent registration failed")
	}
	return a, nil
}

// HeartbeatRevision records the active revision separately from assignment.
// It uses the fleet store's existing synchronous mutation/snapshot boundary,
// including rollback on failure. This adapter keeps the activation batch
// independently buildable on the ephemeral foundation without modifying the
// concurrently owned store.go implementation.
func (s *Store) HeartbeatRevision(req HeartbeatRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[req.AgentID]
	if !ok {
		return fmt.Errorf("%w: %s", errAgentNotRegistered, req.AgentID)
	}
	mutate := func() error {
		cp := *a
		cp.LastHeartbeat = time.Now()
		cp.PolicyVersion = req.PolicyVersion
		cp.PolicyID = req.PolicyID
		cp.PolicyHash = req.PolicyHash
		cp.ActivationError = req.ActivationError
		cp.Status = AgentStatusActive
		s.agents[req.AgentID] = &cp
		return nil
	}
	if transactional, ok := any(s).(interface {
		mutateLocked(string, string, func() error) error
	}); ok {
		return transactional.mutateLocked("", "", mutate)
	}
	return mutate()
}
