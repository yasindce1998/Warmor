package policyserver

import (
	"errors"
	"fmt"
	"time"
)

var errAgentNotRegistered = errors.New("agent not registered")

// HeartbeatRevision records the active revision separately from assignment.
// Version-only legacy reports leave ID and digest unknown. Every report uses
// the store's synchronous transaction boundary, including rollback on failure.
func (s *Store) HeartbeatRevision(req HeartbeatRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[req.AgentID]
	if !ok {
		return fmt.Errorf("%w: %s", errAgentNotRegistered, req.AgentID)
	}
	return s.mutateLocked("", "", func() error {
		cp := cloneAgent(a)
		cp.LastHeartbeat = time.Now()
		cp.PolicyVersion = req.PolicyVersion
		cp.PolicyID = req.PolicyID
		cp.PolicyHash = req.PolicyHash
		cp.ActivationError = req.ActivationError
		cp.Status = AgentStatusActive
		s.agents[req.AgentID] = cp
		return nil
	})
}
