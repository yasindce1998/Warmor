package policyserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/yasindce1998/warmor/internal/telemetry"
)

const telemetryEpochHeader = "X-Warmor-Telemetry-Epoch"
const telemetrySessionHeader = "X-Warmor-Telemetry-Session"

// Strict telemetry authentication has no admin/insecure impersonation bypass.
// Administrators may inspect reports but cannot submit another node's totals.
func telemetryPrincipal(r *http.Request) (string, error) {
	p, ok := r.Context().Value(principalKey{}).(authenticatedPrincipal)
	if !ok || p.admin || !telemetry.ValidID(p.subject) {
		return "", ErrTelemetryFence
	}
	return p.subject, nil
}

func (s *Server) handleTelemetrySession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.telemetry == nil {
		http.NotFound(w, r)
		return
	}
	agent, err := telemetryPrincipal(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if _, ok := s.store.GetAgent(agent); !ok {
		http.Error(w, "agent not registered", http.StatusNotFound)
		return
	}
	lease, err := s.telemetry.AuthorizeSession(agent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, lease)
}

func (s *Server) handleTelemetryReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.telemetry == nil {
		http.NotFound(w, r)
		return
	}
	id := r.URL.Query().Get("rollout_id")
	// Refresh before exposing any verdict, including when every agent is offline.
	s.store.mu.RLock()
	active := false
	var refreshErr error
	for agent := range s.store.agents {
		_, b, err := s.telemetryAssignmentLocked(agent)
		if err == nil && b.RolloutID == id {
			_, refreshErr = s.refreshTelemetryDomainLocked(b)
			active = true
			break
		}
	}
	if !active {
		refreshErr = s.telemetry.RemoveRollout(id)
	}
	s.store.mu.RUnlock()
	if refreshErr != nil {
		http.Error(w, refreshErr.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, s.telemetry.Report(id))
}

// Caller holds the fleet read lock. Roster membership is authoritative desired
// assignment coverage, never the set of agents that happened to send reports.
func (s *Server) refreshTelemetryDomainLocked(b telemetryBinding) (string, error) {
	roster := map[string]bool{}
	for id, a := range s.store.agents {
		p := s.store.matchPolicyLocked(a.Labels)
		if p != nil && !p.AuditMode && p.ID == b.Revision.PolicyID {
			rollout := s.store.rollouts[b.RolloutID]
			if rollout != nil && rollout.Status == "active" {
				roster[id] = consistentBucket(rollout.ID, id) < rollout.Percentage
			}
		}
	}
	return s.telemetry.configureDomain(b.RolloutID, b.Generation, roster)
}

// telemetryAssignmentLocked derives immutable assignment evidence from the
// authoritative fleet snapshot. Labels/percentage/artifact/selector changes
// produce a new generation; offline old assignments cannot move their counts.
// Caller holds store.mu. No cohort field comes from the wire.
func (s *Server) telemetryAssignmentLocked(agentID string) (*PolicyAssignment, telemetryBinding, error) {
	a := s.store.agents[agentID]
	if a == nil {
		return nil, telemetryBinding{}, ErrTelemetryFence
	}
	p := s.store.matchPolicyLocked(a.Labels)
	if p == nil || p.AuditMode {
		return nil, telemetryBinding{}, ErrTelemetryFence
	}
	for _, rollout := range s.store.rollouts {
		if rollout.Status != "active" || rollout.PolicyID != p.ID {
			continue
		}
		canary := consistentBucket(rollout.ID, agentID) < rollout.Percentage
		version := rollout.BaseVersion
		if canary {
			version = rollout.TargetVersion
		}
		assignment, ok := s.store.assignmentLocked(p.ID, version)
		if !ok {
			return nil, telemetryBinding{}, ErrTelemetryFence
		}
		// Hash the entire bounded authoritative assignment domain, including
		// agent labels and competing policies. This intentionally over-invalidates
		// on unrelated fleet changes rather than retain ambiguous cohort evidence.
		domain := struct {
			Rollout            *RolloutState
			Policies           map[string]*Policy
			Agents             map[string]map[string]string
			ManagementSequence uint64
		}{Rollout: rollout, Policies: s.store.policies, Agents: map[string]map[string]string{}}
		if len(s.store.audit) > 0 {
			domain.ManagementSequence = s.store.audit[len(s.store.audit)-1].Sequence
		}
		for id, a := range s.store.agents {
			domain.Agents[id] = a.Labels
		}
		data, err := json.Marshal(domain)
		if err != nil {
			return nil, telemetryBinding{}, err
		}
		h := sha256.Sum256(data)
		generation := hex.EncodeToString(h[:])
		key := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%d/%s/%t", generation, assignment.PolicyID, assignment.Version, assignment.WASMHash, canary)))
		return assignment, telemetryBinding{Revision: telemetry.Revision{PolicyID: assignment.PolicyID, PolicyVersion: assignment.Version, PolicyHash: assignment.WASMHash}, RolloutID: rollout.ID, Generation: generation, Canary: canary, AssignmentKey: hex.EncodeToString(key[:])}, nil
	}
	return nil, telemetryBinding{}, ErrTelemetryFence
}

func (s *Server) attachTelemetryAssignment(r *http.Request, agent string, assignment *PolicyAssignment) error {
	lease := telemetry.Session{Epoch: r.Header.Get(telemetryEpochHeader), SessionID: r.Header.Get(telemetrySessionHeader)}
	if lease.Epoch == "" && lease.SessionID == "" {
		return nil
	}
	if s.telemetry == nil {
		return errors.New("server telemetry is disabled")
	}
	principal, err := telemetryPrincipal(r)
	if err != nil || principal != agent {
		return ErrTelemetryFence
	}
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	current, binding, err := s.telemetryAssignmentLocked(agent)
	// Outside active rollouts telemetry is intentionally absent.
	if errors.Is(err, ErrTelemetryFence) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.PolicyID != assignment.PolicyID || current.Version != assignment.Version || current.WASMHash != assignment.WASMHash {
		return ErrTelemetryFence
	}
	binding.Generation, err = s.refreshTelemetryDomainLocked(binding)
	if err != nil {
		return err
	}
	assignment.Telemetry, err = s.telemetry.issueAssignment(agent, lease, binding)
	return err
}

func (s *Server) ingestHeartbeatTelemetry(r *http.Request, req HeartbeatRequest) error {
	if s.telemetry == nil {
		return errors.New("server telemetry is disabled")
	}
	principal, err := telemetryPrincipal(r)
	if err != nil || principal != req.AgentID {
		return ErrTelemetryFence
	}
	// Keep the authoritative acknowledgement and assignment generation stable
	// through the telemetry commit. Lock order is fleet -> telemetry everywhere.
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	_, binding, err := s.telemetryAssignmentLocked(principal)
	if err != nil {
		return err
	}
	if _, err := s.refreshTelemetryDomainLocked(binding); err != nil {
		return err
	}
	_, err = s.telemetry.ingest(principal, s.store.agents[principal], *req.Telemetry)
	return err
}
