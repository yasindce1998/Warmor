package policyserver

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"time"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/crypto/assignment"
)

func cloneAssignmentTrust(trust assignment.Trust) assignment.Trust {
	copy := assignment.Trust{}
	for id, k := range trust {
		k.Public = slices.Clone(k.Public)
		copy[id] = k
	}
	return copy
}

func (s *Store) putDeployment(b assignment.Bundle) error {
	wire, err := MarshalDeploymentBundle(b)
	if err != nil {
		return err
	}
	e, err := assignment.Decode(b.Envelope)
	if err != nil {
		return err
	}
	d := e.Deployment
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.deployments[d.Target.Audience]; ok {
		previous, err := assignment.DecodeBundle(old)
		if err != nil {
			return err
		}
		p, err := assignment.Decode(previous.Envelope)
		if err != nil {
			return err
		}
		if bytes.Equal(old, wire) {
			return nil
		}
		if p.Deployment.Target != d.Target || d.Sequence <= p.Deployment.Sequence {
			return errors.New("deployment target change or non-monotonic sequence")
		}
	}
	return s.mutateLocked("deployment.publish", d.Target.Audience, func() error { s.deployments[d.Target.Audience] = wire; return nil })
}

func (s *Store) deployment(audience string) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return bytes.Clone(s.deployments[audience])
}

func (s *Store) validateDeploymentsLocked(integrity bool) error {
	if len(s.deployments) > s.limits.MaxAgents {
		return ErrStateLimit
	}
	var retained int64
	for audience, wire := range s.deployments {
		b, err := assignment.DecodeBundle(wire)
		if err != nil {
			return err
		}
		e, err := assignment.Decode(b.Envelope)
		if err != nil {
			return err
		}
		d := e.Deployment
		if audience != d.Target.Audience || !validStateID(audience) || !validStateID(d.Policy.ID) || d.Policy.Version > math.MaxInt64 || assignment.Digest(b.WASM) != d.Policy.SHA256 {
			return errors.New("invalid retained deployment")
		}
		if int64(len(b.WASM)) > s.limits.MaxWASMBytes {
			return ErrStateLimit
		}
		retained += int64(len(b.WASM))
		if integrity && s.verifyKey != nil {
			if err := crypto.VerifyPolicySignature(s.verifyKey, b.WASM, b.ArtifactSignature); err != nil {
				return err
			}
		}
	}
	// Account relay bundles together with legacy immutable revisions; neither
	// route may bypass the configured total retained-WASM budget.
	for _, versions := range s.versions {
		for _, v := range versions {
			if v != nil {
				retained += int64(len(v.data))
			}
		}
	}
	if retained > s.limits.MaxRetainedWASMBytes {
		return ErrStateLimit
	}
	return nil
}

func (s *Server) handleAdminDeployment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(s.assignmentTrust) == 0 {
		http.Error(w, "signed deployment relay not configured", http.StatusNotImplemented)
		return
	}
	s.store.mu.RLock()
	artifactKey := slices.Clone(s.store.verifyKey)
	s.store.mu.RUnlock()
	if len(artifactKey) != ed25519.PublicKeySize {
		http.Error(w, "deployment relay requires artifact verification key", http.StatusServiceUnavailable)
		return
	}
	wire, err := io.ReadAll(io.LimitReader(r.Body, assignment.MaxBundleBytes+1))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	b, err := assignment.DecodeBundle(wire)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	e, err := assignment.Decode(b.Envelope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	d := e.Deployment
	if key, ok := s.assignmentTrust[d.KeyID]; !ok || bytes.Equal(key.Public, artifactKey) {
		http.Error(w, "distinct trusted assignment key required", http.StatusForbidden)
		return
	}
	if err := crypto.VerifyPolicySignature(artifactKey, b.WASM, b.ArtifactSignature); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	// Relay admission verifies signature/target/expiry. Actual ABI, compiler
	// and effective-posture checks belong to the independently configured agent.
	_, err = assignment.Verify(e, b.WASM, s.assignmentTrust, assignment.VerifyOptions{Target: d.Target, Clock: assignment.Clock{Now: time.Now(), Trusted: true},
		SupportedABIs: []uint32{1, 2, 3, 4, 5}, AllowedCompilers: []string{d.Policy.Compiler}, MaxLifetime: 24 * time.Hour})
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := s.store.putDeployment(b); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleGetDeployment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(s.assignmentTrust) == 0 {
		http.Error(w, "signed deployment relay not configured", http.StatusNotImplemented)
		return
	}
	w.Header().Set(assignment.ProtocolHeader, "1")
	id := r.URL.Query().Get("agent_id")
	if id == "" || !authorizeAgent(w, r, id) {
		if id == "" {
			http.Error(w, "agent_id required", http.StatusBadRequest)
		}
		return
	}
	if _, ok := s.store.GetAgent(id); !ok {
		http.Error(w, "agent not registered", http.StatusNotFound)
		return
	}
	wire := s.store.deployment(id)
	if wire == nil {
		http.Error(w, "no signed deployment for audience", http.StatusNotFound)
		return
	}
	b, err := assignment.DecodeBundle(wire)
	if err != nil {
		http.Error(w, "corrupt deployment", http.StatusServiceUnavailable)
		return
	}
	e, err := assignment.Decode(b.Envelope)
	if err != nil {
		http.Error(w, "corrupt envelope", http.StatusServiceUnavailable)
		return
	}
	if r.URL.Query().Get("if_sequence") == fmt.Sprint(e.Deployment.Sequence) && r.URL.Query().Get("if_envelope_hash") == assignment.Digest(b.Envelope) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(wire)
}
