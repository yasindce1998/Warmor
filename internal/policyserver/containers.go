package policyserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
)

type ContainerBinding struct {
	ContainerID string            `json:"container_id"`
	PID         int               `json:"pid"`
	PolicyID    string            `json:"policy_id"`
	Labels      map[string]string `json:"labels,omitempty"`
}

type containerStore struct {
	mu       sync.RWMutex
	bindings map[string]*ContainerBinding
}

func newContainerStore() *containerStore {
	return &containerStore{bindings: make(map[string]*ContainerBinding)}
}

func (s *Server) handleContainerBind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var binding ContainerBinding
	if err := json.NewDecoder(r.Body).Decode(&binding); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if binding.ContainerID == "" || binding.PolicyID == "" {
		http.Error(w, "container_id and policy_id required", http.StatusBadRequest)
		return
	}

	s.containers.mu.Lock()
	s.containers.bindings[binding.ContainerID] = &binding
	s.containers.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{
		"status":       "bound",
		"container_id": binding.ContainerID,
		"policy_id":    binding.PolicyID,
	})
}

func (s *Server) handleContainerDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/containers/")
	if id == "" {
		http.Error(w, "container_id required", http.StatusBadRequest)
		return
	}

	s.containers.mu.Lock()
	delete(s.containers.bindings, id)
	s.containers.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// GetContainerPolicy returns the policy bound to a container.
func (s *Server) GetContainerPolicy(containerID string) (string, bool) {
	s.containers.mu.RLock()
	defer s.containers.mu.RUnlock()
	b, ok := s.containers.bindings[containerID]
	if !ok {
		return "", false
	}
	return b.PolicyID, true
}

// ListContainerBindings returns copies of all container bindings.
func (s *Server) ListContainerBindings() []*ContainerBinding {
	s.containers.mu.RLock()
	defer s.containers.mu.RUnlock()
	out := make([]*ContainerBinding, 0, len(s.containers.bindings))
	for _, b := range s.containers.bindings {
		cp := *b
		out = append(out, &cp)
	}
	return out
}
