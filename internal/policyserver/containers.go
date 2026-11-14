package policyserver

import (
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strings"
)

type ContainerBinding struct {
	ContainerID string            `json:"container_id"`
	PID         int               `json:"pid"`
	PolicyID    string            `json:"policy_id"`
	Labels      map[string]string `json:"labels,omitempty"`
	// Owner is server-derived from the authenticated principal, never JSON.
	Owner string `json:"owner,omitempty"`
}

type containerStore struct {
	*Store
}

func newContainerStore(store *Store) *containerStore {
	return &containerStore{Store: store}
}

func (s *Server) handleContainerBind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var binding ContainerBinding
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&binding); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if !validStateID(binding.ContainerID) || !validStateID(binding.PolicyID) || !validLabels(binding.Labels) || binding.PID < 0 {
		http.Error(w, "container_id and policy_id required", http.StatusBadRequest)
		return
	}

	p, ok := r.Context().Value(principalKey{}).(authenticatedPrincipal)
	if !ok || (!p.admin && p.subject == "") {
		unauthorized(w, "authenticated runtime identity required")
		return
	}
	binding.Owner = p.subject
	if err := s.bindContainer(p, &binding); err != nil {
		http.Error(w, err.Error(), bindingErrorStatus(err))
		return
	}

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
	if !validStateID(id) {
		http.Error(w, "container_id required", http.StatusBadRequest)
		return
	}

	p, ok := r.Context().Value(principalKey{}).(authenticatedPrincipal)
	if !ok || (!p.admin && p.subject == "") {
		unauthorized(w, "authenticated runtime identity required")
		return
	}
	if err := s.deleteContainer(p, id); err != nil {
		http.Error(w, err.Error(), bindingErrorStatus(err))
		return
	}

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
		cp.Labels = maps.Clone(b.Labels)
		out = append(out, &cp)
	}
	slices.SortFunc(out, func(a, b *ContainerBinding) int { return strings.Compare(a.ContainerID, b.ContainerID) })
	return out
}

var errBindingOwner = errors.New("container binding belongs to another runtime")

func (s *Server) bindContainer(p authenticatedPrincipal, b *ContainerBinding) error {
	store := s.containers.Store
	store.mu.Lock()
	defer store.mu.Unlock()
	if old, exists := store.bindings[b.ContainerID]; exists {
		if !p.admin && old.Owner != p.subject {
			return errBindingOwner
		}
		if p.admin {
			b.Owner = old.Owner
		}
	}
	return store.mutateLocked("container.bind", b.ContainerID, func() error {
		cp := *b
		cp.Labels = maps.Clone(b.Labels)
		store.bindings[b.ContainerID] = &cp
		return nil
	})
}

func (s *Server) deleteContainer(p authenticatedPrincipal, id string) error {
	store := s.containers.Store
	store.mu.Lock()
	defer store.mu.Unlock()
	if old, exists := store.bindings[id]; exists && !p.admin && old.Owner != p.subject {
		return errBindingOwner
	}
	return store.mutateLocked("container.delete", id, func() error { delete(store.bindings, id); return nil })
}

func bindingErrorStatus(err error) int {
	if errors.Is(err, errBindingOwner) {
		return http.StatusForbidden
	}
	if errors.Is(err, ErrStateLimit) {
		return http.StatusConflict
	}
	return http.StatusInternalServerError
}
