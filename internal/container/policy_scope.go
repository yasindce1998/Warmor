package container

import (
	"math"
	"strings"
	"sync"
)

type PolicyBinding struct {
	PolicyID    string `json:"policy_id"`
	ContainerID string `json:"container_id"`
	Namespace   string `json:"namespace"`
	Image       string `json:"image"`
}

type PolicyScope struct {
	mu       sync.RWMutex
	bindings map[string]*PolicyBinding // container ID -> binding
}

func NewPolicyScope() *PolicyScope {
	return &PolicyScope{
		bindings: make(map[string]*PolicyBinding),
	}
}

func (ps *PolicyScope) Bind(containerID, policyID string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.bindings[containerID] = &PolicyBinding{
		PolicyID:    policyID,
		ContainerID: containerID,
	}
}

func (ps *PolicyScope) BindWithInfo(info *ContainerInfo, policyID string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.bindings[info.ID] = &PolicyBinding{
		PolicyID:    policyID,
		ContainerID: info.ID,
		Namespace:   info.Namespace,
		Image:       info.Image,
	}
}

func (ps *PolicyScope) Unbind(containerID string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	delete(ps.bindings, containerID)
}

func (ps *PolicyScope) Lookup(containerID string) (string, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	b, ok := ps.bindings[containerID]
	if !ok {
		return "", false
	}
	return b.PolicyID, true
}

// LookupByImage returns the policy bound to the given image. An exact image
// match wins over a "repo:*" wildcard, and among wildcards the longest one
// wins. Remaining ties are broken by the lowest container ID so the result
// does not depend on map iteration order. An empty image matches nothing.
func (ps *PolicyScope) LookupByImage(image string) (string, bool) {
	if image == "" {
		return "", false
	}
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	var best *PolicyBinding
	bestRank := 0
	for _, b := range ps.bindings {
		rank := 0
		switch {
		case b.Image == "":
			continue
		case b.Image == image:
			rank = math.MaxInt // exact matches outrank any wildcard
		case matchImagePrefix(b.Image, image):
			rank = len(b.Image)
		default:
			continue
		}
		if best == nil || rank > bestRank || (rank == bestRank && b.ContainerID < best.ContainerID) {
			best, bestRank = b, rank
		}
	}
	if best == nil {
		return "", false
	}
	return best.PolicyID, true
}

// LookupByNamespace returns the policy bound to the given namespace. If
// several containers in the namespace are bound, the lowest container ID
// wins so the result is deterministic. An empty namespace matches nothing.
func (ps *PolicyScope) LookupByNamespace(ns string) (string, bool) {
	if ns == "" {
		return "", false
	}
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	var best *PolicyBinding
	for _, b := range ps.bindings {
		if b.Namespace == ns && (best == nil || b.ContainerID < best.ContainerID) {
			best = b
		}
	}
	if best == nil {
		return "", false
	}
	return best.PolicyID, true
}

func (ps *PolicyScope) All() []*PolicyBinding {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	out := make([]*PolicyBinding, 0, len(ps.bindings))
	for _, b := range ps.bindings {
		out = append(out, b)
	}
	return out
}

func matchImagePrefix(pattern, image string) bool {
	if prefix, ok := strings.CutSuffix(pattern, ":*"); ok {
		return strings.HasPrefix(image, prefix+":")
	}
	return false
}
