package policyserver

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeWASM(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStorePolicyLifecycle(t *testing.T) {
	s := NewStore()
	dir := t.TempDir()
	v1 := writeWASM(t, dir, "v1.wasm", "one")
	v2 := writeWASM(t, dir, "v2.wasm", "two")

	p := &Policy{ID: "p1", Name: "P1"}
	if err := s.CreatePolicy(p, v1); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("one"))
	if p.Version != 1 || p.WASMHash != hex.EncodeToString(h[:]) || p.WASMPath != v1 {
		t.Errorf("unexpected policy after create: %+v", p)
	}
	if p.CreatedAt.IsZero() || !p.CreatedAt.Equal(p.UpdatedAt) {
		t.Errorf("expected CreatedAt == UpdatedAt and non-zero: %v / %v", p.CreatedAt, p.UpdatedAt)
	}

	if err := s.CreatePolicy(&Policy{ID: "p1"}, v1); err == nil {
		t.Error("expected duplicate create to fail")
	}
	if err := s.CreatePolicy(&Policy{ID: "p2"}, filepath.Join(dir, "missing.wasm")); err == nil {
		t.Error("expected create with missing wasm to fail")
	}
	if _, ok := s.GetPolicy("p2"); ok {
		t.Error("failed create must not leave a policy behind")
	}

	if err := s.UpdatePolicy("p1", v2); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetPolicy("p1")
	h2 := sha256.Sum256([]byte("two"))
	if got.Version != 2 || got.WASMHash != hex.EncodeToString(h2[:]) || got.WASMPath != v2 {
		t.Errorf("unexpected policy after update: %+v", got)
	}
	if data, _ := s.GetWASM("p1"); string(data) != "two" {
		t.Errorf("expected updated wasm bytes, got %q", data)
	}

	if err := s.UpdatePolicy("missing", v2); err == nil {
		t.Error("expected update of unknown policy to fail")
	}
	if err := s.UpdatePolicy("p1", filepath.Join(dir, "missing.wasm")); err == nil {
		t.Error("expected update with missing wasm to fail")
	}
	if got, _ := s.GetPolicy("p1"); got.Version != 2 {
		t.Errorf("failed update must not bump version, got %d", got.Version)
	}

	// GetPolicy returns a copy.
	got.Version = 99
	if again, _ := s.GetPolicy("p1"); again.Version != 2 {
		t.Error("GetPolicy must return a copy")
	}

	if err := s.DeletePolicy("p1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePolicy("p1"); err == nil {
		t.Error("expected second delete to fail")
	}
	if _, ok := s.GetWASM("p1"); ok {
		t.Error("expected wasm removed with policy")
	}
	if len(s.ListPolicies()) != 0 {
		t.Error("expected no policies after delete")
	}
}

func TestStoreMatchPolicy(t *testing.T) {
	s := NewStore()
	dir := t.TempDir()
	w := writeWASM(t, dir, "p.wasm", "x")

	if s.MatchPolicy(map[string]string{"env": "prod"}) != nil {
		t.Error("expected nil match on empty store")
	}

	_ = s.CreatePolicy(&Policy{ID: "catch-all", Priority: 1}, w)
	_ = s.CreatePolicy(&Policy{ID: "prod", Priority: 10, Selector: map[string]string{"env": "prod"}}, w)
	_ = s.CreatePolicy(&Policy{ID: "prod-eu", Priority: 20, Selector: map[string]string{"env": "prod", "region": "eu"}}, w)

	tests := []struct {
		labels map[string]string
		want   string
	}{
		{nil, "catch-all"},
		{map[string]string{"env": "dev"}, "catch-all"},
		{map[string]string{"env": "prod"}, "prod"},
		{map[string]string{"env": "prod", "region": "us"}, "prod"},
		{map[string]string{"env": "prod", "region": "eu"}, "prod-eu"},
	}
	for _, tc := range tests {
		got := s.MatchPolicy(tc.labels)
		if got == nil || got.ID != tc.want {
			t.Errorf("labels %v: expected %s, got %+v", tc.labels, tc.want, got)
		}
	}
}

func TestSelectorMatches(t *testing.T) {
	if !selectorMatches(nil, nil) {
		t.Error("empty selector should match everything")
	}
	if selectorMatches(map[string]string{"a": "1"}, nil) {
		t.Error("non-empty selector must not match nil labels")
	}
	// A selector requiring an empty value matches a missing label (map zero value).
	if !selectorMatches(map[string]string{"a": ""}, map[string]string{}) {
		t.Error("expected empty-value selector to match missing label")
	}
}

func TestStoreAgents(t *testing.T) {
	s := NewStore()
	a := s.RegisterAgent(&RegisterRequest{ID: "a1", Hostname: "h1", Labels: map[string]string{"x": "1"}})
	if a.Status != AgentStatusActive || a.Hostname != "h1" {
		t.Errorf("unexpected agent: %+v", a)
	}

	// Re-register updates in place.
	s.RegisterAgent(&RegisterRequest{ID: "a1", Hostname: "h2"})
	got, _ := s.GetAgent("a1")
	if got.Hostname != "h2" || got.Labels != nil {
		t.Errorf("re-register did not update fields: %+v", got)
	}

	if err := s.Heartbeat("a1", 42); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetAgent("a1")
	if got.PolicyVersion != 42 {
		t.Errorf("expected policy version 42, got %d", got.PolicyVersion)
	}
	if err := s.Heartbeat("nope", 1); err == nil {
		t.Error("expected heartbeat for unknown agent to fail")
	}
	if _, ok := s.GetAgent("nope"); ok {
		t.Error("expected unknown agent lookup to fail")
	}

	s.RegisterAgent(&RegisterRequest{ID: "a2"})
	list := s.ListAgents()
	if len(list) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(list))
	}
	list[0].Status = "mutated"
	for _, ag := range s.ListAgents() {
		if ag.Status == "mutated" {
			t.Error("ListAgents must return copies")
		}
	}
}

func TestStoreMarkStaleAgents(t *testing.T) {
	s := NewStore()
	for _, id := range []string{"fresh", "stale", "gone", "revived"} {
		s.RegisterAgent(&RegisterRequest{ID: id})
	}

	now := time.Now()
	s.mu.Lock()
	s.agents["stale"].LastHeartbeat = now.Add(-2 * time.Minute)
	s.agents["gone"].LastHeartbeat = now.Add(-10 * time.Minute)
	s.agents["revived"].LastHeartbeat = now.Add(-10 * time.Minute)
	s.mu.Unlock()

	s.MarkStaleAgents(time.Minute)

	want := map[string]AgentStatus{
		"fresh":   AgentStatusActive,
		"stale":   AgentStatusStale,
		"gone":    AgentStatusDisconnected, // active -> stale -> disconnected in one pass
		"revived": AgentStatusDisconnected,
	}
	for id, status := range want {
		a, _ := s.GetAgent(id)
		if a.Status != status {
			t.Errorf("%s: expected %s, got %s", id, status, a.Status)
		}
	}

	// A heartbeat brings a disconnected agent back to active.
	if err := s.Heartbeat("revived", 3); err != nil {
		t.Fatal(err)
	}
	if a, _ := s.GetAgent("revived"); a.Status != AgentStatusActive {
		t.Errorf("expected revived agent active, got %s", a.Status)
	}

	// Already-disconnected agents stay disconnected.
	s.MarkStaleAgents(time.Minute)
	if a, _ := s.GetAgent("gone"); a.Status != AgentStatusDisconnected {
		t.Errorf("expected gone to remain disconnected, got %s", a.Status)
	}
}
