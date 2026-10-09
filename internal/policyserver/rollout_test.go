package policyserver

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func setupRolloutTest(t *testing.T) (*Store, *RolloutManager, string) {
	t.Helper()
	store := NewStore()
	rm := NewRolloutManager(store)

	dir := t.TempDir()
	wasmPath := filepath.Join(dir, "policy.wasm")
	_ = os.WriteFile(wasmPath, []byte("test-wasm"), 0644)

	_ = store.CreatePolicy(&Policy{
		ID:       "web-policy",
		Name:     "Web Policy",
		Selector: map[string]string{"tier": "web"},
		Priority: 10,
	}, wasmPath)

	return store, rm, wasmPath
}

func TestRolloutCreation(t *testing.T) {
	_, rm, _ := setupRolloutTest(t)

	state, err := rm.CreateRollout(RolloutConfig{
		ID:            "rollout-1",
		PolicyID:      "web-policy",
		TargetVersion: 2,
		Percentage:    10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "active" {
		t.Errorf("expected status=active, got %s", state.Status)
	}
	if state.Percentage != 10 {
		t.Errorf("expected percentage=10, got %d", state.Percentage)
	}
}

func TestRolloutPercentageUpdate(t *testing.T) {
	_, rm, _ := setupRolloutTest(t)

	_, _ = rm.CreateRollout(RolloutConfig{
		ID:            "rollout-1",
		PolicyID:      "web-policy",
		TargetVersion: 2,
		Percentage:    10,
	})

	if err := rm.UpdatePercentage("rollout-1", 50); err != nil {
		t.Fatal(err)
	}

	state, ok := rm.GetRollout("rollout-1")
	if !ok {
		t.Fatal("rollout not found")
	}
	if state.Percentage != 50 {
		t.Errorf("expected 50%%, got %d%%", state.Percentage)
	}

	// Complete at 100%
	if err := rm.UpdatePercentage("rollout-1", 100); err != nil {
		t.Fatal(err)
	}
	state, _ = rm.GetRollout("rollout-1")
	if state.Status != "completed" {
		t.Errorf("expected status=completed, got %s", state.Status)
	}
}

func TestRolloutAbort(t *testing.T) {
	_, rm, _ := setupRolloutTest(t)

	_, _ = rm.CreateRollout(RolloutConfig{
		ID:            "rollout-1",
		PolicyID:      "web-policy",
		TargetVersion: 2,
		Percentage:    25,
	})

	if err := rm.AbortRollout("rollout-1"); err != nil {
		t.Fatal(err)
	}

	state, _ := rm.GetRollout("rollout-1")
	if state.Status != "aborted" {
		t.Errorf("expected status=aborted, got %s", state.Status)
	}
}

func TestConsistentBucketing(t *testing.T) {
	_, rm, _ := setupRolloutTest(t)

	_, _ = rm.CreateRollout(RolloutConfig{
		ID:            "rollout-1",
		PolicyID:      "web-policy",
		TargetVersion: 2,
		Percentage:    50,
	})

	// Same agent should always get the same decision
	first := rm.ShouldUseNewVersion("rollout-1", "agent-xyz")
	for range 100 {
		if rm.ShouldUseNewVersion("rollout-1", "agent-xyz") != first {
			t.Fatal("inconsistent bucketing for same agent")
		}
	}
}

func TestRolloutDistribution(t *testing.T) {
	_, rm, _ := setupRolloutTest(t)

	_, _ = rm.CreateRollout(RolloutConfig{
		ID:            "rollout-dist",
		PolicyID:      "web-policy",
		TargetVersion: 2,
		Percentage:    50,
	})

	// With 1000 agents and 50% rollout, distribution should be roughly even
	newCount := 0
	total := 1000
	for i := range total {
		agentID := fmt.Sprintf("agent-%d", i)
		if rm.ShouldUseNewVersion("rollout-dist", agentID) {
			newCount++
		}
	}

	ratio := float64(newCount) / float64(total)
	if ratio < 0.40 || ratio > 0.60 {
		t.Errorf("expected ~50%% distribution, got %.1f%% (%d/%d)", ratio*100, newCount, total)
	}
}

func TestResolvePolicyWithRollout(t *testing.T) {
	store, rm, wasmPath := setupRolloutTest(t)

	// Update policy to version 2
	_ = store.UpdatePolicy("web-policy", wasmPath)

	_, _ = rm.CreateRollout(RolloutConfig{
		ID:            "canary-1",
		PolicyID:      "web-policy",
		TargetVersion: 2,
		Percentage:    100, // 100% means all agents get the new version
	})

	labels := map[string]string{"tier": "web"}
	assignment := rm.ResolvePolicy("any-agent", labels)
	if assignment == nil {
		t.Fatal("expected assignment")
	}
	if assignment.Version != 2 {
		t.Errorf("expected version=2, got %d", assignment.Version)
	}
}

func TestResolvePolicyNoRollout(t *testing.T) {
	_, rm, _ := setupRolloutTest(t)

	labels := map[string]string{"tier": "web"}
	assignment := rm.ResolvePolicy("agent-1", labels)
	if assignment == nil {
		t.Fatal("expected assignment")
	}
	if assignment.Version != 1 {
		t.Errorf("expected version=1 (base), got %d", assignment.Version)
	}
}

func TestRolloutCreateValidation(t *testing.T) {
	_, rm, _ := setupRolloutTest(t)

	if _, err := rm.CreateRollout(RolloutConfig{ID: "r", PolicyID: "missing"}); err == nil {
		t.Error("expected error for unknown policy")
	}
	for _, pct := range []int{-1, 101} {
		if _, err := rm.CreateRollout(RolloutConfig{ID: "r", PolicyID: "web-policy", Percentage: pct}); err == nil {
			t.Errorf("expected error for percentage %d", pct)
		}
	}
	state, err := rm.CreateRollout(RolloutConfig{ID: "r", PolicyID: "web-policy", TargetVersion: 2, Percentage: 0})
	if err != nil {
		t.Fatal(err)
	}
	if state.BaseVersion != 0 || state.StartedAt.IsZero() || state.CompletedAt != nil {
		t.Errorf("unexpected initial state: %+v", state)
	}
	if _, err := rm.CreateRollout(RolloutConfig{ID: "r", PolicyID: "web-policy"}); err == nil {
		t.Error("expected duplicate rollout error")
	}
}

func TestRolloutStateTransitions(t *testing.T) {
	_, rm, _ := setupRolloutTest(t)
	_, _ = rm.CreateRollout(RolloutConfig{ID: "r", PolicyID: "web-policy", TargetVersion: 2, Percentage: 10})

	for _, pct := range []int{-1, 101} {
		if err := rm.UpdatePercentage("r", pct); err == nil {
			t.Errorf("expected error for percentage %d", pct)
		}
	}
	if err := rm.UpdatePercentage("missing", 50); err == nil {
		t.Error("expected error updating unknown rollout")
	}
	if err := rm.AbortRollout("missing"); err == nil {
		t.Error("expected error aborting unknown rollout")
	}
	if err := rm.CompleteRollout("missing"); err == nil {
		t.Error("expected error completing unknown rollout")
	}
	if _, ok := rm.GetRollout("missing"); ok {
		t.Error("expected unknown rollout lookup to fail")
	}

	if err := rm.CompleteRollout("r"); err != nil {
		t.Fatal(err)
	}
	state, _ := rm.GetRollout("r")
	if state.Status != "completed" || state.Percentage != 100 || state.CompletedAt == nil {
		t.Errorf("unexpected completed state: %+v", state)
	}

	// GetRollout returns a copy.
	state.Status = "mutated"
	if again, _ := rm.GetRollout("r"); again.Status != "completed" {
		t.Error("GetRollout must return a copy")
	}
}

func TestShouldUseNewVersionStates(t *testing.T) {
	_, rm, _ := setupRolloutTest(t)

	if rm.ShouldUseNewVersion("missing", "agent") {
		t.Error("unknown rollout must not select new version")
	}

	_, _ = rm.CreateRollout(RolloutConfig{ID: "zero", PolicyID: "web-policy", TargetVersion: 2, Percentage: 0})
	_, _ = rm.CreateRollout(RolloutConfig{ID: "full", PolicyID: "web-policy", TargetVersion: 2, Percentage: 100})
	_, _ = rm.CreateRollout(RolloutConfig{ID: "aborted", PolicyID: "web-policy", TargetVersion: 2, Percentage: 100})
	_ = rm.AbortRollout("aborted")

	for i := 0; i < 50; i++ {
		agent := fmt.Sprintf("agent-%d", i)
		if rm.ShouldUseNewVersion("zero", agent) {
			t.Fatalf("0%% rollout selected %s", agent)
		}
		if !rm.ShouldUseNewVersion("full", agent) {
			t.Fatalf("100%% rollout skipped %s", agent)
		}
		if rm.ShouldUseNewVersion("aborted", agent) {
			t.Fatalf("aborted rollout selected %s", agent)
		}
	}
}

func TestShouldUseNewVersionMatchesBucket(t *testing.T) {
	_, rm, _ := setupRolloutTest(t)
	_, _ = rm.CreateRollout(RolloutConfig{ID: "r", PolicyID: "web-policy", TargetVersion: 2, Percentage: 30})
	for i := 0; i < 200; i++ {
		agent := fmt.Sprintf("agent-%d", i)
		want := consistentBucket("r", agent) < 30
		if got := rm.ShouldUseNewVersion("r", agent); got != want {
			t.Fatalf("%s: expected %v, got %v", agent, want, got)
		}
	}
}

func TestConsistentBucketRange(t *testing.T) {
	for i := 0; i < 1000; i++ {
		b := consistentBucket("r", fmt.Sprintf("a-%d", i))
		if b < 0 || b > 99 {
			t.Fatalf("bucket out of range: %d", b)
		}
	}
	if consistentBucket("r1", "a") != consistentBucket("r1", "a") {
		t.Fatal("bucket must be deterministic")
	}
}

func TestResolvePolicyEdgeCases(t *testing.T) {
	store, rm, wasmPath := setupRolloutTest(t)
	labels := map[string]string{"tier": "web"}

	if rm.ResolvePolicy("a", map[string]string{"tier": "db"}) != nil {
		t.Error("expected nil when no policy matches")
	}

	// A rollout for a different policy must not affect web-policy agents.
	_ = store.CreatePolicy(&Policy{ID: "other", Selector: map[string]string{"tier": "db"}}, wasmPath)
	_, _ = rm.CreateRollout(RolloutConfig{ID: "other-r", PolicyID: "other", TargetVersion: 9, Percentage: 100})
	if a := rm.ResolvePolicy("a", labels); a.Version != 1 || a.PolicyID != "web-policy" {
		t.Errorf("unrelated rollout leaked: %+v", a)
	}

	// Aborted rollout is ignored (rollback to base assignment).
	_, _ = rm.CreateRollout(RolloutConfig{ID: "web-r", PolicyID: "web-policy", TargetVersion: 5, Percentage: 100})
	if a := rm.ResolvePolicy("a", labels); a.Version != 5 {
		t.Fatalf("expected 100%% rollout to assign target version, got %+v", a)
	}
	_ = rm.AbortRollout("web-r")
	a := rm.ResolvePolicy("a", labels)
	if a.Version != 1 {
		t.Errorf("expected aborted rollout to fall back to base version, got %d", a.Version)
	}
	base, _ := store.GetPolicy("web-policy")
	if a.WASMHash != base.WASMHash || a.WASMPath != base.WASMPath {
		t.Errorf("assignment should carry base policy wasm metadata: %+v", a)
	}
}
