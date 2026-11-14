package policyserver

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func setupCanaryTest(t *testing.T) (*RolloutManager, *CanaryAnalyzer) {
	t.Helper()
	store := NewStore()
	rm := NewRolloutManager(store)

	dir := t.TempDir()
	wasmPath := filepath.Join(dir, "policy.wasm")
	if err := os.WriteFile(wasmPath, []byte("test-wasm"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := store.CreatePolicy(&Policy{
		ID:       "canary-policy",
		Name:     "Canary Policy",
		Selector: map[string]string{"app": "web"},
		Priority: 10,
	}, wasmPath); err != nil {
		t.Fatal(err)
	}
	// Version 2 is the canary target.
	if err := store.UpdatePolicy("canary-policy", wasmPath); err != nil {
		t.Fatal(err)
	}

	ca := NewCanaryAnalyzer(rm)
	return rm, ca
}

func TestCanaryHealthy(t *testing.T) {
	rm, ca := setupCanaryTest(t)

	_, err := rm.CreateRollout(RolloutConfig{
		ID:            "canary-1",
		PolicyID:      "canary-policy",
		TargetVersion: 2,
		Percentage:    10,
	})
	if err != nil {
		t.Fatal(err)
	}

	ca.Configure("canary-1", CanaryConfig{
		MaxDenyRateDelta:  0.05,
		ObservationWindow: 0, // immediate for testing
		MinSampleSize:     10,
		AutoRollback:      true,
	})

	// Baseline: 10% deny rate
	for i := range 100 {
		ca.RecordDecision("canary-1", false, i < 10)
	}
	// Canary: 11% deny rate (within 5% threshold)
	for i := range 100 {
		ca.RecordDecision("canary-1", true, i < 11)
	}

	metrics, rolled := ca.Evaluate("canary-1")
	if rolled {
		t.Error("should not rollback for minor difference")
	}
	if metrics.Verdict != "healthy" {
		t.Errorf("expected healthy, got %s", metrics.Verdict)
	}
}

func TestCanaryRollback(t *testing.T) {
	rm, ca := setupCanaryTest(t)

	_, err := rm.CreateRollout(RolloutConfig{
		ID:            "canary-2",
		PolicyID:      "canary-policy",
		TargetVersion: 2,
		Percentage:    10,
	})
	if err != nil {
		t.Fatal(err)
	}

	ca.Configure("canary-2", CanaryConfig{
		MaxDenyRateDelta:  0.05,
		ObservationWindow: 0,
		MinSampleSize:     10,
		AutoRollback:      true,
	})

	// Baseline: 5% deny rate
	for i := range 100 {
		ca.RecordDecision("canary-2", false, i < 5)
	}
	// Canary: 20% deny rate (15% delta, exceeds 5% threshold)
	for i := range 100 {
		ca.RecordDecision("canary-2", true, i < 20)
	}

	metrics, rolled := ca.Evaluate("canary-2")
	if !rolled {
		t.Error("expected rollback for high deny rate delta")
	}
	if metrics.Verdict != "rolled-back" {
		t.Errorf("expected rolled-back, got %s", metrics.Verdict)
	}

	// Verify the rollout was actually aborted
	state, ok := rm.GetRollout("canary-2")
	if !ok {
		t.Fatal("rollout not found")
	}
	if state.Status != "aborted" {
		t.Errorf("expected rollout status=aborted, got %s", state.Status)
	}
}

func TestCanaryDegradedNoAutoRollback(t *testing.T) {
	rm, ca := setupCanaryTest(t)

	_, _ = rm.CreateRollout(RolloutConfig{
		ID:            "canary-3",
		PolicyID:      "canary-policy",
		TargetVersion: 2,
		Percentage:    10,
	})

	ca.Configure("canary-3", CanaryConfig{
		MaxDenyRateDelta:  0.05,
		ObservationWindow: 0,
		MinSampleSize:     10,
		AutoRollback:      false, // no auto-rollback
	})

	for i := range 100 {
		ca.RecordDecision("canary-3", false, i < 5)
	}
	for i := range 100 {
		ca.RecordDecision("canary-3", true, i < 20)
	}

	metrics, rolled := ca.Evaluate("canary-3")
	if rolled {
		t.Error("should not auto-rollback when disabled")
	}
	if metrics.Verdict != "degraded" {
		t.Errorf("expected degraded, got %s", metrics.Verdict)
	}

	// Rollout should still be active
	state, _ := rm.GetRollout("canary-3")
	if state.Status != "active" {
		t.Errorf("expected rollout still active, got %s", state.Status)
	}
}

func TestCanaryPendingInsufficientSamples(t *testing.T) {
	rm, ca := setupCanaryTest(t)

	_, _ = rm.CreateRollout(RolloutConfig{
		ID:            "canary-4",
		PolicyID:      "canary-policy",
		TargetVersion: 2,
		Percentage:    10,
	})

	ca.Configure("canary-4", CanaryConfig{
		MaxDenyRateDelta:  0.05,
		ObservationWindow: 0,
		MinSampleSize:     100,
		AutoRollback:      true,
	})

	// Only 5 samples each (below MinSampleSize=100)
	for range 5 {
		ca.RecordDecision("canary-4", false, true)
		ca.RecordDecision("canary-4", true, true)
	}

	metrics, rolled := ca.Evaluate("canary-4")
	if rolled {
		t.Error("should not rollback with insufficient samples")
	}
	if metrics.Verdict != "pending" {
		t.Errorf("expected pending, got %s", metrics.Verdict)
	}
}

func TestCanaryPendingObservationWindow(t *testing.T) {
	rm, ca := setupCanaryTest(t)

	// Use a fixed clock for testing
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	ca.clock = func() time.Time { return now }

	_, _ = rm.CreateRollout(RolloutConfig{
		ID:            "canary-5",
		PolicyID:      "canary-policy",
		TargetVersion: 2,
		Percentage:    10,
	})

	ca.Configure("canary-5", CanaryConfig{
		MaxDenyRateDelta:  0.05,
		ObservationWindow: 5 * time.Minute,
		MinSampleSize:     10,
		AutoRollback:      true,
	})

	// Record enough samples
	for i := range 100 {
		ca.RecordDecision("canary-5", false, i < 5)
		ca.RecordDecision("canary-5", true, i < 50)
	}

	// Still within observation window
	metrics, rolled := ca.Evaluate("canary-5")
	if rolled {
		t.Error("should not rollback before observation window completes")
	}
	if metrics.Verdict != "pending" {
		t.Errorf("expected pending, got %s", metrics.Verdict)
	}

	// Advance time past observation window
	now = now.Add(6 * time.Minute)
	metrics, rolled = ca.Evaluate("canary-5")
	if !rolled {
		t.Error("expected rollback after observation window")
	}
	if metrics.Verdict != "rolled-back" {
		t.Errorf("expected rolled-back, got %s", metrics.Verdict)
	}
}

func TestCanaryReset(t *testing.T) {
	rm, ca := setupCanaryTest(t)

	_, _ = rm.CreateRollout(RolloutConfig{
		ID:            "canary-6",
		PolicyID:      "canary-policy",
		TargetVersion: 2,
		Percentage:    10,
	})

	ca.Configure("canary-6", CanaryConfig{
		MaxDenyRateDelta:  0.05,
		ObservationWindow: 0,
		MinSampleSize:     10,
		AutoRollback:      true,
	})

	for range 50 {
		ca.RecordDecision("canary-6", false, false)
		ca.RecordDecision("canary-6", true, true)
	}

	ca.Reset("canary-6")

	metrics, _ := ca.Evaluate("canary-6")
	if metrics.Verdict != "pending" {
		t.Errorf("expected pending after reset, got %s", metrics.Verdict)
	}
}

func TestCanaryMetricsAccuracy(t *testing.T) {
	rm, ca := setupCanaryTest(t)

	_, _ = rm.CreateRollout(RolloutConfig{
		ID:            "canary-7",
		PolicyID:      "canary-policy",
		TargetVersion: 2,
		Percentage:    10,
	})

	ca.Configure("canary-7", CanaryConfig{
		MaxDenyRateDelta:  0.50,
		ObservationWindow: 0,
		MinSampleSize:     10,
		AutoRollback:      true,
	})

	// 20 baseline events, 5 denied = 25% deny rate
	for i := range 20 {
		ca.RecordDecision("canary-7", false, i < 5)
	}
	// 40 canary events, 12 denied = 30% deny rate
	for i := range 40 {
		ca.RecordDecision("canary-7", true, i < 12)
	}

	metrics := ca.Metrics("canary-7")
	if metrics.BaselineSamples != 20 {
		t.Errorf("expected 20 baseline samples, got %d", metrics.BaselineSamples)
	}
	if metrics.CanarySamples != 40 {
		t.Errorf("expected 40 canary samples, got %d", metrics.CanarySamples)
	}
	if metrics.BaselineDenyRate != 0.25 {
		t.Errorf("expected 0.25 baseline deny rate, got %f", metrics.BaselineDenyRate)
	}
	if metrics.CanaryDenyRate != 0.30 {
		t.Errorf("expected 0.30 canary deny rate, got %f", metrics.CanaryDenyRate)
	}
}

func TestCanaryIdempotentAfterRollback(t *testing.T) {
	rm, ca := setupCanaryTest(t)

	_, _ = rm.CreateRollout(RolloutConfig{
		ID:            "canary-8",
		PolicyID:      "canary-policy",
		TargetVersion: 2,
		Percentage:    10,
	})

	ca.Configure("canary-8", CanaryConfig{
		MaxDenyRateDelta:  0.05,
		ObservationWindow: 0,
		MinSampleSize:     10,
		AutoRollback:      true,
	})

	for i := range 100 {
		ca.RecordDecision("canary-8", false, i < 5)
		ca.RecordDecision("canary-8", true, i < 30)
	}

	_, rolled1 := ca.Evaluate("canary-8")
	if !rolled1 {
		t.Fatal("expected first rollback")
	}

	// Second evaluate should not trigger another rollback
	_, rolled2 := ca.Evaluate("canary-8")
	if rolled2 {
		t.Error("second evaluate should not trigger rollback again")
	}
}

func TestCanaryUnconfigured(t *testing.T) {
	_, ca := setupCanaryTest(t)

	if m := ca.Metrics("never-seen"); m.Verdict != "pending" || m.CanarySamples != 0 {
		t.Errorf("expected empty pending metrics, got %+v", m)
	}
	if m, rolledBack := ca.Evaluate("never-seen"); m.Verdict != "pending" || rolledBack {
		t.Errorf("expected pending without config, got %+v %v", m, rolledBack)
	}

	// Unconfigured input cannot allocate state or contribute to later verdicts.
	ca.RecordDecision("lazy", true, true)
	ca.RecordDecision("lazy", false, false)
	m := ca.Metrics("lazy")
	if m.CanarySamples != 0 || m.BaselineSamples != 0 {
		t.Errorf("unconfigured input must be ignored: %+v", m)
	}
	if m, _ := ca.Evaluate("lazy"); m.Verdict != "pending" {
		t.Errorf("expected pending for unconfigured rollout, got %s", m.Verdict)
	}

	if len(ca.counters) != 0 {
		t.Fatal("unconfigured input allocated counters")
	}
	if err := ca.Configure("lazy", CanaryConfig{MinSampleSize: 1}); err != nil {
		t.Fatal(err)
	}
	if m := ca.Metrics("lazy"); m.CanarySamples != 0 {
		t.Errorf("Configure must not inherit unconfigured decisions: %+v", m)
	}
}

func assertFiniteCanaryMetrics(t *testing.T, m CanaryMetrics) {
	t.Helper()
	for _, rate := range []float64{m.BaselineDenyRate, m.CanaryDenyRate} {
		if math.IsNaN(rate) || math.IsInf(rate, 0) || rate < 0 || rate > 1 {
			t.Fatalf("invalid deny rate: %+v", m)
		}
	}
	if m.ObservedFor < 0 || m.BaselineSamples < 0 || m.CanarySamples < 0 {
		t.Fatalf("negative metrics: %+v", m)
	}
	if _, err := json.Marshal(m); err != nil {
		t.Fatalf("metrics are not JSON safe: %v", err)
	}
}

func mustConfigureCanary(t *testing.T, ca *CanaryAnalyzer, id string, cfg CanaryConfig) {
	t.Helper()
	if err := ca.Configure(id, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestCanaryConfigValidation(t *testing.T) {
	valid := CanaryConfig{MaxDenyRateDelta: 0.1, MinSampleSize: 1}
	tests := []struct {
		name string
		edit func(*CanaryConfig)
	}{
		{"nan", func(c *CanaryConfig) { c.MaxDenyRateDelta = math.NaN() }},
		{"positive infinity", func(c *CanaryConfig) { c.MaxDenyRateDelta = math.Inf(1) }},
		{"negative infinity", func(c *CanaryConfig) { c.MaxDenyRateDelta = math.Inf(-1) }},
		{"negative delta", func(c *CanaryConfig) { c.MaxDenyRateDelta = -0.01 }},
		{"delta above one", func(c *CanaryConfig) { c.MaxDenyRateDelta = 1.01 }},
		{"zero samples", func(c *CanaryConfig) { c.MinSampleSize = 0 }},
		{"negative samples", func(c *CanaryConfig) { c.MinSampleSize = -1 }},
		{"negative observation", func(c *CanaryConfig) { c.ObservationWindow = -1 }},
		{"negative retention", func(c *CanaryConfig) { c.SampleWindow = -1 }},
		{"unbounded retention", func(c *CanaryConfig) { c.SampleWindow = time.Duration(math.MaxInt64) }},
		{"observation beyond retention", func(c *CanaryConfig) { c.ObservationWindow = DefaultCanarySampleWindow + 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := NewCanaryAnalyzer(nil)
			cfg := valid
			tt.edit(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid config passed Validate")
			}
			if err := ca.Configure("bad", cfg); err == nil {
				t.Fatal("invalid config passed Configure")
			}
			ca.RecordDecision("bad", true, true)
			m, rolled := ca.Evaluate("bad")
			if m.Verdict != "pending" || rolled || len(ca.configs) != 0 || len(ca.counters) != 0 {
				t.Fatalf("invalid config changed state: %+v, rolled=%v", m, rolled)
			}
			assertFiniteCanaryMetrics(t, m)
		})
	}
	for _, id := range []string{"", " \t\n"} {
		if err := NewCanaryAnalyzer(nil).Configure(id, valid); err == nil {
			t.Errorf("empty rollout ID %q accepted", id)
		}
	}
	for _, delta := range []float64{0, 1} {
		cfg := valid
		cfg.MaxDenyRateDelta = delta
		cfg.SampleWindow = MaxCanarySampleWindow
		cfg.ObservationWindow = MaxCanarySampleWindow
		if err := cfg.Validate(); err != nil {
			t.Errorf("valid boundary config rejected: %v", err)
		}
	}
}

func TestCanaryReconfiguration(t *testing.T) {
	ca := NewCanaryAnalyzer(nil)
	now := time.Unix(1000, 0)
	ca.clock = func() time.Time { return now }
	cfg := CanaryConfig{MaxDenyRateDelta: 0.1, MinSampleSize: 1, ObservationWindow: time.Minute}
	mustConfigureCanary(t, ca, "r", cfg)
	ca.RecordDecision("r", false, false)
	ca.RecordDecision("r", true, true)
	now = now.Add(2 * time.Minute)
	invalid := cfg
	invalid.MinSampleSize = 0
	if err := ca.Configure("r", invalid); err == nil {
		t.Fatal("invalid reconfiguration succeeded")
	}
	// Explicit default retention is semantically identical to zero.
	cfg.SampleWindow = DefaultCanarySampleWindow
	mustConfigureCanary(t, ca, "r", cfg)
	if m, _ := ca.Evaluate("r"); m.Verdict != "degraded" || m.CanarySamples != 1 {
		t.Fatalf("invalid/identical configuration changed observation: %+v", m)
	}
	cfg.MaxDenyRateDelta = 0.2
	mustConfigureCanary(t, ca, "r", cfg)
	if m, _ := ca.Evaluate("r"); m.Verdict != "pending" || m.CanarySamples != 0 || m.ObservedFor != 0 {
		t.Fatalf("changed configuration retained old evidence: %+v", m)
	}
	// Idle configured time must not satisfy the observation requirement.
	now = now.Add(time.Hour)
	ca.RecordDecision("r", false, false)
	ca.RecordDecision("r", true, true)
	if m, _ := ca.Evaluate("r"); m.Verdict != "pending" || m.ObservedFor != 0 {
		t.Fatalf("idle time counted as observation: %+v", m)
	}
}

func TestCanaryRollingWindow(t *testing.T) {
	ca := NewCanaryAnalyzer(nil)
	now := time.Unix(1000, 0)
	ca.clock = func() time.Time { return now }
	cfg := CanaryConfig{MaxDenyRateDelta: 0.1, MinSampleSize: 2, SampleWindow: 128 * time.Second, ObservationWindow: 10 * time.Second}
	mustConfigureCanary(t, ca, "r", cfg)
	for range 2 {
		ca.RecordDecision("r", false, false)
		ca.RecordDecision("r", true, true)
	}
	now = now.Add(10 * time.Second)
	if m, _ := ca.Evaluate("r"); m.Verdict != "degraded" || m.ObservedFor != 10*time.Second {
		t.Fatalf("expected degraded at observation boundary: %+v", m)
	}
	now = now.Add(cfg.SampleWindow - 10*time.Second)
	if m := ca.Metrics("r"); m.CanarySamples != 0 || m.BaselineSamples != 0 || m.ObservedFor != 0 {
		t.Fatalf("samples at retention boundary did not expire: %+v", m)
	}
	for range 2 {
		ca.RecordDecision("r", false, false)
		ca.RecordDecision("r", true, false)
	}
	if m, _ := ca.Evaluate("r"); m.Verdict != "pending" || m.ObservedFor != 0 {
		t.Fatalf("expired observation age reused: %+v", m)
	}
	now = now.Add(10 * time.Second)
	if m, _ := ca.Evaluate("r"); m.Verdict != "healthy" || m.CanaryDenyRate != 0 {
		t.Fatalf("old degraded samples contaminated fresh window: %+v", m)
	}
	// Keep fresh samples arriving for many complete windows. Memory and reported
	// observation duration must stay bounded; counts cannot accumulate forever.
	for range 1000 {
		now = now.Add(time.Second)
		ca.RecordDecision("r", false, false)
		ca.RecordDecision("r", true, false)
		m := ca.Metrics("r")
		if m.CanarySamples > 128 || m.BaselineSamples > 128 || m.ObservedFor > cfg.SampleWindow {
			t.Fatalf("rolling window is not bounded: %+v", m)
		}
		assertFiniteCanaryMetrics(t, m)
	}
	now = now.Add(time.Duration(math.MaxInt64))
	if m, _ := ca.Evaluate("r"); m.Verdict != "pending" || m.CanarySamples != 0 {
		t.Fatalf("large clock jump retained samples: %+v", m)
	}
}

func TestCanarySubBucketExpiryAndBackwardClock(t *testing.T) {
	ca := NewCanaryAnalyzer(nil)
	now := time.Unix(1000, 0)
	ca.clock = func() time.Time { return now }
	cfg := CanaryConfig{MinSampleSize: 1, SampleWindow: 128 * time.Second}
	mustConfigureCanary(t, ca, "r", cfg)
	ca.RecordDecision("r", false, false)
	now = now.Add(500 * time.Millisecond)
	ca.RecordDecision("r", true, true)
	now = now.Add(-time.Hour)
	ca.RecordDecision("r", true, false)
	m, _ := ca.Evaluate("r")
	if m.CanarySamples != 2 || m.CanaryDenyRate != 0.5 || m.ObservedFor != 500*time.Millisecond {
		t.Fatalf("backwards clock corrupted metrics: %+v", m)
	}
	assertFiniteCanaryMetrics(t, m)
	// Whole-bucket expiry is conservative: never retain a sample too long.
	now = time.Unix(1000, 0).Add(cfg.SampleWindow)
	if m := ca.Metrics("r"); m.CanarySamples != 0 || m.BaselineSamples != 0 {
		t.Fatalf("expired bucket retained samples: %+v", m)
	}
	// A tiny positive window must not divide by zero or create a negative index.
	cfg.SampleWindow = time.Nanosecond
	mustConfigureCanary(t, ca, "r", cfg)
	ca.RecordDecision("r", false, false)
	ca.RecordDecision("r", true, true)
	if m, _ := ca.Evaluate("r"); m.Verdict != "degraded" {
		t.Fatalf("tiny window failed: %+v", m)
	}
	now = now.Add(time.Nanosecond)
	if m := ca.Metrics("r"); m.CanarySamples != 0 {
		t.Fatalf("tiny window did not expire: %+v", m)
	}
}

type canaryTestAborter struct {
	calls int
	err   error
}

func (a *canaryTestAborter) AbortRollout(string) error {
	a.calls++
	return a.err
}

func TestCanaryAbortFailureAndRetry(t *testing.T) {
	ca := NewCanaryAnalyzer(nil)
	aborter := &canaryTestAborter{err: errors.New("persist abort: disk full")}
	ca.rollouts = aborter
	cfg := CanaryConfig{MinSampleSize: 1, AutoRollback: true}
	mustConfigureCanary(t, ca, "r", cfg)
	ca.RecordDecision("r", false, false)
	ca.RecordDecision("r", true, true)
	for range 2 {
		m, rolled := ca.Evaluate("r")
		if rolled || m.Verdict != "degraded" || m.RollbackError != aborter.err.Error() {
			t.Fatalf("phantom successful rollback: %+v, rolled=%v", m, rolled)
		}
		if m := ca.Metrics("r"); m.Verdict == "rolled-back" || m.RollbackError == "" {
			t.Fatalf("metrics lost abort failure: %+v", m)
		}
	}
	if aborter.calls != 2 {
		t.Fatalf("failed abort was latched: calls=%d", aborter.calls)
	}
	aborter.err = nil
	if m, rolled := ca.Evaluate("r"); !rolled || m.Verdict != "rolled-back" || m.RollbackError != "" {
		t.Fatalf("successful retry not reported: %+v, rolled=%v", m, rolled)
	}
	cfg.MaxDenyRateDelta = 0.5
	mustConfigureCanary(t, ca, "r", cfg)
	if m, rolled := ca.Evaluate("r"); rolled || m.Verdict != "rolled-back" || aborter.calls != 3 {
		t.Fatalf("successful abort was not latched across configuration: %+v", m)
	}
	ca.Reset("r")
	if m := ca.Metrics("r"); m.Verdict != "pending" || m.RollbackError != "" {
		t.Fatalf("Reset retained abort state: %+v", m)
	}
}

func TestCanaryAbortMissingOrInactiveRollout(t *testing.T) {
	for _, status := range []string{"missing", "completed", "aborted", "nil manager"} {
		t.Run(status, func(t *testing.T) {
			rm, ca := setupCanaryTest(t)
			if status == "nil manager" {
				ca = NewCanaryAnalyzer(nil)
			} else if status != "missing" {
				if _, err := rm.CreateRollout(RolloutConfig{ID: "r", PolicyID: "canary-policy", TargetVersion: 2, Percentage: 10}); err != nil {
					t.Fatal(err)
				}
				var err error
				if status == "completed" {
					err = rm.CompleteRollout("r")
				} else {
					err = rm.AbortRollout("r")
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			mustConfigureCanary(t, ca, "r", CanaryConfig{MinSampleSize: 1, AutoRollback: true})
			ca.RecordDecision("r", false, false)
			ca.RecordDecision("r", true, true)
			if m, rolled := ca.Evaluate("r"); rolled || m.Verdict != "degraded" || m.RollbackError == "" {
				t.Fatalf("unsuccessful abort reported as success: %+v, rolled=%v", m, rolled)
			}
		})
	}
}

func TestCanarySampleOverflow(t *testing.T) {
	for _, mode := range []string{"bucket", "sum"} {
		t.Run(mode, func(t *testing.T) {
			ca := NewCanaryAnalyzer(nil)
			now := time.Unix(1000, 0)
			ca.clock = func() time.Time { return now }
			mustConfigureCanary(t, ca, "r", CanaryConfig{MinSampleSize: 1, AutoRollback: true})
			ca.RecordDecision("r", false, false)
			ca.RecordDecision("r", true, true)
			b := &ca.counters["r"].buckets[0]
			b.canaryTotal, b.canaryDeny = int(^uint(0)>>1), int(^uint(0)>>1)
			if mode == "sum" {
				now = now.Add(time.Minute)
			}
			ca.RecordDecision("r", true, true)
			m, rolled := ca.Evaluate("r")
			if rolled || m.Verdict != "pending" || !m.SampleOverflow || m.CanarySamples != 0 || m.BaselineSamples != 0 {
				t.Fatalf("overflow produced a health/rollback verdict: %+v", m)
			}
			assertFiniteCanaryMetrics(t, m)
			now = now.Add(DefaultCanarySampleWindow)
			ca.RecordDecision("r", false, false)
			ca.RecordDecision("r", true, false)
			if m, _ := ca.Evaluate("r"); m.SampleOverflow || m.Verdict != "healthy" {
				t.Fatalf("expired overflow poisoned new window: %+v", m)
			}
		})
	}
}

func TestCanaryConcurrentDecisionsAndEvaluation(t *testing.T) {
	ca := NewCanaryAnalyzer(nil)
	fixed := time.Unix(1000, 0)
	ca.clock = func() time.Time { return fixed }
	mustConfigureCanary(t, ca, "r", CanaryConfig{MinSampleSize: 1})
	var wg sync.WaitGroup
	for worker := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 1000 {
				ca.RecordDecision("r", worker%2 == 0, i%4 == 0)
				if i%20 == 0 {
					m, _ := ca.Evaluate("r")
					assertFiniteCanaryMetrics(t, m)
				}
			}
		}()
	}
	wg.Wait()
	m := ca.Metrics("r")
	if m.CanarySamples != 6000 || m.BaselineSamples != 6000 || m.CanaryDenyRate != 0.25 || m.BaselineDenyRate != 0.25 {
		t.Fatalf("concurrent decisions lost or duplicated: %+v", m)
	}
}

func TestCanaryConcurrentRollbackExactlyOnce(t *testing.T) {
	_, ca := setupCanaryTest(t)
	aborter := &canaryTestAborter{}
	ca.rollouts = aborter
	mustConfigureCanary(t, ca, "r", CanaryConfig{MinSampleSize: 1, AutoRollback: true})
	ca.RecordDecision("r", false, false)
	ca.RecordDecision("r", true, true)
	var wg sync.WaitGroup
	var successes atomic.Int32
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, rolled := ca.Evaluate("r")
			if rolled {
				successes.Add(1)
			}
			if m.Verdict != "rolled-back" {
				t.Errorf("unexpected concurrent verdict: %+v", m)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || aborter.calls != 1 {
		t.Fatalf("abort was not exactly once: successes=%d calls=%d", successes.Load(), aborter.calls)
	}
}

func TestCanaryConcurrentResetAndConfiguration(t *testing.T) {
	ca := NewCanaryAnalyzer(nil)
	cfg := CanaryConfig{MinSampleSize: 1}
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				switch worker % 4 {
				case 0:
					mustConfigureCanary(t, ca, "r", cfg)
				case 1:
					ca.Reset("r")
				case 2:
					ca.RecordDecision("r", true, true)
					ca.RecordDecision("r", false, false)
				case 3:
					m, _ := ca.Evaluate("r")
					assertFiniteCanaryMetrics(t, m)
					assertFiniteCanaryMetrics(t, ca.Metrics("r"))
				}
			}
		}()
	}
	wg.Wait()
	ca.Reset("r")
	if m := ca.Metrics("r"); m.Verdict != "pending" || m.CanarySamples != 0 {
		t.Fatalf("final reset failed: %+v", m)
	}
}

func TestCanaryMetricsAfterRollback(t *testing.T) {
	rm, ca := setupCanaryTest(t)
	_, _ = rm.CreateRollout(RolloutConfig{ID: "rb", PolicyID: "canary-policy", TargetVersion: 2, Percentage: 50})
	ca.Configure("rb", CanaryConfig{MaxDenyRateDelta: 0.1, MinSampleSize: 1, AutoRollback: true})
	ca.RecordDecision("rb", false, false)
	ca.RecordDecision("rb", true, true)

	if _, rolledBack := ca.Evaluate("rb"); !rolledBack {
		t.Fatal("expected rollback")
	}
	if m := ca.Metrics("rb"); m.Verdict != "rolled-back" {
		t.Errorf("expected Metrics to report rolled-back, got %s", m.Verdict)
	}
	if state, _ := rm.GetRollout("rb"); state.Status != "aborted" {
		t.Errorf("expected rollout aborted by canary, got %s", state.Status)
	}
	// Aborted rollout no longer selects the canary version.
	if rm.ShouldUseNewVersion("rb", "any-agent") {
		t.Error("aborted rollout must not route agents to the canary")
	}
}
