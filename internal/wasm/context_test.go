package wasm

import (
	"context"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/pkg/api"
)

// newTestEvaluator is a helper that builds a PolicyEvaluator backed by the fixture.
func newTestEvaluator(t *testing.T, poolSize int) (*PolicyEvaluator, *Runtime) {
	t.Helper()
	ctx := context.Background()
	rt := newTestRuntime(t)

	pool, err := NewPool(ctx, rt, poolSize)
	if err != nil {
		rt.Close(ctx)
		t.Fatalf("NewPool: %v", err)
	}

	return NewPolicyEvaluator(pool, "test-host"), rt
}

// ---- NewPolicyEvaluator ----

func TestNewPolicyEvaluator_NotNil(t *testing.T) {
	ctx := context.Background()
	ev, rt := newTestEvaluator(t, 1)
	defer rt.Close(ctx)
	defer ev.Close(ctx)

	if ev == nil {
		t.Fatal("NewPolicyEvaluator returned nil")
	}
}

// ---- PolicyEvaluator.Evaluate ----

func TestPolicyEvaluator_Evaluate_Allow(t *testing.T) {
	ctx := context.Background()
	ev, rt := newTestEvaluator(t, 1)
	defer rt.Close(ctx)
	defer ev.Close(ctx)

	event := &api.Event{
		PID:      1,
		UID:      1000,
		GID:      1000,
		Comm:     "ls",
		Filename: "/bin/ls",
		Type:     api.EventTypeProcess,
	}

	result, err := ev.Evaluate(ctx, event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if result.Action != api.ActionAllow {
		t.Errorf("Action = %v, want ActionAllow", result.Action)
	}
	if result.Cached {
		t.Error("Cached should be false for a direct evaluation")
	}
	if result.Latency <= 0 {
		t.Error("Latency should be positive")
	}
	if result.Audit {
		t.Error("Audit should be false for a plain ALLOW")
	}
}

func TestPolicyEvaluator_Evaluate_Deny(t *testing.T) {
	ctx := context.Background()
	ev, rt := newTestEvaluator(t, 1)
	defer rt.Close(ctx)
	defer ev.Close(ctx)

	event := &api.Event{
		PID:      2,
		UID:      0,
		GID:      0,
		Comm:     "bash",
		Filename: "/bin/bash",
		Type:     api.EventTypeProcess,
	}

	result, err := ev.Evaluate(ctx, event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if result.Action != api.ActionDeny {
		t.Errorf("Action = %v, want ActionDeny", result.Action)
	}
	if result.Reason == "" {
		t.Error("Reason should be non-empty for a deny decision")
	}
}

func TestPolicyEvaluator_Evaluate_Log(t *testing.T) {
	ctx := context.Background()
	ev, rt := newTestEvaluator(t, 1)
	defer rt.Close(ctx)
	defer ev.Close(ctx)

	event := &api.Event{
		PID:      3,
		UID:      1000,
		Comm:     "python3",
		Filename: "/usr/bin/python3",
		Type:     api.EventTypeProcess,
	}

	result, err := ev.Evaluate(ctx, event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if result.Action != api.ActionLog {
		t.Errorf("Action = %v, want ActionLog", result.Action)
	}
	if result.Reason == "" {
		t.Error("Reason should be non-empty for a log decision")
	}
}

// TestPolicyEvaluator_Evaluate_ResultTimestamp verifies the result timestamp is
// populated and close to now.
func TestPolicyEvaluator_Evaluate_ResultTimestamp(t *testing.T) {
	ctx := context.Background()
	ev, rt := newTestEvaluator(t, 1)
	defer rt.Close(ctx)
	defer ev.Close(ctx)

	event := &api.Event{UID: 1000, Comm: "ls", Filename: "/bin/ls", Type: api.EventTypeProcess}

	result, err := ev.Evaluate(ctx, event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if result.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

// TestPolicyEvaluator_Evaluate_CancelledContext verifies the evaluator returns
// an error when the context is cancelled before it can acquire a pool instance.
func TestPolicyEvaluator_Evaluate_CancelledContext(t *testing.T) {
	ctx := context.Background()
	// Pool size = 1; drain it first so the evaluator blocks on Get.
	ev, rt := newTestEvaluator(t, 1)
	defer rt.Close(ctx)
	defer ev.Close(ctx)

	// Drain the pool manually.
	pool := ev.pool
	pol, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("pre-drain Get: %v", err)
	}
	defer pool.Put(pol)

	// Now try to Evaluate with a cancelled context.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	_, err = ev.Evaluate(cancelled, &api.Event{UID: 1000, Type: api.EventTypeProcess})
	if err == nil {
		t.Fatal("expected error with cancelled context, got nil")
	}
}

// ---- buildReason ----

func TestPolicyEvaluator_BuildReason_Allow(t *testing.T) {
	ctx := context.Background()
	ev, rt := newTestEvaluator(t, 1)
	defer rt.Close(ctx)
	defer ev.Close(ctx)

	event := &api.Event{UID: 1000, Filename: "/bin/ls"}
	reason := ev.buildReason(api.ActionAllow, event)
	if reason == "" {
		t.Error("buildReason(Allow) returned empty string")
	}
}

func TestPolicyEvaluator_BuildReason_Deny(t *testing.T) {
	ctx := context.Background()
	ev, rt := newTestEvaluator(t, 1)
	defer rt.Close(ctx)
	defer ev.Close(ctx)

	event := &api.Event{UID: 0, Filename: "/bin/bash"}
	reason := ev.buildReason(api.ActionDeny, event)
	if reason == "" {
		t.Error("buildReason(Deny) returned empty string")
	}
	// Reason should reference the file and UID.
	if !strings.Contains(reason, "/bin/bash") {
		t.Errorf("buildReason(Deny) = %q, expected it to mention the filename", reason)
	}
}

func TestPolicyEvaluator_BuildReason_Log(t *testing.T) {
	ctx := context.Background()
	ev, rt := newTestEvaluator(t, 1)
	defer rt.Close(ctx)
	defer ev.Close(ctx)

	event := &api.Event{UID: 1000, Filename: "/usr/bin/python3"}
	reason := ev.buildReason(api.ActionLog, event)
	if reason == "" {
		t.Error("buildReason(Log) returned empty string")
	}
}

func TestPolicyEvaluator_BuildReason_Unknown(t *testing.T) {
	ctx := context.Background()
	ev, rt := newTestEvaluator(t, 1)
	defer rt.Close(ctx)
	defer ev.Close(ctx)

	event := &api.Event{UID: 1000}
	reason := ev.buildReason(api.Action(99), event)
	if reason == "" {
		t.Error("buildReason(unknown action) should return a non-empty fallback string")
	}
}

// ---- ActionAuditDeny mapping ----

// TestActionAuditDeny_Value verifies the constant matches the documented WASM ABI value.
func TestActionAuditDeny_Value(t *testing.T) {
	if ActionAuditDeny != api.Action(3) {
		t.Errorf("ActionAuditDeny = %d, want 3", ActionAuditDeny)
	}
}

// ---- PolicyEvaluator.Close ----

func TestPolicyEvaluator_Close(t *testing.T) {
	ctx := context.Background()
	ev, rt := newTestEvaluator(t, 2)
	defer rt.Close(ctx)

	if err := ev.Close(ctx); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}
