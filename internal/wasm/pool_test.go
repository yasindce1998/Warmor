package wasm

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/yasindce1998/warmor/pkg/api"
)

// ---- NewPool ----

func TestNewPool_Success(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)

	pool, err := NewPool(ctx, rt, 3)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close(ctx)

	if pool.Size() != 3 {
		t.Errorf("Size() = %d, want 3", pool.Size())
	}
}

func TestNewPool_ZeroSizeDefaultsToOne(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)

	pool, err := NewPool(ctx, rt, 0)
	if err != nil {
		t.Fatalf("NewPool(size=0): %v", err)
	}
	defer pool.Close(ctx)

	if pool.Size() != 1 {
		t.Errorf("Size() = %d, want 1 (zero input defaults to 1)", pool.Size())
	}
}

// ---- Pool.Get / Pool.Put ----

func TestPool_GetPut_RoundTrip(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)

	pool, err := NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close(ctx)

	pol, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if pol == nil {
		t.Fatal("Get returned nil policy")
	}

	pool.Put(pol)

	// After Put we should be able to Get again.
	pol2, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if pol2 == nil {
		t.Fatal("second Get returned nil policy")
	}
	pool.Put(pol2)
}

func TestPool_Put_NilIsNoOp(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)

	pool, err := NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close(ctx)

	// Put(nil) must not panic.
	pool.Put(nil)
}

func TestPool_Get_CancelledContext(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)

	pool, err := NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close(ctx)

	// Drain the pool so Get will block.
	pol, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("initial Get: %v", err)
	}
	defer pool.Put(pol)

	// Now Get on a cancelled context should return an error immediately.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	_, err = pool.Get(cancelled)
	if err == nil {
		t.Fatal("expected error from Get with cancelled context, got nil")
	}
}

// ---- Pool.Close ----

func TestPool_Close_Empty(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)

	pool, err := NewPool(ctx, rt, 2)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}

	if err := pool.Close(ctx); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestPool_Close_Idempotent(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)

	pool, err := NewPool(ctx, rt, 2)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}

	if err := pool.Close(ctx); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := pool.Close(ctx); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestPool_GetAfterClose(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)

	pool, err := NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	pool.Close(ctx)

	policy, err := pool.Get(ctx)
	if !errors.Is(err, ErrPoolClosed) {
		t.Errorf("Get after Close: err = %v, want ErrPoolClosed", err)
	}
	if policy != nil {
		t.Error("Get after Close returned a non-nil policy")
	}
}

func TestPool_PutAfterClose(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)

	pool, err := NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	policy, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	pool.Close(ctx)

	// Returning a checked-out instance after Close must not panic.
	pool.Put(policy)
}

func TestEvaluator_EvaluateAfterClose(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)

	pool, err := NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	evaluator := NewPolicyEvaluator(pool, "test-host")
	evaluator.Close(ctx)

	if _, err := evaluator.Evaluate(ctx, &api.Event{Comm: "ls"}); !errors.Is(err, ErrPoolClosed) {
		t.Errorf("Evaluate after Close: err = %v, want ErrPoolClosed", err)
	}
}

// ---- Concurrent evaluation ----

func TestPool_ConcurrentEvaluation(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)

	const poolSize = 4
	const goroutines = 20
	const eventsPerGoroutine = 10

	pool, err := NewPool(ctx, rt, poolSize)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close(ctx)

	events := []*api.Event{
		{PID: 1, UID: 1000, Comm: "ls", Filename: "/bin/ls", Type: api.EventTypeProcess},
		{PID: 2, UID: 0, Comm: "bash", Filename: "/bin/bash", Type: api.EventTypeProcess},
		{PID: 3, UID: 1000, Comm: "python3", Filename: "/usr/bin/python3", Type: api.EventTypeProcess},
	}
	expected := []api.Action{api.ActionAllow, api.ActionDeny, api.ActionLog}

	var wg sync.WaitGroup
	errors := make(chan error, goroutines*eventsPerGoroutine)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				idx := i % len(events)
				pol, err := pool.Get(ctx)
				if err != nil {
					errors <- err
					return
				}
				action, err := pol.Evaluate(ctx, events[idx])
				pool.Put(pol)
				if err != nil {
					errors <- err
					return
				}
				if action != expected[idx] {
					errors <- nil // count mismatch separately
					t.Errorf("goroutine: action = %v, want %v", action, expected[idx])
				}
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		if err != nil {
			t.Errorf("concurrent error: %v", err)
		}
	}
}

// TestPool_ExcessPut verifies that Put on a full pool closes the extra instance
// without blocking or panicking.
func TestPool_ExcessPut(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)

	pool, err := NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close(ctx)

	// Get the single instance out to make room.
	pol, _ := pool.Get(ctx)

	// Instantiate an extra policy directly from the runtime.
	extra, err := NewPolicy(ctx, rt)
	if err != nil {
		t.Fatalf("NewPolicy for extra: %v", err)
	}

	// Put back the original — fills the pool.
	pool.Put(pol)

	// Putting the extra should trigger the overflow path (closes it silently).
	pool.Put(extra) // must not panic or block
}
