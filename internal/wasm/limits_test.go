package wasm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

// within fails the test instead of hanging if f does not return in time.
func within(t *testing.T, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("did not return within %v (looping policy hung the caller)", d)
	}
}

func TestEvaluate_LoopingPolicyTimesOut(t *testing.T) {
	pool := newPoolFromBytes(t, wasmtest.LoopPolicy(), 1)
	ev := NewPolicyEvaluator(pool, "h")
	ev.SetTimeout(20 * time.Millisecond)

	within(t, 5*time.Second, func() {
		start := time.Now()
		res, err := ev.Evaluate(context.Background(), &api.Event{UID: 1})
		if !errors.Is(err, ErrEvaluationTimeout) {
			t.Errorf("Evaluate = %+v, %v; want ErrEvaluationTimeout", res, err)
		}
		if el := time.Since(start); el > 2*time.Second {
			t.Errorf("timeout took %v", el)
		}
	})
}

func TestEvaluate_TimedOutInstanceIsReplaced(t *testing.T) {
	// uid 0 loops forever; anything else is allowed.
	pool := newPoolFromBytes(t, wasmtest.LoopOnUIDPolicy(), 1)
	ev := NewPolicyEvaluator(pool, "h")
	ev.SetTimeout(20 * time.Millisecond)

	within(t, 10*time.Second, func() {
		for i := 0; i < 3; i++ {
			if _, err := ev.Evaluate(context.Background(), &api.Event{UID: 0}); !errors.Is(err, ErrEvaluationTimeout) {
				t.Fatalf("round %d: err = %v, want timeout", i, err)
			}
			// The only instance was closed by the timeout; a working one
			// must have taken its place.
			res, err := ev.Evaluate(context.Background(), &api.Event{UID: 1000})
			if err != nil || res.Action != api.ActionAllow {
				t.Fatalf("round %d: after timeout Evaluate = %+v, %v; want allow", i, res, err)
			}
		}
	})
	if got := len(pool.instances); got != 1 {
		t.Errorf("pool holds %d idle instances, want 1", got)
	}
}

func TestEvaluate_DefaultTimeout(t *testing.T) {
	ev := NewPolicyEvaluator(nil, "h")
	if ev.Timeout() != DefaultEvalTimeout {
		t.Fatalf("Timeout = %v, want %v", ev.Timeout(), DefaultEvalTimeout)
	}
	ev.SetTimeout(0)
	if ev.Timeout() != DefaultEvalTimeout {
		t.Fatal("non-positive timeout must restore the default, never disable it")
	}
	ev.SetTimeout(time.Second)
	if ev.Timeout() != time.Second {
		t.Fatal("SetTimeout ignored")
	}
}

func TestRuntime_MemoryLimit(t *testing.T) {
	slowOK := func(p *Pool) *PolicyEvaluator {
		ev := NewPolicyEvaluator(p, "h")
		ev.SetTimeout(10 * time.Second) // growing memory is slow under -race
		return ev
	}
	// The policy asks for 300 more pages (~19 MiB) and denies if refused.
	pool := newPoolFromBytes(t, wasmtest.GrowPolicy(300), 1)
	res, err := slowOK(pool).Evaluate(context.Background(), &api.Event{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != api.ActionDeny {
		t.Fatalf("memory.grow beyond the default %d-page limit succeeded", DefaultMemoryLimitPages)
	}

	// A larger configured limit lets the same growth succeed.
	pool = newPoolFromBytes(t, wasmtest.GrowPolicy(300), 1, RuntimeConfig{MemoryLimitPages: 1024})
	res, err = slowOK(pool).Evaluate(context.Background(), &api.Event{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != api.ActionAllow {
		t.Fatal("growth within the configured limit was refused")
	}
}
