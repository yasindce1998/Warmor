package wasm

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestGeneratedAllocatorSteadyState(t *testing.T) {
	if testing.Short() || !compiler.CargoAvailable() {
		if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
			t.Fatal("cargo and wasm32 target required")
		}
		t.Skip("needs cargo and wasm32 target")
	}
	p := &compiler.Policy{Name: "allocator", Version: 1, DefaultAction: "deny", Rules: []compiler.Rule{{
		Name: "allow", Event: "process", Action: "allow", Reason: "matched allocator rule",
		Conditions: compiler.Conditions{All: []compiler.Condition{{Field: "path", Operator: "eq", Value: "/bin/ok"}}},
	}}}
	out := filepath.Join(t.TempDir(), "allocator.wasm")
	built, err := compiler.Build(p, compiler.BuildOptions{OutputPath: out})
	defer compiler.Cleanup(built)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(context.Background())
	if err := rt.LoadPolicy(ctx, out); err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close(context.Background())
	if !pool.StaticRulesProcess().Eligible {
		t.Fatal("static declaration did not round-trip")
	}
	policy, err := pool.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Put(policy)
	initialSize := policy.instance.Memory().Size()
	eventPointer := policy.eventBufPtr
	event := &api.Event{PID: 42, UID: 1000, Comm: "test", Filename: "/bin/ok"}
	wantEvent := make([]byte, eventStructSize)
	writeEventBinary(wantEvent, event, policy.temporal())
	var firstTemporary uint32
	for i := 0; i < 2000; i++ {
		action, err := policy.Evaluate(ctx, event)
		if err != nil || action != api.ActionAllow {
			t.Fatalf("round %d: action %v, error %v", i, action, err)
		}
		if reason := policy.GetMatchedRule(ctx); reason != "matched allocator rule" {
			t.Fatalf("round %d: reason %q (exhausted)", i, reason)
		}
		data, ok := policy.instance.Memory().Read(eventPointer, eventStructSize)
		if !ok || !bytes.Equal(data, wantEvent) {
			t.Fatalf("round %d: corrupted persistent event", i)
		}
		for _, size := range []uint32{65536, 1<<31 - 1, 1 << 31, ^uint32(0)} {
			res, err := policy.instance.ExportedFunction("malloc").Call(ctx, uint64(size))
			if err != nil || res[0] != 0 {
				t.Fatalf("malloc(%d) = %v, %v", size, res, err)
			}
		}
		ptr, err := policy.malloc(ctx, 513)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstTemporary = ptr
		} else if ptr != firstTemporary {
			t.Fatalf("temporary buffer drifted: %d to %d", firstTemporary, ptr)
		}
		if _, err := policy.instance.ExportedFunction("free").Call(ctx, uint64(ptr), 513); err != nil {
			t.Fatal(err)
		}
	}
	if policy.instance.Memory().Size() != initialSize || policy.eventBufPtr != eventPointer {
		t.Fatal("grew linear memory or relocated event buffer")
	}
}
