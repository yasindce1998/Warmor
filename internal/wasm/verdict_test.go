package wasm

import (
	"context"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestEvaluateRejectsInvalidVerdicts(t *testing.T) {
	for _, action := range []int32{-1, 4, 99, 1 << 30} {
		pool := newPoolFromBytes(t, wasmtest.ConstPolicy(action, nil), 1)
		evaluator := NewPolicyEvaluator(pool, "test")
		for i := 0; i < 2; i++ {
			result, err := evaluator.Evaluate(context.Background(), &api.Event{})
			if err == nil || !strings.Contains(err.Error(), "invalid policy action") || result != nil {
				t.Fatalf("action %d: result = %+v, error = %v", action, result, err)
			}
		}
	}
}

func TestJSONPolicyRejectsInvalidVerdict(t *testing.T) {
	rt, err := loadTestModule(t, fnMalloc, fnFree, testFunc{name: "evaluate_syscall", params: 2, results: 1, ret: 99})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(context.Background(), rt, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close(context.Background())
	result, err := NewPolicyEvaluator(pool, "test").Evaluate(context.Background(), &api.Event{})
	if result != nil || err == nil || !strings.Contains(err.Error(), "invalid policy action 99") {
		t.Fatalf("result = %+v, error = %v", result, err)
	}
}
