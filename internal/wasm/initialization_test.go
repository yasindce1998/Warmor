package wasm

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/pkg/api"
)

func loopingFunction(name string, params, results int) testFunc {
	body := []byte{0x03, 0x40, 0x0c, 0x00, 0x0b}
	if results != 0 {
		body = append(body, 0x41, 0x00)
	}
	return testFunc{name: name, params: params, results: results, body: body}
}

func boundedTestRuntime(t *testing.T) *Runtime {
	t.Helper()
	rt, err := NewRuntime(context.Background(), RuntimeConfig{InitializationTimeout: 30 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rt.Close(context.Background()) })
	return rt
}

func TestInitializationGuestCallsBounded(t *testing.T) {
	start := loopingFunction("start", 0, 0)
	start.start = true
	for _, guest := range []testFunc{start, loopingFunction("_start", 0, 0), loopingFunction("abi_version", 0, 1), loopingFunction("malloc", 1, 1)} {
		t.Run(guest.name, func(t *testing.T) {
			funcs := []testFunc{fnBinaryDeny, fnMalloc}
			if guest.name == "malloc" {
				funcs[1] = guest
			} else {
				funcs = append(funcs, guest)
			}
			mod := buildTestModule(funcs)
			for _, path := range []string{"load", "policy", "pool", "replace"} {
				t.Run(path, func(t *testing.T) {
					rt := boundedTestRuntime(t)
					within(t, 2*time.Second, func() {
						ctx := context.Background() // no caller deadline
						var err error
						if path == "load" {
							err = rt.LoadPolicyBytes(ctx, mod)
						} else {
							// Bypass load probing to test independent entry points.
							rt.module, err = rt.runtime.CompileModule(ctx, mod)
							if err != nil {
								t.Error(err)
								return
							}
							switch path {
							case "policy":
								_, err = NewPolicy(ctx, rt)
							case "pool":
								_, err = NewPool(ctx, rt, 1)
							case "replace":
								p := &Pool{runtime: rt, module: rt.module, done: make(chan struct{}), instances: make(chan *Policy, 1)}
								err = p.Replace(nil)
							}
						}
						if err == nil {
							t.Error("looping guest accepted")
						}
					})
				})
			}
		})
	}
}

func TestPoolDeclarationCallsBounded(t *testing.T) {
	for _, guest := range []testFunc{
		loopingFunction("warmor_fields_read", 1, 1), loopingFunction("warmor_static_rules", 3, 1),
		{name: "warmor_fields_read", params: 1, results: 1, body: []byte{0x00}},
		{name: "warmor_static_rules", params: 3, results: 1, body: []byte{0x00}},
	} {
		t.Run(guest.name, func(t *testing.T) {
			rt := loadDeclarationTestRuntime(t, fnMalloc, fnBinaryDeny, guest)
			within(t, 2*time.Second, func() {
				pool, err := NewPool(context.Background(), rt, 1)
				if err == nil {
					_ = pool.Close(context.Background())
					t.Fatal("accepted instance closed by declaration timeout or trap")
				}
				if !strings.Contains(err.Error(), "initialize pool member 0:") {
					t.Errorf("failed before the declaration under test: %v", err)
				}
			})
		})
	}
}

// loadDeclarationTestRuntime gives compilation and the benign load-time probe
// the normal initialization budget. Only NewPool's declaration phase needs a
// short test budget; charging setup to 30ms flakes on contended native runners.
func loadDeclarationTestRuntime(t *testing.T, funcs ...testFunc) *Runtime {
	t.Helper()
	rt, err := loadTestModule(t, funcs...)
	if err != nil {
		t.Fatal(err)
	}
	// Leave scheduler headroom for pool instantiation, but remain shorter than
	// both declaration-specific production limits and the 2s watchdog. The
	// caller also asserts the failure came after successful instantiation.
	rt.initTimeout = 250 * time.Millisecond
	return rt
}

func TestMallocRegionsValidated(t *testing.T) {
	for _, ptr := range []int32{0, -1, 65535} {
		malloc := fnMalloc
		malloc.ret = ptr
		rt := boundedTestRuntime(t)
		if err := rt.LoadPolicyBytes(context.Background(), buildTestModule([]testFunc{malloc, fnBinaryDeny})); err == nil {
			t.Errorf("binary pointer %d accepted", ptr)
		}
		if err := rt.LoadPolicyBytes(context.Background(), buildTestModule([]testFunc{malloc, fnJSONAllow})); err != nil {
			t.Fatal(err)
		}
		p, err := NewPolicy(context.Background(), rt)
		if err != nil {
			t.Fatal(err)
		}
		if action, err := p.Evaluate(context.Background(), &api.Event{}); err == nil || action != api.ActionDeny {
			t.Errorf("JSON pointer %d: action %v, error %v", ptr, action, err)
		}
		p.Close(context.Background())
	}
}

func TestRejectsMalformedMemoryAndAllocatorExports(t *testing.T) {
	for _, bad := range []testFunc{{name: "malloc", results: 1}, {name: "malloc", params: 1}, {name: "free", params: 1}, {name: "get_last_matched_rule", params: 1, results: 1}} {
		funcs := []testFunc{fnBinaryDeny}
		if bad.name != "malloc" {
			funcs = append(funcs, fnMalloc)
		}
		_, err := loadTestModule(t, append(funcs, bad)...)
		if err == nil || !strings.Contains(err.Error(), bad.name) {
			t.Errorf("bad %s signature accepted: %v", bad.name, err)
		}
	}
	rt := boundedTestRuntime(t)
	mod := bytes.Replace(buildTestModule([]testFunc{fnMalloc, fnBinaryDeny}), []byte("memory"), []byte("hidden"), 1)
	if err := rt.LoadPolicyBytes(context.Background(), mod); err == nil || !strings.Contains(err.Error(), "memory") {
		t.Errorf("unexported memory accepted: %v", err)
	}
}

func TestMatchedRuleCannotAliasOrOverreadEventBuffer(t *testing.T) {
	rule := testFunc{name: "get_last_matched_rule", params: 2, results: 1, ret: 1024}
	rt, err := loadTestModule(t, fnMalloc, fnBinaryDeny, rule)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy(context.Background(), rt)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(context.Background())
	if _, err := p.malloc(context.Background(), 512); err == nil {
		t.Fatal("alias of persistent event buffer accepted")
	}
	p.eventBufPtr = 0 // test independent length cap
	if got := p.GetMatchedRule(context.Background()); got != "" {
		t.Fatalf("oversized reason accepted: %d bytes", len(got))
	}
}

func TestPoolReplacementPinnedToOriginalModule(t *testing.T) {
	ctx := context.Background()
	// This tests generation pinning, not timeout enforcement. Use the normal
	// initialization budget for both benign compilations: the 30ms looping-
	// guest fixture can expire during setup on contended native Windows CI.
	rt, err := loadTestModule(t, fnMalloc, fnBinaryDeny)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close(ctx)
	other, err := NewPool(ctx, rt, 1) // pools must not collide on module names
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(ctx)
	pol, _ := pool.Get(ctx)
	if err := rt.LoadPolicyBytes(ctx, buildTestModule([]testFunc{fnMalloc, fnJSONAllow})); err != nil {
		t.Fatal(err)
	}
	if err := pool.Replace(pol); err != nil {
		t.Fatal(err)
	}
	pol, err = pool.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Put(pol)
	if action, err := pol.Evaluate(ctx, &api.Event{}); err != nil || action != api.ActionDeny {
		t.Fatalf("replacement changed policy generation: %v, %v", action, err)
	}
}

func TestEvaluationAuxiliaryGuestCallsBounded(t *testing.T) {
	for _, tc := range []struct {
		name  string
		funcs []testFunc
	}{
		{"JSON malloc", []testFunc{loopingFunction("malloc", 1, 1), fnJSONAllow}},
		{"JSON free", []testFunc{fnMalloc, fnJSONAllow, loopingFunction("free", 2, 0)}},
		{"reason export", []testFunc{fnMalloc, fnJSONAllow, loopingFunction("get_last_matched_rule", 2, 1)}},
		{"reason free", []testFunc{fnMalloc, fnJSONAllow, {name: "get_last_matched_rule", params: 2, results: 1}, loopingFunction("free", 2, 0)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, err := loadTestModule(t, tc.funcs...)
			if err != nil {
				t.Fatal(err)
			}
			p, err := NewPolicy(context.Background(), rt)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close(context.Background())
			within(t, 2*time.Second, func() {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer cancel()
				var err error
				if strings.HasPrefix(tc.name, "reason") {
					_, err = p.getMatchedRule(ctx)
				} else {
					_, err = p.Evaluate(ctx, &api.Event{})
				}
				if err == nil || !p.instance.IsClosed() {
					t.Errorf("looping auxiliary call: %v, closed=%v", err, p.instance.IsClosed())
				}
			})
		})
	}
}

func TestDeclarationMallocAndFreeFailures(t *testing.T) {
	// malloc(256) succeeds for the event; every other size loops forever.
	malloc := fnMalloc
	malloc.body = []byte{0x20, 0x00, 0x41}
	malloc.body = append(malloc.body, sleb(eventStructSize)...)
	malloc.body = append(malloc.body, 0x46, 0x04, 0x7f, 0x41)
	malloc.body = append(malloc.body, sleb(1024)...)
	malloc.body = append(malloc.body, 0x05)
	malloc.body = append(malloc.body, loopingFunction("", 0, 1).body...)
	malloc.body = append(malloc.body, 0x0b)
	static := testFunc{name: compiler.StaticRulesExport, params: 3, results: 1, ret: 1}
	for _, tc := range []struct {
		name  string
		funcs []testFunc
	}{
		{"malloc loops", []testFunc{malloc, fnBinaryDeny, static}},
		{"free traps", []testFunc{fnMalloc, fnJSONAllow, static, {name: "free", params: 2, body: []byte{0x00}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := loadDeclarationTestRuntime(t, tc.funcs...)
			within(t, 2*time.Second, func() {
				pool, err := NewPool(context.Background(), rt, 1)
				if err == nil {
					_ = pool.Close(context.Background())
					t.Fatal("pool accepted failed declaration allocation/free")
				}
				if !strings.Contains(err.Error(), "initialize pool member 0:") {
					t.Errorf("failed before the declaration allocation/free under test: %v", err)
				}
			})
		})
	}
}
