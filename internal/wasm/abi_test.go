package wasm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/pkg/api"
)

// testFunc is an exported function in a hand-assembled test module. Every
// function ignores its parameters and returns the constant ret (when it has
// a result).
type testFunc struct {
	name    string
	params  int // number of i32 params
	results int // 0 or 1 i32 results
	ret     int32
}

func uleb(v uint32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			out = append(out, b|0x80)
			continue
		}
		return append(out, b)
	}
}

func sleb(v int32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if (v == 0 && b&0x40 == 0) || (v == -1 && b&0x40 != 0) {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

func section(id byte, payload []byte) []byte {
	return append(append([]byte{id}, uleb(uint32(len(payload)))...), payload...)
}

func vec(n int, items []byte) []byte { return append(uleb(uint32(n)), items...) }

// buildTestModule assembles a minimal wasm module with one memory (exported
// as "memory") and the given functions.
func buildTestModule(funcs []testFunc) []byte {
	var types, fnIdx, exports, code []byte
	for i, f := range funcs {
		t := []byte{0x60}
		ps := make([]byte, f.params)
		for j := range ps {
			ps[j] = 0x7f
		}
		t = append(t, vec(f.params, ps)...)
		rs := make([]byte, f.results)
		for j := range rs {
			rs[j] = 0x7f
		}
		t = append(t, vec(f.results, rs)...)
		types = append(types, t...)
		fnIdx = append(fnIdx, uleb(uint32(i))...)

		exports = append(exports, vec(len(f.name), []byte(f.name))...)
		exports = append(exports, 0x00)
		exports = append(exports, uleb(uint32(i))...)

		body := []byte{0x00} // no locals
		if f.results == 1 {
			body = append(body, 0x41)
			body = append(body, sleb(f.ret)...)
		}
		body = append(body, 0x0b)
		code = append(code, append(uleb(uint32(len(body))), body...)...)
	}
	exports = append(exports, vec(len("memory"), []byte("memory"))...)
	exports = append(exports, 0x02, 0x00)

	m := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	m = append(m, section(1, vec(len(funcs), types))...)
	m = append(m, section(3, vec(len(funcs), fnIdx))...)
	m = append(m, section(5, vec(1, []byte{0x00, 0x01}))...)
	m = append(m, section(7, vec(len(funcs)+1, exports))...)
	m = append(m, section(10, vec(len(funcs), code))...)
	return m
}

var (
	fnMalloc      = testFunc{name: "malloc", params: 1, results: 1, ret: 1024}
	fnFree        = testFunc{name: "free", params: 2}
	fnJSONAllow   = testFunc{name: "evaluate_syscall", params: 2, results: 1, ret: int32(api.ActionAllow)}
	fnBinaryDeny  = testFunc{name: "evaluate_event", params: 1, results: 1, ret: int32(api.ActionDeny)}
	fnJSONStyleEv = testFunc{name: "evaluate_event", params: 2, results: 1, ret: int32(api.ActionDeny)}
)

func abiVersion(v int32) testFunc {
	return testFunc{name: "abi_version", results: 1, ret: v}
}

func loadTestModule(t *testing.T, funcs ...testFunc) (*Runtime, error) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "policy.wasm")
	if err := os.WriteFile(path, buildTestModule(funcs), 0o644); err != nil {
		t.Fatalf("write module: %v", err)
	}
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	t.Cleanup(func() { rt.Close(ctx) })
	return rt, rt.LoadPolicy(ctx, path)
}

func evalOnce(t *testing.T, rt *Runtime) api.Action {
	t.Helper()
	ctx := context.Background()
	pool, err := NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close(ctx)
	res, err := NewPolicyEvaluator(pool, "h").Evaluate(ctx, &api.Event{UID: 1000, Filename: "/bin/ls"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return res.Action
}

func TestLoadPolicy_JSONABI(t *testing.T) {
	rt, err := loadTestModule(t, fnMalloc, fnFree, fnJSONAllow)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if got := evalOnce(t, rt); got != api.ActionAllow {
		t.Errorf("action = %v, want ALLOW", got)
	}
}

func TestLoadPolicy_BinaryABI(t *testing.T) {
	rt, err := loadTestModule(t, fnMalloc, fnBinaryDeny)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	ctx := context.Background()
	pol, err := NewPolicy(ctx, rt)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	defer pol.Close(ctx)
	if !pol.useBinaryABI {
		t.Error("expected binary ABI for evaluate_event(i32) -> i32")
	}
	if got := evalOnce(t, rt); got != api.ActionDeny {
		t.Errorf("action = %v, want DENY", got)
	}
}

// A JSON policy that names its (ptr, len) entry point evaluate_event used to be
// driven through the binary ABI with one argument, which failed on every
// event and denied everything. It must now be rejected at load time.
func TestLoadPolicy_RejectsJSONStyleEvaluateEvent(t *testing.T) {
	_, err := loadTestModule(t, fnMalloc, fnFree, fnJSONStyleEv)
	if err == nil {
		t.Fatal("expected LoadPolicy to reject evaluate_event(i32, i32)")
	}
	for _, want := range []string{"evaluate_event", "(i32, i32) -> (i32)", "evaluate_syscall"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}

// When a module exports both, a JSON-style evaluate_event must not shadow a
// valid evaluate_syscall.
func TestLoadPolicy_JSONStyleEvaluateEventFallsBackToSyscall(t *testing.T) {
	rt, err := loadTestModule(t, fnMalloc, fnFree, fnJSONStyleEv, fnJSONAllow)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if got := evalOnce(t, rt); got != api.ActionAllow {
		t.Errorf("action = %v, want ALLOW from evaluate_syscall", got)
	}
}

func TestLoadPolicy_RejectsBadEvaluateSyscallSignature(t *testing.T) {
	_, err := loadTestModule(t, fnMalloc, testFunc{name: "evaluate_syscall", params: 1, results: 1})
	if err == nil || !strings.Contains(err.Error(), "evaluate_syscall") {
		t.Fatalf("expected signature error for evaluate_syscall, got %v", err)
	}
}

func TestLoadPolicy_RejectsMissingEntryPoint(t *testing.T) {
	_, err := loadTestModule(t, fnMalloc, fnFree)
	if err == nil || !strings.Contains(err.Error(), "neither") {
		t.Fatalf("expected missing-entry-point error, got %v", err)
	}
}

func TestLoadPolicy_RejectsMissingMalloc(t *testing.T) {
	_, err := loadTestModule(t, fnJSONAllow)
	if err == nil || !strings.Contains(err.Error(), "malloc") {
		t.Fatalf("expected missing-malloc error, got %v", err)
	}
}

func TestLoadPolicy_ABIVersion(t *testing.T) {
	tests := []struct {
		version int32
		ok      bool
	}{
		{0, false},
		{1, true},
		{2, true},
		{3, false},
		{-1, false},
	}
	for _, tc := range tests {
		rt, err := loadTestModule(t, fnMalloc, fnFree, fnJSONAllow, abiVersion(tc.version))
		if tc.ok {
			if err != nil {
				t.Errorf("abi_version %d: unexpected error %v", tc.version, err)
				continue
			}
			if got := evalOnce(t, rt); got != api.ActionAllow {
				t.Errorf("abi_version %d: action = %v, want ALLOW", tc.version, got)
			}
			continue
		}
		if err == nil {
			t.Errorf("abi_version %d: expected load error", tc.version)
			continue
		}
		if !strings.Contains(err.Error(), "unsupported policy ABI version") {
			t.Errorf("abi_version %d: error %q should say unsupported ABI version", tc.version, err)
		}
		if rt.module != nil {
			t.Errorf("abi_version %d: rejected module must not be installed", tc.version)
		}
	}
}

func TestLoadPolicy_RejectsBadABIVersionSignature(t *testing.T) {
	_, err := loadTestModule(t, fnMalloc, fnFree, fnJSONAllow,
		testFunc{name: "abi_version", params: 1, results: 1, ret: 2})
	if err == nil || !strings.Contains(err.Error(), "abi_version") {
		t.Fatalf("expected abi_version signature error, got %v", err)
	}
}

// A rejected reload must leave the previously loaded module in place.
func TestLoadPolicy_RejectedReloadKeepsPreviousModule(t *testing.T) {
	ctx := context.Background()
	rt, err := loadTestModule(t, fnMalloc, fnFree, fnJSONAllow)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.wasm")
	if err := os.WriteFile(bad, buildTestModule([]testFunc{fnMalloc, abiVersion(9), fnJSONAllow}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := rt.LoadPolicy(ctx, bad); err == nil {
		t.Fatal("expected error for abi_version 9")
	}
	if got := evalOnce(t, rt); got != api.ActionAllow {
		t.Errorf("action = %v after rejected reload, want ALLOW from previous module", got)
	}
}
