package wasm

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
)

var wasmHeader = []byte{0, 'a', 's', 'm', 1, 0, 0, 0}

func framingModule(id byte, payload []byte) []byte {
	return append(append([]byte(nil), wasmHeader...), section(id, payload)...)
}

// compilerSpy proves rejection precedes the dependency's non-interruptible
// decoder. Never pass the count-bomb fixtures to raw wazero in these tests.
type compilerSpy struct {
	wazero.Runtime
	calls    int
	onReturn func()
}

func (s *compilerSpy) CompileModule(ctx context.Context, binary []byte) (wazero.CompiledModule, error) {
	s.calls++
	compiled, err := s.Runtime.CompileModule(ctx, binary)
	if s.onReturn != nil {
		s.onReturn()
	}
	return compiled, err
}

func TestPreflightRejectsComplexityBeforeWazero(t *testing.T) {
	huge := uleb(^uint32(0))
	fixtures := map[string][]byte{}
	for _, id := range []byte{1, 2, 3, 4, 5, 6, 7, 9, 10, 11} {
		fixtures["vector "+string(rune('A'+id))] = framingModule(id, huge)
	}
	fixtures["function count"] = framingModule(3, uleb(MaxPolicyFunctions+1))
	fixtures["type arity"] = framingModule(1, append([]byte{1, 0x60}, huge...))
	fixtures["body size"] = framingModule(10, append([]byte{1}, uleb(MaxPolicyFunctionBytes+1)...))
	fixtures["total code bytes"] = framingModule(10, append([]byte{1}, make([]byte, MaxPolicyCodeBytes+1)...))
	localBody := append(append([]byte{1}, huge...), 0x7f, 0x0b)
	fixtures["local expansion"] = framingModule(10, append(append([]byte{1}, uleb(uint32(len(localBody)))...), localBody...))
	fixtures["table minimum"] = framingModule(4, append([]byte{1, 0x70, 0}, huge...))
	fixtures["element expansion"] = framingModule(9, append([]byte{1, 1, 0}, huge...))
	fixtures["name expansion"] = framingModule(0, append([]byte{4, 'n', 'a', 'm', 'e'}, section(1, huge)...))
	fixtures["local name expansion"] = framingModule(0, append([]byte{4, 'n', 'a', 'm', 'e'}, section(2, append([]byte{1, 0}, huge...))...))
	fixtures["name subsection underflow"] = framingModule(0, []byte{4, 'n', 'a', 'm', 'e', 0, 0, 0})
	fixtures["truncated section"] = append(append([]byte{}, wasmHeader...), 1, 0xff, 0xff, 0xff, 0xff, 0x0f)
	fixtures["duplicate section"] = append(framingModule(1, []byte{0}), section(1, []byte{0})...)
	fixtures["many sections"] = append(append([]byte{}, wasmHeader...), bytes.Repeat([]byte{0, 1, 0}, maxPolicySections+1)...)
	rt, err := NewRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(context.Background())
	spy := &compilerSpy{Runtime: rt.runtime}
	rt.runtime = spy
	for name, binary := range fixtures {
		t.Run(name, func(t *testing.T) {
			before := spy.calls
			err := rt.LoadPolicyBytes(context.Background(), binary)
			if err == nil || !strings.Contains(err.Error(), "preflight") {
				t.Fatalf("expected preflight failure, got %v", err)
			}
			if spy.calls != before {
				t.Fatal("unsafe input reached wazero decoder")
			}
		})
	}
}

func compilationWorkload(functions, instructions int) []byte {
	m := framingModule(1, []byte{1, 0x60, 0, 0}) // () -> ()
	indices := append(uleb(uint32(functions)), make([]byte, functions)...)
	m = append(m, section(3, indices)...)
	// A real sequence of local reads/adds/writes, not NOP padding or a guest
	// loop. The validator/compiler must process every encoded instruction.
	body := append([]byte{1, 1, 0x7f}, bytes.Repeat([]byte{0x20, 0, 0x41, 1, 0x6a, 0x21, 0}, instructions)...)
	body = append(body, 0x0b)
	code := uleb(uint32(functions))
	for i := 0; i < functions; i++ {
		code = append(code, append(uleb(uint32(len(body))), body...)...)
	}
	return append(m, section(10, code)...)
}

func TestCompilationCancellationIsNotAHardDeadline(t *testing.T) {
	// This intentionally exercises actual decoding/validation/compiler work,
	// not a guest execution loop. Keep the workload modest on shared CI hosts.
	// It documents pinned wazero 1.11 behavior; if a future dependency makes
	// cancellation effective, update this test and the isolation threat model.
	binary := compilationWorkload(128, 1024)
	if err := preflightModule(context.Background(), binary); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt := wazero.NewRuntimeWithConfig(context.Background(), wazero.NewRuntimeConfig().WithDebugInfoEnabled(false))
	defer rt.Close(context.Background())
	start := time.Now()
	compiled, err := rt.CompileModule(ctx, binary)
	if err != nil {
		t.Fatalf("pinned dependency behavior changed (review timeout claims): %v", err)
	}
	defer compiled.Close(context.Background())
	t.Logf("raw wazero compiled %d bytes / 128 functions / 131072 integer adds despite canceled context in %v", len(binary), time.Since(start))
	if len(compiled.ExportedFunctions()) != 0 {
		t.Fatal("unexpected workload exports")
	}
}

func TestPreflightHonorsCanceledContextWithoutCompilerWork(t *testing.T) {
	rt, err := NewRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(context.Background())
	spy := &compilerSpy{Runtime: rt.runtime}
	rt.runtime = spy
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := rt.LoadPolicyBytes(ctx, compilationWorkload(128, 1024)); !errors.Is(err, context.Canceled) {
		t.Fatalf("load = %v", err)
	}
	if spy.calls != 0 {
		t.Fatal("canceled input reached compiler")
	}
}

func TestCompilationLateResultKeepsPreviousModule(t *testing.T) {
	rt, err := NewRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(context.Background())
	binary := buildTestModule([]testFunc{fnMalloc, fnBinaryDeny})
	if err = rt.LoadPolicyBytes(context.Background(), binary); err != nil {
		t.Fatal(err)
	}
	previous := rt.module
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Cancel exactly as real compilation returns: deterministic, no racing
	// timer/goroutine and no claim that the compiler was interrupted.
	rt.runtime = &compilerSpy{Runtime: rt.runtime, onReturn: cancel}
	err = rt.LoadPolicyBytes(ctx, binary)
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "compilation exceeded") {
		t.Fatalf("late result = %v", err)
	}
	if rt.module != previous {
		t.Fatal("late compilation replaced last-known-good module")
	}
}

func TestPreflightAcceptsFixtureAndIgnoresDebugPayload(t *testing.T) {
	binary, err := os.ReadFile(filepath.Join("testdata", "allow_policy.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	if err := preflightModule(context.Background(), binary); err != nil {
		t.Fatal(err)
	}
	// Deliberately invalid DWARF is opaque custom data, not interpreted.
	debug := append([]byte{11}, []byte(".debug_info")...)
	debug = append(debug, 0xff, 0xff, 0xff)
	binary = append(binary, section(0, debug)...)
	rt, err := NewRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(context.Background())
	if err := rt.LoadPolicyBytes(context.Background(), binary); err != nil {
		t.Fatal(err)
	}
}

func FuzzPreflightFraming(f *testing.F) {
	f.Add(buildTestModule([]testFunc{fnMalloc, fnBinaryDeny}))
	f.Add(compilationWorkload(2, 16))
	f.Add(framingModule(1, uleb(^uint32(0))))
	f.Fuzz(func(t *testing.T, binary []byte) {
		if len(binary) > 1<<20 {
			t.Skip()
		}
		// No compiler calls: fuzz admission parsing without risking a second
		// unbounded parser/compiler in the same process.
		_ = preflightModule(context.Background(), binary)
	})
}
