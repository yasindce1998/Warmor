package wasm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

// newPoolFromBytes loads a module from bytes into a fresh runtime + pool.
func newPoolFromBytes(t *testing.T, mod []byte, size int, cfg ...RuntimeConfig) *Pool {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "p.wasm")
	if err := os.WriteFile(path, mod, 0o600); err != nil {
		t.Fatal(err)
	}
	rt, err := NewRuntime(ctx, cfg...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rt.Close(ctx) })
	if err := rt.LoadPolicy(ctx, path); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	pool, err := NewPool(ctx, rt, size)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { pool.Close(ctx) })
	return pool
}

func TestPoolFieldsRead_Declared(t *testing.T) {
	masks := [3]uint32{compiler.FieldBitPath, 0, compiler.FieldBitRemoteAddr | compiler.FieldBitRemotePort}
	pool := newPoolFromBytes(t, wasmtest.ConstPolicy(0, &masks), 2)
	ev := NewPolicyEvaluator(pool, "h")
	for i, want := range masks {
		if got := ev.FieldsRead(api.EventType(i)); got != want {
			t.Errorf("FieldsRead(%d) = %#x, want %#x", i, got, want)
		}
	}
	if got := ev.FieldsRead(api.EventType(9)); got != FieldsUnknown {
		t.Errorf("FieldsRead(unknown type) = %#x, want FieldsUnknown", got)
	}
}

func TestPoolFieldsRead_Undeclared(t *testing.T) {
	for name, mod := range map[string][]byte{
		"binary ABI": wasmtest.ConstPolicy(0, nil),
	} {
		pool := newPoolFromBytes(t, mod, 1)
		for i := 0; i < 3; i++ {
			if got := pool.FieldsRead(api.EventType(i)); got != FieldsUnknown {
				t.Errorf("%s: FieldsRead(%d) = %#x, want FieldsUnknown", name, i, got)
			}
		}
	}
	// The Rust JSON-ABI fixture declares nothing either.
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)
	pool, err := NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close(ctx)
	if got := pool.FieldsRead(api.EventTypeProcess); got != FieldsUnknown {
		t.Errorf("fixture FieldsRead = %#x, want FieldsUnknown", got)
	}
	var nilEval *PolicyEvaluator
	if nilEval.FieldsRead(api.EventTypeProcess) != FieldsUnknown {
		t.Error("nil evaluator must report FieldsUnknown")
	}
}

// TestCompiledYAMLDeclaresFieldsRead builds a YAML policy with the real Rust
// toolchain and checks the generated module's declaration round-trips.
func TestCompiledYAMLDeclaresFieldsRead(t *testing.T) {
	if testing.Short() || !compiler.CargoAvailable() {
		t.Skip("needs cargo and the wasm32-unknown-unknown target")
	}
	ctx := context.Background()
	yamlPath := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(yamlPath, []byte(`name: fields-e2e
version: 1
rules:
  - name: exec
    event: process
    conditions:
      all:
        - path: { glob: "/tmp/**" }
    action: deny
  - name: net
    event: network
    conditions:
      all:
        - remote_port: { eq: 22 }
        - uid: { not: 0 }
    action: deny
default_action: allow
`), 0o600); err != nil {
		t.Fatal(err)
	}
	rt, err := NewRuntime(ctx, RuntimeConfig{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	if err := rt.LoadPolicyFromYAML(ctx, yamlPath); err != nil {
		t.Fatalf("LoadPolicyFromYAML: %v", err)
	}
	pool, err := NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close(ctx)
	want := map[api.EventType]uint32{
		api.EventTypeProcess: compiler.FieldBitPath,
		api.EventTypeFile:    0,
		api.EventTypeNetwork: compiler.FieldBitRemotePort | compiler.FieldBitUID,
	}
	for typ, w := range want {
		if got := pool.FieldsRead(typ); got != w {
			t.Errorf("FieldsRead(%v) = %v, want %v", typ, compiler.FieldNames(got), compiler.FieldNames(w))
		}
	}
	// And the decision itself still works.
	res, err := NewPolicyEvaluator(pool, "h").Evaluate(ctx, &api.Event{Filename: "/tmp/x"})
	if err != nil || res.Action != api.ActionDeny {
		t.Fatalf("Evaluate = %+v, %v; want deny", res, err)
	}
}
