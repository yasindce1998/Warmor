package wasm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/crypto/assignment"
	"github.com/yasindce1998/warmor/internal/policybuild"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
)

func TestAssignmentChecksPoolCapturedModuleAfterRuntimeReload(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	first, err := policybuild.Append(wasmtest.VersionedConstPolicy(0, 1), policybuild.Metadata{Compiler: "build-first", DefaultAction: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.LoadPolicyBytes(ctx, first); err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close(ctx)
	want := assignment.Policy{ID: "first", Version: 1, SHA256: assignment.Digest(first), ABI: 1, Compiler: "build-first", Posture: assignment.Posture{Mode: "audit", DefaultAction: "allow"}}
	if err := pool.CheckAssignment(want); err != nil {
		t.Fatal(err)
	}
	second, err := policybuild.Append(wasmtest.VersionedConstPolicy(1, 2), policybuild.Metadata{Compiler: "build-second", DefaultAction: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.LoadPolicyBytes(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := pool.CheckAssignment(want); err != nil {
		t.Fatal("runtime reload changed captured pool identity", err)
	}
	borrowed, err := pool.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Replace(borrowed); err != nil {
		t.Fatal("replacement did not use captured compiled module", err)
	}
	if err := pool.CheckAssignment(want); err != nil {
		t.Fatal(err)
	}
	wrong := want
	wrong.ABI = 2
	wrong.Compiler = "build-second"
	wrong.SHA256 = assignment.Digest(second)
	wrong.Posture.DefaultAction = "deny"
	if err := pool.CheckAssignment(wrong); err == nil {
		t.Fatal("old pool accepted unrelated current-runtime declarations")
	}
}

func TestCompiledAssignmentRetainsBuildContextSafeIdentifierAndMetadata(t *testing.T) {
	if !compiler.CargoAvailable() {
		if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
			t.Fatal("required Rust wasm32 toolchain missing")
		}
		t.Skip("requires Rust wasm32 toolchain")
	}
	policy := &compiler.Policy{Name: "signed \"context\"/../policy", Version: 1, DefaultAction: "deny", Rules: []compiler.Rule{{Name: "allow-safe", Event: "process", Action: "allow", Conditions: compiler.Conditions{All: []compiler.Condition{{Field: "path", Operator: "eq", Value: "/bin/safe"}}}}}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := compiler.Build(policy, compiler.BuildOptions{Context: ctx, OutputPath: filepath.Join(t.TempDir(), "policy.wasm")})
	defer compiler.Cleanup(result)
	if err != nil {
		t.Fatal(err)
	}
	module, err := os.ReadFile(result.WasmPath)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(context.Background())
	if err := rt.LoadPolicyBytes(ctx, module); err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close(context.Background())
	want := assignment.Policy{ID: "signed-policy", Version: 1, SHA256: assignment.Digest(module), ABI: 3, Compiler: compiler.Identity, Posture: assignment.Posture{Mode: "enforce", DefaultAction: "deny"}}
	if err := pool.CheckAssignment(want); err != nil {
		t.Fatal("context-aware compiler output lost signed metadata", err)
	}
	if compiler.Version != "7" || compiler.Identity != "warmor-yaml/7" {
		t.Fatal("compiler cache identity regressed")
	}
}
