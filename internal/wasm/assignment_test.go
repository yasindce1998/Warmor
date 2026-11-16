package wasm

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/crypto"
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
	wantIdentity := ArtifactIdentity{Digest: want.SHA256, ABI: want.ABI, Compiler: want.Compiler, DefaultAction: want.Posture.DefaultAction}
	if pool.Identity() != wantIdentity {
		t.Fatalf("receipt and assignment identities differ: %+v", pool.Identity())
	}
	if err := pool.CheckAssignment(want); err != nil {
		t.Fatal(err)
	}
	observed := pool.Metadata()
	if err := observed.MatchArtifact(want.SHA256, want.ABI, want.Compiler, want.Posture.DefaultAction); err != nil {
		t.Fatal("observations disagree with signed pool identity", err)
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
	if pool.Identity() != wantIdentity {
		t.Fatal("runtime candidate changed receipt pool identity")
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
	if pool.Identity() != wantIdentity {
		t.Fatal("pool replacement changed receipt identity")
	}
	wrong := want
	wrong.ABI = 2
	wrong.Compiler = "build-second"
	wrong.SHA256 = assignment.Digest(second)
	wrong.Posture.DefaultAction = "deny"
	if err := pool.CheckAssignment(wrong); err == nil {
		t.Fatal("old pool accepted unrelated current-runtime declarations")
	}
	if !reflect.DeepEqual(pool.Metadata(), observed) {
		t.Fatal("runtime reload/replacement changed captured observations")
	}
	if err := pool.Metadata().MatchArtifact(wrong.SHA256, wrong.ABI, wrong.Compiler, wrong.Posture.DefaultAction); err == nil {
		t.Fatal("observations accepted unrelated runtime claims")
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
	out := filepath.Join(t.TempDir(), "policy.wasm")
	if err := os.WriteFile(out, []byte("previous artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := compiler.Build(policy, compiler.BuildOptions{Context: ctx, OutputPath: out})
	defer compiler.Cleanup(result)
	if err != nil {
		t.Fatal(err)
	}
	module, err := os.ReadFile(result.WasmPath)
	if err != nil {
		t.Fatal(err)
	}
	declarations, err := policybuild.Read(module)
	if err != nil || declarations == nil || declarations.Compiler != "warmor-yaml/7" || declarations.DefaultAction != "deny" {
		t.Fatalf("published build declarations = %+v, %v", declarations, err)
	}
	key, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crypto.PolicySignaturePath(out), key.SignPolicyFile(module), 0o600); err != nil {
		t.Fatal(err)
	}
	// Sign only after Build's one-file commit; loading uses exactly verified bytes.
	verified, err := crypto.ReadVerifiedPolicy(key.Public, out, 64<<20)
	if err != nil {
		t.Fatal("published artifact/signature mismatch", err)
	}
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(context.Background())
	if err := rt.LoadPolicyBytes(ctx, verified); err != nil {
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
	if err := pool.Metadata().MatchArtifact(want.SHA256, want.ABI, want.Compiler, want.Posture.DefaultAction); err != nil {
		t.Fatal("compiled observations disagree with signed pool claims", err)
	}
	if compiler.Version != "7" || compiler.Identity != "warmor-yaml/7" {
		t.Fatal("compiler cache identity regressed")
	}
}
