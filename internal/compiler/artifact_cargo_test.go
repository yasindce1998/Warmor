//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package compiler_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/crypto/assignment"
	"github.com/yasindce1998/warmor/internal/policybuild"
	"github.com/yasindce1998/warmor/internal/wasm"
)

func TestBuildArtifactCommaTempDir(t *testing.T) {
	if os.Getenv("WARMOR_TEST_COMMA_TMP_CHILD") != "1" {
		if !compiler.CargoAvailable() {
			if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
				t.Fatal("required Rust wasm32 toolchain missing")
			}
			t.Skip("requires Rust wasm32 toolchain")
		}
		parent := filepath.Join(t.TempDir(), "owned,comma parent")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestBuildArtifactCommaTempDir$", "-test.v")
		// Only the fresh child gets TMPDIR: the test runner's environment and
		// concurrently running tests are untouched.
		cmd.Env = append(os.Environ(), "WARMOR_TEST_COMMA_TMP_CHILD=1", "TMPDIR="+parent)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("real Cargo build with comma TMPDIR: %v\n%s", err, output)
		}
		t.Logf("comma TMPDIR subprocess: %s", output)
		return
	}

	if !strings.Contains(os.TempDir(), ",") {
		t.Fatal("child must use comma-containing temp parent")
	}
	outDir, work := t.TempDir(), t.TempDir()
	t.Setenv("TMPDIR", work) // Child only, never runs parallel tests.
	out := filepath.Join(outDir, "policy.wasm")
	if err := os.WriteFile(out, []byte("previous artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := &compiler.Policy{Name: "comma-path-policy", Version: 1, DefaultAction: "deny", Rules: []compiler.Rule{{
		Name: "allow-safe", Event: "process", Action: "allow",
		Conditions: compiler.Conditions{All: []compiler.Condition{{Field: "path", Operator: "eq", Value: "/bin/safe"}}},
	}}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := compiler.Build(policy, compiler.BuildOptions{Context: ctx, OutputPath: out})
	defer compiler.Cleanup(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.CratePath, work+string(os.PathSeparator)) {
		t.Fatalf("crate %s not under comma TMPDIR %s", result.CratePath, work)
	}
	rawPath := filepath.Join(result.CratePath, "warmor_policy_comma_path_policy.wasm")
	info, err := os.Lstat(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || st == nil || st.Nlink != 1 {
		t.Fatalf("raw compiler output must be a singly-linked regular file: %+v", info)
	}
	raw, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	if metadata, err := policybuild.Read(raw); err != nil || metadata != nil {
		t.Fatalf("raw compiler output metadata = %+v, %v", metadata, err)
	}
	module, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	want, err := policybuild.Append(raw, policybuild.Metadata{Compiler: "warmor-yaml/7", DefaultAction: "deny"})
	if err != nil || !bytes.Equal(module, want) {
		t.Fatalf("published bytes differ from raw output plus build declarations: %v", err)
	}
	key, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crypto.PolicySignaturePath(out), key.SignPolicyFile(module), 0o600); err != nil {
		t.Fatal(err)
	}
	verified, err := crypto.ReadVerifiedPolicy(key.Public, out, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := wasm.NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(context.Background())
	if err := rt.LoadPolicyBytes(ctx, verified); err != nil {
		t.Fatal(err)
	}
	pool, err := wasm.NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close(context.Background())
	if err := pool.CheckAssignment(assignment.Policy{
		ID: "comma-policy", Version: 1, SHA256: assignment.Digest(verified), ABI: 3, Compiler: "warmor-yaml/7",
		Posture: assignment.Posture{Mode: "enforce", DefaultAction: "deny"},
	}); err != nil {
		t.Fatal("comma-path build lost signed declarations or ABI", err)
	}
	compiler.Cleanup(result)
	assertCargoDirectoryEntries(t, work)

	// Force a real rustc option error via real Cargo, not an injected tool.
	// The previously published module and its signature must remain untouched.
	t.Setenv("CARGO_ENCODED_RUSTFLAGS", "--warmor-test-invalid-rustc-option")
	failed, err := compiler.Build(policy, compiler.BuildOptions{Context: ctx, OutputPath: out})
	defer compiler.Cleanup(failed)
	if err == nil || failed != nil || errors.Is(err, compiler.ErrArtifactPublicationIndeterminate) ||
		!strings.Contains(err.Error(), "warmor-test-invalid-rustc-option") {
		t.Fatalf("real Cargo failure = %+v, %v", failed, err)
	}
	after, err := crypto.ReadVerifiedPolicy(key.Public, out, 64<<20)
	if err != nil || !bytes.Equal(after, verified) {
		t.Fatalf("real Cargo error changed existing signed artifact: %v", err)
	}
	assertCargoDirectoryEntries(t, work)
	assertCargoDirectoryEntries(t, outDir, "policy.wasm", "policy.wasm.sig")
}

func assertCargoDirectoryEntries(t *testing.T, dir string, names ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(names) {
		t.Fatalf("unexpected staging files or sources in %s: %v", dir, entries)
	}
	for i := range entries {
		if entries[i].Name() != names[i] {
			t.Fatalf("unexpected entry %s, want %s", entries[i].Name(), names[i])
		}
	}
}
