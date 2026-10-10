package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
)

const validPolicy = `name: test-policy
version: 1
description: compile test
variables:
  blocked_bins:
    - /usr/bin/nc
rules:
  - name: block-tmp-exec
    event: process
    conditions:
      all:
        - path: { glob: "/tmp/**" }
    action: deny
    reason: no tmp
  - name: block-nc
    event: process
    conditions:
      all:
        - path: { any_of: $blocked_bins }
    action: deny
default_action: allow
`

func writePolicy(t *testing.T, content string) string {
	t.Helper()
	return writeFile(t, filepath.Join(t.TempDir(), "policy.yaml"), content)
}

func TestCompile_Validate(t *testing.T) {
	r := runChild(t, nil, "-validate", writePolicy(t, validPolicy))
	if r.code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", r.code, r.stderr)
	}
	assertContains(t, "stdout", r.stdout, "test-policy is valid (2 rules, default_action=allow)")
}

func TestCompile_RustOnlyMatchesGenerator(t *testing.T) {
	path := writePolicy(t, validPolicy)
	r := runChild(t, nil, "--rust-only", path)
	if r.code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", r.code, r.stderr)
	}
	p, err := compiler.ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := compiler.GenerateRust(p)
	if err != nil {
		t.Fatal(err)
	}
	if r.stdout != want {
		t.Errorf("--rust-only output differs from compiler.GenerateRust (len %d vs %d)", len(r.stdout), len(want))
	}
}

func TestCompile_NoCargo(t *testing.T) {
	// An empty PATH makes the toolchain lookup fail without touching rustup.
	r := runChild(t, []string{"PATH=" + t.TempDir()}, writePolicy(t, validPolicy))
	if r.code != 1 {
		t.Fatalf("exit = %d, want 1", r.code)
	}
	assertContains(t, "stderr", r.stderr, "Rust toolchain not found", "--rust-only")
}

func TestCompile_Errors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no input", nil, "no input file specified"},
		{"missing file", []string{filepath.Join(t.TempDir(), "nope.yaml")}, "error:"},
		{"invalid yaml", []string{"-validate", writePolicy(t, "rules: [unclosed")}, "error:"},
		{"invalid action", []string{"-validate", writePolicy(t, `name: x
version: 1
rules:
  - name: r
    event: process
    conditions:
      all:
        - path: { eq: /x }
    action: obliterate
default_action: allow
`)}, "error:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runChild(t, nil, tt.args...)
			if r.code != 1 {
				t.Errorf("exit = %d, want 1 (stdout: %s, stderr: %s)", r.code, r.stdout, r.stderr)
			}
			assertContains(t, "stderr", r.stderr, tt.want)
		})
	}
}

func TestCompile_UsageAndVersion(t *testing.T) {
	r := runChild(t, nil)
	assertContains(t, "usage", r.stderr, "Usage: warmor-compile", "--rust-only policy.yaml")
	r = runChild(t, nil, "-version")
	if r.code != 0 {
		t.Fatalf("exit = %d", r.code)
	}
	assertContains(t, "stdout", r.stdout, "warmor-compile ")
}

// TestCompile_FullBuild exercises the real cargo build path in-process. It is
// opt-in because it needs a Rust toolchain with the wasm32 target and may
// fetch crates from the network.
func TestCompile_FullBuild(t *testing.T) {
	if os.Getenv("WARMOR_TEST_CARGO_BUILD") != "1" {
		t.Skip("set WARMOR_TEST_CARGO_BUILD=1 to run the cargo build test")
	}
	if !compiler.CargoAvailable() {
		t.Skip("cargo with wasm32-unknown-unknown not available")
	}
	out := filepath.Join(t.TempDir(), "out.wasm")
	stdout, _ := runMain(t, "", "-o", out, writePolicy(t, validPolicy))
	assertContains(t, "stdout", stdout, "Compiling test-policy (2 rules)", "Compiled to")
	if fi, err := os.Stat(out); err != nil || fi.Size() == 0 {
		t.Errorf("wasm output missing or empty: %v", err)
	}
}
