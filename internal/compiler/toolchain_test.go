//go:build !windows

package compiler_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/policybuild"
)

const toolchainPolicyYAML = `name: toolchain-policy
version: 1
default_action: deny
rules:
  - name: deny-bin
    event: process
    conditions: {all: [{path: {eq: "/bin/x"}}]}
    action: deny
`

const fakeRustcVersion = "rustc 1.100.0 (deadbeef 2026-01-01)"

// fakeToolchain installs minimal rustup/cargo/rustc shims on PATH. When
// withRustc is false, rustc is deliberately absent so the build exercises the
// best-effort (field omitted) path.
func fakeToolchain(t *testing.T, withRustc bool) string {
	t.Helper()
	bin := t.TempDir()
	scripts := map[string]string{
		"rustup": "#!/bin/sh\necho wasm32-unknown-unknown\n",
		"cargo": "#!/bin/sh\nset -eu\nout=\nfor arg do\n" +
			"  case \"$arg\" in --emit=link=*) out=${arg#--emit=link=};; esac\n" +
			"done\ntest -n \"$out\"\n/bin/cp \"$WARMOR_TEST_ARTIFACT\" \"$out\"\n",
	}
	if withRustc {
		// Leading/trailing whitespace and a newline must be trimmed.
		scripts["rustc"] = "#!/bin/sh\nprintf '  " + fakeRustcVersion + "  \\n'\n"
	}
	for name, script := range scripts {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv("WARMOR_TEST_ARTIFACT", writeToolchainFixture(t))
	return bin
}

func writeToolchainFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "raw.wasm")
	if err := os.WriteFile(path, []byte{0, 97, 115, 109, 1, 0, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func toolchainPolicy(t *testing.T) *compiler.Policy {
	t.Helper()
	p, err := compiler.Parse([]byte(toolchainPolicyYAML))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRustcVersionIsCapturedAndTrimmed(t *testing.T) {
	fakeToolchain(t, true)
	got, err := compiler.RustcVersion()
	if err != nil {
		t.Fatal(err)
	}
	if got != fakeRustcVersion {
		t.Fatalf("RustcVersion = %q, want %q", got, fakeRustcVersion)
	}
}

func TestRustcVersionErrorWhenRustcMissing(t *testing.T) {
	fakeToolchain(t, false)
	if got, err := compiler.RustcVersion(); err == nil || got != "" {
		t.Fatalf("RustcVersion = %q, %v; want error and empty string", got, err)
	}
}

func TestBuildRecordsRustcVersionInMetadata(t *testing.T) {
	fakeToolchain(t, true)
	out := filepath.Join(t.TempDir(), "policy.wasm")
	result, err := compiler.Build(toolchainPolicy(t), compiler.BuildOptions{OutputPath: out})
	defer compiler.Cleanup(result)
	if err != nil {
		t.Fatal(err)
	}
	module, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := policybuild.Read(module)
	if err != nil || meta == nil {
		t.Fatalf("read build metadata: %+v, %v", meta, err)
	}
	if meta.RustcVersion != fakeRustcVersion {
		t.Fatalf("metadata rustc = %q, want %q", meta.RustcVersion, fakeRustcVersion)
	}
	if meta.Compiler != compiler.Identity || meta.DefaultAction != "deny" {
		t.Fatalf("unexpected build metadata: %+v", meta)
	}
}

func TestBuildOmitsRustcVersionWhenUnavailable(t *testing.T) {
	fakeToolchain(t, false)
	out := filepath.Join(t.TempDir(), "policy.wasm")
	result, err := compiler.Build(toolchainPolicy(t), compiler.BuildOptions{OutputPath: out})
	defer compiler.Cleanup(result)
	if err != nil {
		t.Fatal(err)
	}
	module, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := policybuild.Read(module)
	if err != nil || meta == nil {
		t.Fatalf("read build metadata: %+v, %v", meta, err)
	}
	if meta.RustcVersion != "" {
		t.Fatalf("rustc recorded without rustc on PATH: %q", meta.RustcVersion)
	}
}
