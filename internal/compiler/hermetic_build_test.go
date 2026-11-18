package compiler

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests reproduce the non-hermetic compiler subprocess: the child used to
// inherit the whole environment and run under a temp-dir working directory, so
// a planted rustc wrapper (env var or parent .cargo/config.toml) executed code
// inside builds of controller-supplied policy input.
func requireWasmToolchain(t *testing.T) {
	t.Helper()
	if !CargoAvailable() {
		if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
			t.Fatal("required Rust wasm32 toolchain missing")
		}
		t.Skip("requires Rust wasm32 toolchain")
	}
}

func writePlantedWrapper(t *testing.T, dir, marker string) string {
	t.Helper()
	wrapper := filepath.Join(dir, "planted-rustc-wrapper")
	body := fmt.Sprintf("#!/bin/sh\nprintf planted > %q\nexec \"$@\"\n", marker)
	if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return wrapper
}

func TestHermeticBuildIgnoresPlantedRustcWrapperEnv(t *testing.T) {
	requireWasmToolchain(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker")
	wrapper := writePlantedWrapper(t, dir, marker)

	t.Setenv("CARGO_BUILD_RUSTC_WRAPPER", wrapper)
	t.Setenv("RUSTC_WRAPPER", wrapper)

	out := filepath.Join(dir, "policy.wasm")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := Build(safetyPolicy(), BuildOptions{Context: ctx, OutputPath: out})
	defer Cleanup(result)
	if err != nil {
		t.Fatalf("build with planted wrappers: %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("planted rustc wrapper executed during build")
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat marker: %v", err)
	}
	if data, err := os.ReadFile(out); err != nil || len(data) < 4 || string(data[:4]) != "\x00asm" {
		t.Fatalf("build did not produce wasm: %v", err)
	}
}

func TestHermeticBuildIgnoresAncestorCargoConfig(t *testing.T) {
	requireWasmToolchain(t)
	// Build places its private crate below TMPDIR; plant config in that parent.
	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	marker := filepath.Join(parent, "marker")
	wrapper := writePlantedWrapper(t, parent, marker)
	configDir := filepath.Join(parent, ".cargo")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := "[build]\nrustc-wrapper = \"" + filepath.ToSlash(wrapper) + "\"\n"
	if err := os.WriteFile(filepath.Join(configDir, "config.toml"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "policy.wasm")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := Build(safetyPolicy(), BuildOptions{Context: ctx, OutputPath: out})
	defer Cleanup(result)
	if err != nil {
		t.Fatalf("build with planted parent cargo config: %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("rustc-wrapper from parent .cargo/config.toml executed during build")
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat marker: %v", err)
	}
	if data, err := os.ReadFile(out); err != nil || len(data) < 4 || string(data[:4]) != "\x00asm" {
		t.Fatalf("build did not produce wasm: %v", err)
	}
}

// TestHermeticBuildCompilerReceivesAllowlistedEnv observes the real subprocess:
// a PATH-local rustc records its environment, then delegates to the real
// toolchain. It proves the allowlist is actually applied to the child, not
// just unit-tested in isolation.
func TestHermeticBuildCompilerReceivesAllowlistedEnv(t *testing.T) {
	requireWasmToolchain(t)
	realRustc, err := exec.LookPath("rustc")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	logFile := filepath.Join(dir, "child-env")
	script := fmt.Sprintf("#!/bin/sh\nenv > %q\nexec %q \"$@\"\n", logFile, realRustc)
	if err := os.WriteFile(filepath.Join(bin, "rustc"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RUSTFLAGS", "-C debug-assertions=yes")
	t.Setenv("CARGO_ENCODED_RUSTFLAGS", "--cfg=planted")

	out := filepath.Join(dir, "policy.wasm")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := Build(safetyPolicy(), BuildOptions{Context: ctx, OutputPath: out})
	defer Cleanup(result)
	if err != nil {
		t.Fatalf("build with observing rustc: %v", err)
	}
	recorded, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("compiler never received the allowlisted environment: %v", err)
	}
	keys := make(map[string]bool)
	for _, line := range strings.Split(string(recorded), "\n") {
		key, _, _ := strings.Cut(line, "=")
		keys[key] = true
	}
	for _, key := range []string{"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_WRAPPER", "RUSTC_BOOTSTRAP"} {
		if keys[key] {
			t.Fatalf("child compiler saw %q from parent environment", key)
		}
	}
	for _, key := range []string{"PATH", "HOME", "TMPDIR", "CARGO_HOME", "RUSTUP_HOME"} {
		if !keys[key] {
			t.Fatalf("child compiler did not see required %q", key)
		}
	}
}

func TestHermeticBuildEnvStripsRedirections(t *testing.T) {
	dir := t.TempDir()
	env := hermeticBuildEnv(dir)
	seen := make(map[string]bool, len(env))
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if seen[key] {
			t.Fatalf("duplicate env key %q", key)
		}
		seen[key] = true
	}
	for _, key := range []string{
		"RUSTFLAGS", "RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WRAPPER",
		"CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_BOOTSTRAP",
		"LD_PRELOAD", "DYLD_INSERT_LIBRARIES",
	} {
		if seen[key] {
			t.Fatalf("dangerous env key %q survived hermetic allowlist", key)
		}
	}
	for _, key := range []string{"PATH", "HOME", "TMPDIR", "CARGO_HOME", "RUSTUP_HOME"} {
		if !seen[key] {
			t.Fatalf("required env key %q missing from hermetic allowlist", key)
		}
	}
}
