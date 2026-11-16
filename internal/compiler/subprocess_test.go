package compiler

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/policybuild"
)

const fakeToolWasm = "\x00asm\x01\x00\x00\x00"

func init() {
	// Fake tools are exec'd with real cargo/rustup arguments, not test flags.
	name := filepath.Base(os.Args[0])
	if os.Getenv("WARMOR_COMPILER_TEST_HELPER") != "" && (strings.HasPrefix(name, "cargo") || strings.HasPrefix(name, "rustup")) {
		TestCompilerToolHelper(nil)
	}
}

// The test executable is also a portable, injected fake cargo/rustup. Children
// inherit only this test's fixture environment, never select host processes.
func TestCompilerToolHelper(t *testing.T) {
	mode := os.Getenv("WARMOR_COMPILER_TEST_HELPER")
	if mode == "" {
		return
	}
	if mode == "tree-child" || mode == "tree-grandchild" {
		if mode == "tree-child" {
			startToolTestChild("tree-grandchild")
		}
		helperPIDReady()
		for {
			time.Sleep(time.Hour)
		}
	}
	tool := filepath.Base(os.Args[0])
	if strings.HasPrefix(tool, "rustup") {
		if mode == "rustup-tree" {
			startToolTestChild("tree-child")
			helperPIDReady()
			for {
				time.Sleep(time.Hour)
			}
		}
		if mode == "rustup-flood" {
			floodToolTestOutput()
		}
		_, _ = io.WriteString(os.Stdout, "wasm32-unknown-unknown\n")
		os.Exit(0)
	}
	if mode == "cargo-tree" || mode == "cargo-parent-exit" || mode == "cargo-tree-flood" {
		startToolTestChild("tree-child")
		helperPIDReady()
		if mode == "cargo-tree-flood" {
			waitToolTestPIDs(3)
			floodToolTestOutput()
		}
		if mode == "cargo-parent-exit" {
			// Wait for the grandchild to be demonstrably alive before exit.
			waitToolTestPIDs(3)
			os.Exit(0)
		}
		for {
			time.Sleep(time.Hour)
		}
	}
	if mode == "cargo-slow" {
		writeToolTestArtifact()
		for {
			_, _ = io.WriteString(os.Stdout, "still compiling\n")
			_, _ = io.WriteString(os.Stderr, "still compiling\n")
			time.Sleep(10 * time.Millisecond)
		}
	}
	if mode == "cargo-flood" || mode == "both-flood" {
		writeToolTestArtifact()
		floodToolTestOutput()
	}
	if mode == "exact-limit" {
		_, _ = io.WriteString(os.Stdout, strings.Repeat("x", toolOutputLimit/2))
		_, _ = io.WriteString(os.Stderr, strings.Repeat("y", toolOutputLimit/2))
		os.Exit(0)
	}
	if mode == "nonzero" {
		_, _ = io.WriteString(os.Stderr, "compiler diagnostic")
		os.Exit(7)
	}
	if mode == "success" {
		writeToolTestArtifact()
		os.Exit(0)
	}
	os.Exit(2)
}

func startToolTestChild(mode string) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestCompilerToolHelper$")
	cmd.Env = append(os.Environ(), "WARMOR_COMPILER_TEST_HELPER="+mode, "GORACE=atexit_sleep_ms=0")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		panic(err)
	}
}

func helperPIDReady() {
	path := filepath.Join(os.Getenv("WARMOR_COMPILER_TEST_PIDS"), strconv.Itoa(os.Getpid()))
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		panic(err)
	}
}

func waitToolTestPIDs(n int) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		files, _ := os.ReadDir(os.Getenv("WARMOR_COMPILER_TEST_PIDS"))
		if len(files) >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	panic("helper descendants did not start")
}

func writeToolTestArtifact() {
	dir := filepath.Join(os.Getenv("CARGO_TARGET_DIR"), "wasm32-unknown-unknown", "release")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "warmor_policy_safe.wasm"), []byte(fakeToolWasm), 0o600); err != nil {
		panic(err)
	}
}

func floodToolTestOutput() {
	chunk := strings.Repeat("x", 4096)
	// Finite output followed by exit(0) catches the case where the parent exits
	// successfully before the overflow notification wins a select.
	for range toolOutputLimit/len(chunk) + 2 {
		_, _ = io.WriteString(os.Stdout, chunk)
		_, _ = io.WriteString(os.Stderr, chunk)
	}
	os.Exit(0)
}

func toolTestCommand(t *testing.T, mode string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCompilerToolHelper$")
	cmd.Env = append(os.Environ(), "WARMOR_COMPILER_TEST_HELPER="+mode, "GORACE=atexit_sleep_ms=0")
	return cmd
}

func fakeToolchain(t *testing.T, mode string) string {
	t.Helper()
	dir := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cargo", "rustup"} {
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		// Symlinks keep these fixtures cheap, but Windows development accounts
		// need not have symlink creation privileges.
		if runtime.GOOS == "windows" {
			data, err := os.ReadFile(executable)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name), data, 0o700); err != nil {
				t.Fatal(err)
			}
		} else if err := os.Symlink(executable, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("WARMOR_COMPILER_TEST_HELPER", mode)
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	return dir
}

func TestToolOutputBound(t *testing.T) {
	for _, mode := range []string{"both-flood", "exact-limit", "nonzero"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := toolTestCommand(t, mode)
			cmd.Env = append(cmd.Env, "CARGO_TARGET_DIR="+t.TempDir())
			output, err := runTool(ctx, cmd)
			if n := len(output.stdout) + len(output.stderr); n > toolOutputLimit {
				t.Fatalf("captured %d bytes, limit %d", n, toolOutputLimit)
			}
			switch mode {
			case "both-flood":
				if !errors.Is(err, errToolOutputLimit) {
					t.Fatalf("expected output overflow, got %v", err)
				}
			case "exact-limit":
				if err != nil || len(output.stdout)+len(output.stderr) != toolOutputLimit {
					t.Fatalf("exactly-at-limit output: %v, %d bytes", err, len(output.stdout)+len(output.stderr))
				}
			case "nonzero":
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 7 || output.stderr != "compiler diagnostic" {
					t.Fatalf("lost exit/diagnostic: %v, %+v", err, output)
				}
			}
		})
	}
}

func TestBuildRejectsBoundedToolFailures(t *testing.T) {
	for _, mode := range []string{"rustup-flood", "cargo-flood", "cargo-flood-verbose", "cargo-slow"} {
		t.Run(mode, func(t *testing.T) {
			verbose := mode == "cargo-flood-verbose"
			if verbose {
				mode = "cargo-flood"
				null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				stdout, stderr := os.Stdout, os.Stderr
				os.Stdout, os.Stderr = null, null
				defer func() { os.Stdout, os.Stderr = stdout, stderr; _ = null.Close() }()
			}
			fakeToolchain(t, mode)
			crates := t.TempDir()
			for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
				t.Setenv(key, crates)
			}
			output := filepath.Join(t.TempDir(), "policy.wasm")
			const oldOutput = "previous good artifact"
			if err := os.WriteFile(output, []byte(oldOutput), 0o600); err != nil {
				t.Fatal(err)
			}
			timeout := 5 * time.Second
			if mode == "cargo-slow" {
				timeout = 500 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			result, err := Build(safetyPolicy(), BuildOptions{Context: ctx, OutputPath: output, Verbose: verbose})
			if result != nil || err == nil {
				Cleanup(result)
				t.Fatalf("bounded tool failure returned result=%+v err=%v", result, err)
			}
			wantErr := errToolOutputLimit
			if mode == "cargo-slow" {
				wantErr = context.DeadlineExceeded
			}
			if !errors.Is(err, wantErr) {
				t.Fatalf("expected %v, got %v", wantErr, err)
			}
			if len(err.Error()) > toolOutputLimit+1024 {
				t.Fatalf("unbounded diagnostic: %d bytes", len(err.Error()))
			}
			data, readErr := os.ReadFile(output)
			if readErr != nil || string(data) != oldOutput {
				t.Fatalf("failed build replaced good artifact: %q, %v", data, readErr)
			}
			entries, err := os.ReadDir(crates)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), "warmor-compile-") {
					t.Fatalf("failed build leaked crate %s", entry.Name())
				}
			}
		})
	}
}

func TestBuildWithOwnedToolSuccess(t *testing.T) {
	fakeToolchain(t, "success")
	output := filepath.Join(t.TempDir(), "policy.wasm")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := Build(safetyPolicy(), BuildOptions{Context: ctx, OutputPath: output})
	defer Cleanup(result)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(result.WasmPath)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := policybuild.Read(data)
	if err != nil || metadata == nil || metadata.Compiler != Identity || metadata.DefaultAction != "allow" || !strings.HasPrefix(string(data), fakeToolWasm) {
		t.Fatalf("successful artifact lost compiler metadata: %+v, %v", metadata, err)
	}
}

func TestBuildActualCargoWithContext(t *testing.T) {
	if testing.Short() {
		t.Skip("actual Rust toolchain disabled by -short")
	}
	if !CargoAvailable() {
		if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
			t.Fatal("cargo and wasm32 target required")
		}
		t.Skip("cargo/wasm32 target unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output := filepath.Join(t.TempDir(), "policy.wasm")
	result, err := Build(safetyPolicy(), BuildOptions{Context: ctx, OutputPath: output})
	defer Cleanup(result)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(result.WasmPath)
	if err != nil || len(data) < 8 || string(data[:4]) != "\x00asm" {
		t.Fatalf("actual Cargo build did not produce Wasm: %v", err)
	}
	metadata, err := policybuild.Read(data)
	if err != nil || metadata == nil || metadata.Compiler != Identity || metadata.DefaultAction != "allow" {
		t.Fatalf("actual Cargo artifact lost compiler metadata: %+v, %v", metadata, err)
	}
}

func TestBuildCancelledBeforeToolStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := Build(safetyPolicy(), BuildOptions{Context: ctx})
	if result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled build: %+v, %v", result, err)
	}
}

func TestToolRepeatedFailuresDoNotLeakGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()
	for range 12 {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		cmd := toolTestCommand(t, "cargo-slow")
		cmd.Env = append(cmd.Env, "CARGO_TARGET_DIR="+t.TempDir())
		_, err := runTool(ctx, cmd)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected deadline, got %v", err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before {
			return
		}
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("goroutines grew after joined command failures: before=%d after=%d", before, runtime.NumGoroutine())
}
