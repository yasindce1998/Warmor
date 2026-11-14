//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package compiler

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/policybuild"
	"golang.org/x/sys/unix"
)

func TestBuildArtifactRestrictiveUmask(t *testing.T) {
	if os.Getenv("WARMOR_TEST_UMASK_CHILD") != "1" {
		if !CargoAvailable() {
			if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
				t.Fatal("required Rust wasm32 toolchain missing")
			}
			t.Skip("requires Rust wasm32 toolchain")
		}
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		// Set umask only in a fresh subprocess, never in the Go test process.
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "umask 077; exec \"$@\"", "warmor-umask-test", exe,
			"-test.run=^TestBuildArtifactRestrictiveUmask$", "-test.v")
		cmd.Env = append(os.Environ(), "WARMOR_TEST_UMASK_CHILD=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("real Cargo build under umask 077: %v\n%s", err, output)
		}
		t.Logf("umask subprocess: %s", output)
		return
	}

	dir, work := t.TempDir(), t.TempDir()
	t.Setenv("TMPDIR", work)
	ordinary := filepath.Join(dir, "ordinary")
	if err := os.WriteFile(ordinary, []byte("normal creation"), 0o644); err != nil {
		t.Fatal(err)
	}
	assertArtifactMode(t, ordinary, 0o600) // Establish the child's effective umask.
	policy, err := Parse([]byte(sampleYAML))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	path := filepath.Join(dir, "policy.wasm")
	result, err := Build(policy, BuildOptions{Context: ctx, OutputPath: path})
	defer Cleanup(result)
	if err != nil {
		t.Fatal(err)
	}
	assertArtifactMode(t, path, 0o600)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := policybuild.Read(data)
	if err != nil || metadata == nil || metadata.Compiler != Identity || metadata.DefaultAction != policy.DefaultAction {
		t.Fatalf("real Cargo output metadata = %+v, %v", metadata, err)
	}
	Cleanup(result)
	assertOnlyOutput(t, work)
	assertOnlyOutput(t, dir, "ordinary", "policy.wasm")
}

func TestArtifactPublicationPreservesExistingMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.wasm")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := newArtifactPublisher().publish(context.Background(), path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	assertArtifactMode(t, path, 0o640)
	assertArtifactContents(t, path, []byte("new"))
	assertOnlyOutput(t, dir, "policy.wasm")
}

func assertArtifactMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("%s mode = %o, want %o", path, info.Mode().Perm(), want)
	}
}

func TestArtifactRejectsFIFOsWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fifo.wasm")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBuiltArtifact(path); err == nil {
		t.Fatal("FIFO accepted as cargo output")
	}
	// Test the race-safe open itself: NONBLOCK must permit fstat rejection.
	f, err := openArtifact(path, false)
	if err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	_ = f.Close()
	if err != nil || checkBuiltArtifact(info) == nil {
		t.Fatalf("opened FIFO not rejected: %v", err)
	}
	if _, err := newArtifactPublisher().publish(context.Background(), path, []byte("new")); err == nil {
		t.Fatal("FIFO accepted as destination")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("FIFO replaced: %v, %v", info, err)
	}
	assertOnlyOutput(t, dir, "fifo.wasm")
}
