//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package compiler

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

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
