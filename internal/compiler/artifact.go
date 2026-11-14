package compiler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Bound both the tool's output read and the final metadata-bearing artifact.
const maxCompiledArtifactBytes = 64 << 20

// ErrArtifactPublicationIndeterminate means replacement succeeded but durability
// could not be confirmed, or the OS cannot establish whether replacement took
// place. Inspect the destination before using it or retrying. This is not a
// claim that the old artifact was preserved.
var ErrArtifactPublicationIndeterminate = errors.New("compiled artifact publication/durability indeterminate; inspect destination before use or retry")

func readBuiltArtifact(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := checkBuiltArtifact(info); err != nil {
		return nil, err
	}
	f, err := openArtifact(path, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Check the opened object too: Lstat alone would race a symlink/FIFO swap.
	opened, err := checkedArtifactInfo(f)
	if err != nil {
		return nil, err
	}
	if err := checkArtifactIdentity(path, f, opened); err != nil {
		return nil, err
	}
	if err := checkBuiltArtifact(opened); err != nil {
		return nil, err
	}
	// Do not trust only Stat: a tool's surviving writer could grow the file.
	data, err := io.ReadAll(io.LimitReader(f, maxCompiledArtifactBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCompiledArtifactBytes {
		return nil, fmt.Errorf("built wasm exceeds %d bytes", maxCompiledArtifactBytes)
	}
	// Recheck the same handle after the bounded read, including its link count.
	if _, err := checkedArtifactInfo(f); err != nil {
		return nil, err
	}
	return data, nil
}

func checkedArtifactInfo(f *os.File) (os.FileInfo, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("wasm artifact must be a singly-linked regular file")
	}
	if err := checkArtifactLinkCount(f, info); err != nil {
		return nil, err
	}
	return info, nil
}

func checkBuiltArtifact(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("built wasm must be a regular file, not a symlink or special file")
	}
	if info.Size() > maxCompiledArtifactBytes {
		return fmt.Errorf("built wasm exceeds %d bytes", maxCompiledArtifactBytes)
	}
	return nil
}

// Per-publication seams let tests fail individual filesystem operations without
// global hooks or allowing Build callers to disable durability.
type artifactPublisher struct {
	write    func(*os.File, []byte) (int, error)
	fileSync func(*os.File) error
	close    func(*os.File) error
	// The bool is true if replacement happened OR may have happened.
	replace func(string, string) (bool, error)
}

func newArtifactPublisher() artifactPublisher {
	return artifactPublisher{
		write:    func(f *os.File, data []byte) (int, error) { return f.Write(data) },
		fileSync: func(f *os.File) error { return f.Sync() },
		close:    func(f *os.File) error { return f.Close() },
		replace:  replaceArtifact,
	}
}

func (p artifactPublisher) publish(ctx context.Context, path string, data []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if path == "" {
		path = "policy.wasm"
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve output wasm: %w", err)
	}
	mode, existing, err := outputArtifactMode(path)
	if err != nil {
		return "", fmt.Errorf("check output wasm: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".warmor-policy-*")
	if err != nil {
		return "", fmt.Errorf("stage output wasm: %w", err)
	}
	defer os.Remove(f.Name())
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
	}()
	n, err := p.write(f, data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return "", fmt.Errorf("write staged wasm: %w", err)
	}
	if existing {
		if err := f.Chmod(mode); err != nil {
			return "", fmt.Errorf("set output wasm mode: %w", err)
		}
	}
	// New outputs retain CreateTemp's 0600 filtered by the caller's umask.
	// Chmod(0644) here would bypass a restrictive umask. Do not read/change the
	// process-wide umask: compilation can run concurrently with other file I/O.
	if err := p.fileSync(f); err != nil {
		return "", fmt.Errorf("sync staged wasm: %w", err)
	}
	if err := p.close(f); err != nil {
		return "", fmt.Errorf("close staged wasm: %w", err)
	}
	closed = true
	// Cancellation is honored up to the commit boundary. Once replacement has
	// occurred, report its outcome rather than a misleading cancellation error.
	if err := ctx.Err(); err != nil {
		return "", err
	}
	mayHavePublished, err := p.replace(f.Name(), path)
	if err != nil {
		if mayHavePublished {
			return "", fmt.Errorf("%w (%s): %w", ErrArtifactPublicationIndeterminate, path, err)
		}
		return "", fmt.Errorf("replace output wasm: %w", err)
	}
	return path, nil
}

func outputArtifactMode(path string) (mode os.FileMode, existing bool, err error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if !info.Mode().IsRegular() {
		return 0, false, fmt.Errorf("output wasm must be a regular file, not a symlink or special file")
	}
	// Rename permission alone would allow bypassing an existing read-only file.
	if info.Mode().Perm()&0o222 == 0 {
		return 0, false, os.ErrPermission
	}
	f, err := openArtifact(path, true) // Check writability, never truncate.
	if err != nil {
		return 0, false, err
	}
	defer f.Close()
	opened, err := checkedArtifactInfo(f)
	if err != nil {
		return 0, false, err
	}
	if err := checkArtifactIdentity(path, f, opened); err != nil {
		return 0, false, err
	}
	if err := f.Close(); err != nil {
		return 0, false, err
	}
	return opened.Mode().Perm(), true, nil
}
