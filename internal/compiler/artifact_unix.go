//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package compiler

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func checkArtifactLinkCount(_ *os.File, info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return fmt.Errorf("cannot establish wasm artifact link count")
	}
	if st.Nlink != 1 {
		return fmt.Errorf("wasm artifact must be singly-linked (link count %d)", st.Nlink)
	}
	return nil
}

func checkArtifactIdentity(path string, _ *os.File, opened os.FileInfo) error {
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !current.Mode().IsRegular() || !os.SameFile(current, opened) {
		return fmt.Errorf("wasm artifact changed while opening")
	}
	return nil
}

func openArtifact(path string, write bool) (*os.File, error) {
	flags := os.O_RDONLY
	if write {
		flags = os.O_WRONLY
	}
	// NONBLOCK prevents a raced-in FIFO from hanging before the fstat check.
	return os.OpenFile(path, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
}

// Match the durable replacement pattern used by agentstore/policyserver.
func replaceArtifact(from, to string) (bool, error) {
	if err := os.Rename(from, to); err != nil {
		return false, err
	}
	dir, err := os.Open(filepath.Dir(to))
	if err != nil {
		return true, err
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err == nil {
		err = closeErr
	}
	return true, err
}
