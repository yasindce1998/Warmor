//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package compiler

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

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
