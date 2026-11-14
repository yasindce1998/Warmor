//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package policyserver

import (
	"os"
	"path/filepath"
	"syscall"
)

func lockStateFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func unlockStateFile(f *os.File) error { return f.Close() }

func publishSnapshot(from, to string) (bool, error) {
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
