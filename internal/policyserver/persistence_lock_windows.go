package policyserver

import (
	"golang.org/x/sys/windows"
	"os"
)

func lockStateFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func unlockStateFile(f *os.File) error { return f.Close() }

// Windows cannot directory-fsync with os.File.Sync; use write-through replacement.
func publishSnapshot(from, to string) (bool, error) {
	src, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return false, err
	}
	dst, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return false, err
	}
	err = windows.MoveFileEx(src, dst, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
	return err == nil, err
}
