//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

// Package privatefile opens sensitive recordings without following symlinks.
package privatefile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// directory walks every component by descriptor. Existing ancestors must not be
// writable by other users (sticky shared ancestors such as /tmp are allowed).
// New directories are private. privateLeaf tightens an owned store directory.
func directory(path string, privateLeaf, create bool) (int, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.Split(strings.TrimPrefix(abs, "/"), "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == unix.ENOENT && create {
			if err = unix.Mkdirat(fd, part, 0700); err == nil || err == unix.EEXIST {
				next, err = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			unix.Close(fd)
			return -1, err
		}
		leaf := i == len(parts)-1
		if privateLeaf && leaf {
			if st.Uid != uint32(os.Geteuid()) {
				unix.Close(fd)
				return -1, fmt.Errorf("recording directory is not owned by current user")
			}
			if err := unix.Fchmod(fd, 0700); err != nil {
				unix.Close(fd)
				return -1, err
			}
		} else if (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (st.Mode&0022 != 0 && st.Mode&unix.S_ISVTX == 0) || (leaf && st.Mode&0022 != 0) {
			unix.Close(fd)
			return -1, fmt.Errorf("untrusted recording directory %s", path)
		}
	}
	return fd, nil
}

// OpenAppend creates 0600 regular files, or tightens existing singly-linked,
// current-user-owned regular files before any new sensitive bytes are appended.
// privateDir additionally requires/tightens the leaf store directory to 0700.
func OpenAppend(path string, privateDir, createDirs bool) (*os.File, error) {
	dir, err := directory(filepath.Dir(path), privateDir, createDirs)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, filepath.Base(path), unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err == nil {
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
			err = fmt.Errorf("recording must be a singly-linked regular file owned by current user")
		} else {
			err = unix.Fchmod(fd, 0600)
		}
	}
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// Rotate verifies the active pathname still identifies the opened private file,
// then renames within its checked directory. Other users cannot swap entries in
// that directory. Existing archive names are rejected, including symlinks.
func Rotate(path, archive string, file *os.File) error {
	if filepath.Dir(path) != filepath.Dir(archive) {
		return fmt.Errorf("archive must share recording directory")
	}
	dir, err := directory(filepath.Dir(path), false, false)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	var actual, expected unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &expected); err != nil {
		return err
	}
	if err := unix.Fstatat(dir, filepath.Base(path), &actual, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if actual.Dev != expected.Dev || actual.Ino != expected.Ino || actual.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("active recording path changed")
	}
	if actual.Nlink != 1 || actual.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("unsafe active recording")
	}
	if err := unix.Fchmod(int(file.Fd()), 0600); err != nil {
		return err
	}
	if err := unix.Fstatat(dir, filepath.Base(archive), &actual, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
		return fmt.Errorf("archive already exists or cannot be checked")
	}
	return unix.Renameat(dir, filepath.Base(path), dir, filepath.Base(archive))
}
