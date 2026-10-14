//go:build linux

package container

import (
	"io/fs"
	"syscall"
)

// inodeOf returns the inode number, which for a cgroup v2 directory is the
// cgroup id BPF reports.
func inodeOf(fi fs.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Ino, true
}
