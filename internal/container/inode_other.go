//go:build !linux

package container

import "io/fs"

// inodeOf is unsupported off Linux: there are no cgroup ids to resolve.
func inodeOf(fs.FileInfo) (uint64, bool) { return 0, false }
