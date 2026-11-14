//go:build linux

package main

import (
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// bootstrap reads no IPC and runs no guest code. Go's os/exec does not close
// arbitrary non-CLOEXEC descriptors inherited from the supervisor. Do not close
// them in this running Go runtime: fd numbers may also belong to its netpoller.
// Instead unshare this locked thread's fd table, mark everything except the
// explicit 0/1/2 allowlist CLOEXEC, and immediately replace the process image.
// The second exec discards this runtime and starts a fresh one with clean fds.
// No goroutine from another thread may add descriptors to the unshared table.
func bootstrap() {
	runtime.LockOSThread()
	if err := unix.CloseRange(3, uint(^uint32(0)), unix.CLOSE_RANGE_UNSHARE|unix.CLOSE_RANGE_CLOEXEC); err != nil {
		os.Exit(1)
	}
	// /proc/self/exe names the running, already digest-validated inode, even
	// after an atomic installer rename. fd 3 is closed by this exec too.
	if err := syscall.Exec("/proc/self/exe", []string{"warmor-policy-host", "--serve"}, []string{"GOMAXPROCS=1"}); err != nil {
		os.Exit(1)
	}
}
