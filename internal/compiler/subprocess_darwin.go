package compiler

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Darwin's public sys/proc.h values (not provided by x/sys/unix).
const (
	darwinNoChildWait = 0x40000000 // P_NOCLDWAIT: SIGCHLD SIG_IGN or SA_NOCLDWAIT
	darwinZombie      = 5          // SZOMB
	darwinWaitPID     = 1          // P_PID from sys/wait.h
)

func prepareOwnedTool() error {
	self, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
	if err != nil {
		return fmt.Errorf("check Darwin child-wait mode: %w", err)
	}
	if self.Proc.P_flag&darwinNoChildWait != 0 {
		return errors.New("toolchain requires waitable children: SIGCHLD SIG_IGN/SA_NOCLDWAIT is unsupported")
	}
	return nil
}

// darwinSiginfo is the 64-bit siginfo_t ABI in XNU's sys/signal.h on both
// amd64 and arm64. Only si_pid is read; initialize it to zero for WNOHANG.
type darwinSiginfo struct {
	signo, errno, code, pid int32
	uid                     uint32
	status                  int32
	addr, value, band       uint64
	pad                     [7]uint64
}

func toolChildExited(pid int) (bool, error) {
	for {
		var info darwinSiginfo
		// x/sys has no Darwin Waitid wrapper. SYS_WAITID is the native BSD
		// waitid(P_PID, pid, ..., WNOWAIT) syscall, not wait4 (which reaps).
		// The nonblocking syscall also returns ECHILD for an externally reaped
		// child; unlike kqueue ESRCH, that is an actual wait-ownership check.
		_, _, errno := syscall.Syscall6(unix.SYS_WAITID, darwinWaitPID, uintptr(pid), uintptr(unsafe.Pointer(&info)),
			unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, 0, 0)
		runtime.KeepAlive(&info)
		if errors.Is(errno, unix.EINTR) {
			continue
		}
		if errno != 0 {
			return false, errno
		}
		return info.pid != 0, nil
	}
}

func killOwnedToolGroup(pid int) error {
	return killDarwinToolGroup(pid, unix.Kill)
}

func killDarwinToolGroup(pid int, signalGroup func(int, syscall.Signal) error) error {
	if err := prepareOwnedTool(); err != nil {
		return err
	}
	if _, err := toolChildExited(pid); err != nil {
		return err
	}
	err := signalGroup(-pid, unix.SIGKILL)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if !errors.Is(err, unix.EPERM) {
		return err
	}
	// XNU killpg1 excludes SZOMB and can report EPERM for a zombie-only
	// group. Do NOT suppress EPERM for a group containing any live member.
	// The leader stays waitable and pins this group ID throughout inspection.
	members, inspectErr := unix.SysctlKinfoProcSlice("kern.proc.pgrp", pid)
	if inspectErr != nil {
		return errors.Join(err, fmt.Errorf("inspect owned Darwin group: %w", inspectErr))
	}
	if !darwinGroupOnlyZombies(pid, os.Getpid(), members) {
		return err
	}
	// An external reaper between the first probe and inspection must not turn
	// an unowned/missing leader into an apparent successful cleanup.
	_, inspectErr = toolChildExited(pid)
	return inspectErr
}

func darwinGroupOnlyZombies(pid, parent int, members []unix.KinfoProc) bool {
	leader := false
	for _, member := range members {
		if member.Eproc.Pgid != int32(pid) || member.Proc.P_stat != darwinZombie {
			return false
		}
		if member.Proc.P_pid == int32(pid) && member.Eproc.Ppid == int32(parent) {
			leader = true
		}
	}
	return leader
}
