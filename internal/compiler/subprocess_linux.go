package compiler

import (
	"errors"

	"golang.org/x/sys/unix"
)

func prepareOwnedTool() error { return nil }

func toolChildExited(pid int) (bool, error) {
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return info.Signo != 0, err
	}
}

func killOwnedToolGroup(pid int) error {
	if _, err := toolChildExited(pid); err != nil {
		return err
	}
	err := unix.Kill(-pid, unix.SIGKILL)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}
