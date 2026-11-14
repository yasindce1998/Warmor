package compiler

import (
	"errors"

	"golang.org/x/sys/unix"
)

func observeToolExit(pid int) (func() (bool, error), func(), error) {
	return func() (bool, error) {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)
		if errors.Is(err, unix.EINTR) {
			return false, nil
		}
		return info.Signo != 0, err
	}, func() {}, nil
}
