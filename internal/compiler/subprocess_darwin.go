package compiler

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

func observeToolExit(pid int) (func() (bool, error), func(), error) {
	// kqueue has no atomic close-on-exec creation flag on Darwin. Coordinate
	// with concurrent os/exec starts so children cannot inherit this observer.
	syscall.ForkLock.RLock()
	fd, err := unix.Kqueue()
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, nil, err
	}
	closeObserver := func() { _ = unix.Close(fd) }
	changes := []unix.Kevent_t{{
		Ident: uint64(pid), Filter: unix.EVFILT_PROC,
		Flags: unix.EV_ADD | unix.EV_ENABLE | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT,
	}}
	_, err = unix.Kevent(fd, changes, nil, nil)
	if errors.Is(err, unix.ESRCH) {
		// The child exited before registration. It has not been reaped, so its
		// PID still pins our process group just as a NOTE_EXIT notification does.
		return func() (bool, error) { return true, nil }, closeObserver, nil
	}
	if err != nil {
		closeObserver()
		return nil, nil, err
	}
	return func() (bool, error) {
		var events [1]unix.Kevent_t
		n, err := unix.Kevent(fd, nil, events[:], &unix.Timespec{})
		if errors.Is(err, unix.EINTR) {
			return false, nil
		}
		if n > 0 && events[0].Flags&unix.EV_ERROR != 0 {
			return false, unix.Errno(events[0].Data)
		}
		return n > 0, err
	}, closeObserver, nil
}
