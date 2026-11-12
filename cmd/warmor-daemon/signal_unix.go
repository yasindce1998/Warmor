//go:build !windows
// +build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func notifySignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
}

func isReloadSignal(sig os.Signal) bool {
	return sig == syscall.SIGHUP
}

func isShutdownSignal(sig os.Signal) bool {
	return sig == os.Interrupt || sig == syscall.SIGTERM
}
