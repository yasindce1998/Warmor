//go:build windows
// +build windows

package main

import (
	"os"
	"os/signal"
)

func notifySignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt)
}

func isReloadSignal(_ os.Signal) bool {
	return false
}

func isShutdownSignal(sig os.Signal) bool {
	return sig == os.Interrupt
}
