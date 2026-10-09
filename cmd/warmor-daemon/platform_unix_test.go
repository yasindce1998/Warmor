//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func TestSignalClassification(t *testing.T) {
	tests := []struct {
		sig              os.Signal
		reload, shutdown bool
	}{
		{syscall.SIGHUP, true, false},
		{os.Interrupt, false, true},
		{syscall.SIGTERM, false, true},
		{syscall.SIGUSR1, false, false},
	}
	for _, tt := range tests {
		if got := isReloadSignal(tt.sig); got != tt.reload {
			t.Errorf("isReloadSignal(%v) = %v, want %v", tt.sig, got, tt.reload)
		}
		if got := isShutdownSignal(tt.sig); got != tt.shutdown {
			t.Errorf("isShutdownSignal(%v) = %v, want %v", tt.sig, got, tt.shutdown)
		}
	}
}

func TestNotifySignals_DeliversSIGHUP(t *testing.T) {
	ch := make(chan os.Signal, 1)
	notifySignals(ch)
	t.Cleanup(func() { signal.Stop(ch) })

	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case sig := <-ch:
		if !isReloadSignal(sig) {
			t.Errorf("got %v, want SIGHUP", sig)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SIGHUP not delivered")
	}
}

func TestStartPolicyWatcher_NoOpOnUnix(t *testing.T) {
	ch := make(chan struct{}, 1)
	stop := startPolicyWatcher("/does/not/matter.wasm", ch)
	if stop == nil {
		t.Fatal("stop func must not be nil")
	}
	stop()
	select {
	case <-ch:
		t.Error("no-op watcher should never signal reload")
	default:
	}
}

func TestServiceStubs(t *testing.T) {
	if isWindowsService() {
		t.Error("isWindowsService() should be false off Windows")
	}
	if handleServiceCommand([]string{"install"}) || handleServiceCommand(nil) {
		t.Error("handleServiceCommand should never handle commands off Windows")
	}
	runService() // must be a harmless no-op
}
