package enforcer

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

// victim is a long-lived child whose PID the kernel-verdict events carry, so
// the tests can prove the enforcer never kills it. A single goroutine waits
// on it and reports the exit on done.
type victim struct {
	pid  int
	done chan error
}

func startVictim(t *testing.T) *victim {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("uses sleep")
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	v := &victim{pid: cmd.Process.Pid, done: make(chan error, 1)}
	go func() { v.done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-v.done
	})
	return v
}

func requireAlive(t *testing.T, v *victim) {
	t.Helper()
	select {
	case err := <-v.done:
		v.done <- err // keep it for Cleanup
		t.Fatalf("process %d was terminated: %v", v.pid, err)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestHandleEvent_KernelDeniedIsRecordedNotReenforced(t *testing.T) {
	pm := &fakePolicyMap{}
	sink := &sinkRecorder{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyMap: pm, sink: sink})
	victim := startVictim(t)

	// The fixture policy would allow this exec; the kernel's deny must win
	// and must not be overwritten by a WASM allow in the cache or kernel map.
	e.handleEvent(&api.Event{
		PID: uint32(victim.pid), UID: 1000, Comm: "ls", Filename: "/usr/bin/ls",
		LSMEvent: true, KernelDenied: true,
	})

	stats := e.GetStats()
	if stats.Denied != 1 || stats.Allowed != 0 || stats.AuditDenied != 0 {
		t.Fatalf("stats = %+v, want exactly 1 denied", stats)
	}
	if n := e.cache.Stats().Size; n != 0 {
		t.Errorf("kernel verdict was cached (%d entries); it must not be re-evaluated", n)
	}
	if rules := pm.snapshot(); len(rules) != 0 {
		t.Errorf("kernel verdict wrote policy map rules: %+v", rules)
	}
	requireAlive(t, victim)

	e.pipeline.Close()
	if lines := sink.snapshot(); len(lines) != 1 || !strings.Contains(lines[0], "kernel policy map deny") {
		t.Errorf("streamed %q, want one line with the kernel reason", lines)
	}
}

func TestHandleEvent_NoKernelVerdictStillEvaluated(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	e.handleEvent(&api.Event{UID: 1000, Comm: "ls", Filename: "/usr/bin/ls", LSMEvent: true})
	if stats := e.GetStats(); stats.Allowed != 1 {
		t.Fatalf("stats = %+v, want the policy's allow", stats)
	}
}
