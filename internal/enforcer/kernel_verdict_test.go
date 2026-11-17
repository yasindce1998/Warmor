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
		LSMEvent: true, KernelTimestampNS: 1, KernelDenied: true,
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

func TestHandleEvent_IntegrityEnforceViolation(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	victim := startVictim(t)

	e.handleEvent(&api.Event{
		PID: uint32(victim.pid), Comm: "dropper", Filename: "/tmp/dropper",
		Type: api.EventTypeProcess, LSMEvent: true, KernelTimestampNS: 1, KernelDenied: true, IntegrityViolation: true,
	})

	if stats := e.GetStats(); stats.Denied != 1 {
		t.Fatalf("stats = %+v, want 1 denied", stats)
	}
	requireAlive(t, victim)
}

func TestHandleEvent_IntegrityAuditViolation(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	victim := startVictim(t)

	// Audit mode: the exec ran; report a would-deny without acting.
	e.handleEvent(&api.Event{
		PID: uint32(victim.pid), Comm: "dropper", Filename: "/tmp/dropper",
		Type: api.EventTypeProcess, LSMEvent: true, KernelTimestampNS: 1, IntegrityViolation: true,
	})

	stats := e.GetStats()
	if stats.AuditDenied != 1 || stats.Denied != 0 {
		t.Fatalf("stats = %+v, want 1 audit-denied", stats)
	}
	requireAlive(t, victim)
}

func TestHandleEvent_NoKernelVerdictStillEvaluated(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	e.handleEvent(&api.Event{UID: 1000, Comm: "ls", Filename: "/usr/bin/ls", LSMEvent: true})
	if stats := e.GetStats(); stats.Allowed != 1 {
		t.Fatalf("stats = %+v, want the policy's allow", stats)
	}
}

// Synthetic events can set verdict flags in memory, but only an in-tree LSM
// event (LSMEvent plus a raw kernel timestamp) is allowed to suppress
// userspace evaluation and be recorded as a kernel verdict.
func TestHandleKernelVerdict_UntrustedFlagsIgnored(t *testing.T) {
	for _, tc := range []struct {
		name  string
		event *api.Event
	}{
		{
			name: "kernel-denied without LSM",
			event: &api.Event{PID: 0, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls",
				KernelDenied: true, KernelTimestampNS: 1},
		},
		{
			name: "kernel-denied without kernel timestamp",
			event: &api.Event{PID: 0, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls",
				LSMEvent: true, KernelDenied: true},
		},
		{
			name: "integrity violation without LSM",
			event: &api.Event{PID: 0, Type: api.EventTypeProcess, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls",
				IntegrityViolation: true, KernelTimestampNS: 1},
		},
		{
			name: "integrity violation without kernel timestamp",
			event: &api.Event{PID: 0, Type: api.EventTypeProcess, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls",
				LSMEvent: true, IntegrityViolation: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newTestEnforcer(t, testEnforcerOpts{})
			inProcessEvaluator(t, e).SetTimeout(5 * time.Second)
			e.handleEvent(tc.event)
			if stats := e.GetStats(); stats.Allowed != 1 || stats.Denied != 0 || stats.AuditDenied != 0 {
				t.Fatalf("untrusted verdict must not suppress policy evaluation: %+v", stats)
			}
		})
	}
}
