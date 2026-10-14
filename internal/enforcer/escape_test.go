package enforcer

import (
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/pkg/api"
)

func nsenterEvent(pid uint32) *api.Event {
	return &api.Event{
		Type: api.EventTypeProcess, PID: pid, UID: 1000, Comm: "sh",
		Filename: "/usr/bin/nsenter", CgroupID: 42, LSMEvent: true, Hook: "exec",
		Process: &api.ProcessEvent{Filename: "/usr/bin/nsenter"},
	}
}

func withEscape(t *testing.T, e *Enforcer, mode string) {
	t.Helper()
	d, err := newEscapeDetector(mode, func(id uint64) bool { return id == 42 })
	if err != nil {
		t.Fatal(err)
	}
	e.escape = d
}

func TestEscape_AlertModeDoesNotChangeDecision(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	withEscape(t, e, EscapeAlert)

	e.handleEvent(nsenterEvent(0))

	if n := len(e.escape.Alerts()); n != 1 {
		t.Fatalf("got %d escape alerts, want 1", n)
	}
	// The fixture policy allows the exec; alert mode must not deny it.
	if stats := e.GetStats(); stats.Allowed != 1 || stats.Denied != 0 {
		t.Fatalf("stats = %+v, want the policy's allow", stats)
	}
}

func TestEscape_DenyModeEnforces(t *testing.T) {
	sink := &sinkRecorder{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{sink: sink})
	withEscape(t, e, EscapeDeny)

	// PID 0: handleDeny skips the kill, nothing real is signalled.
	e.handleEvent(nsenterEvent(0))

	if stats := e.GetStats(); stats.Denied != 1 || stats.Allowed != 0 {
		t.Fatalf("stats = %+v, want 1 denied", stats)
	}
	if n := e.cache.Stats().Size; n != 0 {
		t.Errorf("escape deny was cached (%d entries); it depends on history, not the event", n)
	}
	e.pipeline.Close()
	lines := sink.snapshot()
	if len(lines) != 1 || !strings.Contains(lines[0], "escape detected") {
		t.Errorf("streamed %q, want the escape deny", lines)
	}
}

func TestEscape_DenyModeLearningOnlyAudits(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{learning: true})
	withEscape(t, e, EscapeDeny)
	victim := startVictim(t)

	e.handleEvent(nsenterEvent(uint32(victim.pid)))

	if stats := e.GetStats(); stats.AuditDenied != 1 || stats.Denied != 0 {
		t.Fatalf("stats = %+v, want an audit-only deny in learning mode", stats)
	}
	requireAlive(t, victim)
}

func TestEscape_KernelDeniedStillAlerts(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	withEscape(t, e, EscapeDeny)
	victim := startVictim(t)

	ev := nsenterEvent(uint32(victim.pid))
	ev.KernelDenied = true
	e.handleEvent(ev)

	if n := len(e.escape.Alerts()); n != 1 {
		t.Fatalf("got %d alerts, want 1 for a blocked escape attempt", n)
	}
	// Recorded once, by the kernel-verdict path; never killed (exec failed).
	if stats := e.GetStats(); stats.Denied != 1 {
		t.Fatalf("stats = %+v, want 1 denied", stats)
	}
	requireAlive(t, victim)
}

func TestEscape_HostCgroupIgnored(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	withEscape(t, e, EscapeDeny)
	ev := nsenterEvent(0)
	ev.CgroupID = 7 // not a container
	e.handleEvent(ev)
	if n := len(e.escape.Alerts()); n != 0 {
		t.Fatalf("host nsenter alerted: %d", n)
	}
}

func TestNewEscapeDetector_Modes(t *testing.T) {
	for _, m := range []string{"", EscapeOff} {
		if d, err := newEscapeDetector(m, nil); err != nil || d != nil {
			t.Errorf("mode %q: %v, %v; want disabled", m, d, err)
		}
	}
	if _, err := newEscapeDetector("block", nil); err == nil {
		t.Error("invalid mode accepted")
	}
}
