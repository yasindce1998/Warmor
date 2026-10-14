package enforcer

import (
	"testing"

	"github.com/yasindce1998/warmor/pkg/api"
)

type eventSyncRecorder struct {
	setRuleCalls int
	events       []*api.Event
	actions      []uint8
	audits       []bool
}

func (r *eventSyncRecorder) SetRule(uint64, uint8, string, uint8, bool) error {
	r.setRuleCalls++
	return nil
}

func (r *eventSyncRecorder) Clear() error { return nil }

func (r *eventSyncRecorder) SyncEvent(ev *api.Event, action uint8, audit bool) error {
	r.events = append(r.events, ev)
	r.actions = append(r.actions, action)
	r.audits = append(r.audits, audit)
	return nil
}

func TestSyncToPolicyMapPrefersEventSyncer(t *testing.T) {
	rec := &eventSyncRecorder{}
	e := &Enforcer{policyMap: rec}

	ev := &api.Event{
		Type: api.EventTypeNetwork, PID: 1,
		Network: &api.NetworkEvent{Operation: "connect", Protocol: "tcp", RemoteAddr: "1.2.3.4", RemotePort: 443},
	}
	e.syncToPolicyMap(ev, &api.ActionResult{Action: api.ActionDeny}, 0)
	if rec.setRuleCalls != 0 || len(rec.events) != 1 || rec.events[0] != ev || rec.actions[0] != 1 || rec.audits[0] {
		t.Fatalf("deny not routed to SyncEvent: %+v", rec)
	}

	// Global audit mode must reach the kernel as an audit rule.
	e.auditMode = true
	e.syncToPolicyMap(ev, &api.ActionResult{Action: api.ActionDeny}, 0)
	if !rec.audits[1] {
		t.Fatal("audit mode not folded into SyncEvent")
	}

	e.auditMode = false
	e.syncToPolicyMap(ev, &api.ActionResult{Action: api.ActionAllow}, 0)
	if rec.actions[2] != 0 {
		t.Fatal("allow must sync action 0")
	}
}
