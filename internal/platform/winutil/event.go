package winutil

import (
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

// ProcessEvent builds the enforcer event for a process start. Both the ETW
// and the eBPF backends use it so they report processes identically.
func ProcessEvent(info ProcInfo, ts time.Time) *api.Event {
	ev := &api.Event{
		PID:       info.PID,
		Comm:      info.Comm,
		Filename:  info.Image,
		Timestamp: ts,
		Process: &api.ProcessEvent{
			BaseEvent: api.BaseEvent{Type: api.EventTypeProcess, PID: info.PID, Comm: info.Comm, Timestamp: ts},
			Filename:  info.Image,
			Args:      SplitCommandLine(info.CmdLine),
		},
	}
	ev.SetType(api.EventTypeProcess)
	return ev
}
