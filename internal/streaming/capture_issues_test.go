package streaming

import (
	"testing"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

func TestFromAPIEventRecordsCaptureIssues(t *testing.T) {
	event := &api.Event{
		Type:              api.EventTypeProcess,
		Timestamp:         time.Now(),
		KernelTimestampNS: 1, // live kernel sensor: cgroup 0 means untracked
		Comm:              "tool",
		Filename:          "/tool",
		Process:           &api.ProcessEvent{Filename: "/tool", Args: []string{"tool"}},
		TruncatedFields:   []string{"filename", "process.args"},
	}
	se := FromAPIEvent(event, nil)

	got := make(map[string]string)
	for _, issue := range se.InputIssues {
		got[issue.Field] = issue.State
	}
	want := map[string]string{
		"cgroup_id":    "unknown",
		"ppid":         "unknown",
		"parent_comm":  "unknown",
		"filename":     "truncated",
		"process.args": "truncated",
	}
	for field, state := range want {
		if got[field] != state {
			t.Errorf("issue[%q].State = %q, want %q (all: %+v)", field, got[field], state, se.InputIssues)
		}
	}
	if se.Decision != "" {
		t.Errorf("Decision = %q, want unchanged (no verdict mutation)", se.Decision)
	}
}

func TestFromAPIEventDoesNotFlagUnsetCgroupInReplay(t *testing.T) {
	// Replay/synthetic events leave CgroupID at its zero value without that
	// meaning "untracked by the kernel"; do not label them incomplete.
	se := FromAPIEvent(&api.Event{Type: api.EventTypeProcess, Timestamp: time.Now(), Comm: "tool"}, nil)
	for _, issue := range se.InputIssues {
		if issue.Field == "cgroup_id" {
			t.Errorf("unexpected cgroup_id issue on a synthetic event: %+v", issue)
		}
	}
}

func TestFromAPIEventOmitsIssuesForCompleteInputs(t *testing.T) {
	event := &api.Event{
		Type:       api.EventTypeProcess,
		Timestamp:  time.Now(),
		Comm:       "tool",
		Filename:   "/tool",
		CgroupID:   42,
		PPID:       1,
		ParentComm: "init",
		Process:    &api.ProcessEvent{Filename: "/tool", Args: []string{"tool"}},
	}
	se := FromAPIEvent(event, nil)
	for _, issue := range se.InputIssues {
		switch issue.Field {
		case "cgroup_id", "ppid", "parent_comm", "filename", "process.args":
			t.Errorf("unexpected issue for a complete input: %+v", issue)
		}
	}
}
