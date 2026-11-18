package streaming

import (
	"testing"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

func hasInputIssue(issues []InputIssue, field, state string) bool {
	for _, issue := range issues {
		if issue.Field == field && issue.State == state {
			return true
		}
	}
	return false
}

// A Linux-correlated merge carries the LSM kernel decision enriched with
// tracepoint argv/parent. Streaming must surface the suppression as an
// InputIssue so SIEM/replay consumers know the twin was merged, not lost.
func TestFromAPIEventMarksDeduplicated(t *testing.T) {
	event := &api.Event{
		Type: api.EventTypeProcess, PID: 42, CgroupID: 7,
		Timestamp:    time.Unix(1, 0),
		Deduplicated: true,
		Process:      &api.ProcessEvent{Filename: "/bin/sh", Args: []string{"/bin/sh", "-c", "echo hi"}},
	}
	se := FromAPIEvent(event, nil)
	if !hasInputIssue(se.InputIssues, CorrelationIssueField, "deduplicated") {
		t.Fatalf("deduplicated event missing correlation InputIssue: %+v", se.InputIssues)
	}
}

func TestFromAPIEventNoIssueWhenNotDeduplicated(t *testing.T) {
	event := &api.Event{
		Type: api.EventTypeProcess, PID: 42, CgroupID: 7,
		Timestamp: time.Unix(1, 0),
		Process:   &api.ProcessEvent{Filename: "/bin/sh", Args: []string{"/bin/sh"}},
	}
	se := FromAPIEvent(event, nil)
	if hasInputIssue(se.InputIssues, CorrelationIssueField, "deduplicated") {
		t.Fatalf("unpaired event must not carry a dedup issue: %+v", se.InputIssues)
	}
}
