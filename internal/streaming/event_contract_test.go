package streaming

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

func TestRecordedInputSnapshotOwnsMutablePayloads(t *testing.T) {
	input := &api.Event{PID: 7, PPID: 6, ParentComm: "parent", Comm: "tool", Filename: "/tool", Timestamp: time.Now().UTC(), Process: &api.ProcessEvent{Filename: "/tool", Args: []string{"tool", "--secret"}}}
	se := FromAPIEvent(input, nil)
	input.Process.Args[1], input.Process.Filename = "changed", "/changed"
	if se.SchemaVersion != EventSchemaVersion || se.PPID != 6 || se.PolicyInput.ParentComm != "parent" || se.PolicyInput.Process.Args[1] != "--secret" || se.PolicyInput.Process.Filename != "/tool" {
		t.Fatalf("bad snapshot: %+v", se)
	}
	data, err := json.Marshal(se)
	if err != nil {
		t.Fatal(err)
	}
	var decoded SecurityEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.PolicyInput, se.PolicyInput) {
		t.Fatal("snapshot changed after JSON roundtrip")
	}
}

func TestRawPathBytesMarkedIncomplete(t *testing.T) {
	se := FromAPIEvent(&api.Event{Filename: "/bad\xff", Process: &api.ProcessEvent{Filename: "/bad\xff", Args: []string{"bad\xfe"}}}, nil)
	fields := make(map[string]bool)
	for _, issue := range se.InputIssues {
		fields[issue.Field] = true
	}
	for _, field := range []string{"filename", "process.filename", "process.args"} {
		if !fields[field] {
			t.Errorf("invalid UTF-8 not marked incomplete: %s", field)
		}
	}
}
