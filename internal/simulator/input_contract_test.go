package simulator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestPolicyInputRoundTripAllTypes(t *testing.T) {
	for _, typ := range []api.EventType{api.EventTypeProcess, api.EventTypeFile, api.EventTypeNetwork} {
		for _, hook := range []string{"", "exec", "file", "connect", "bind", "listen", "mount", "ptrace", "connect_unix"} {
			input := &api.Event{PID: 13, UID: 1, GID: 2, PPID: 12, ParentComm: "parent", Comm: "雪", Filename: "/" + strings.Repeat("long", 80), Timestamp: time.Unix(1700000010, 0).UTC(), CgroupID: 45, ContainerStart: time.Unix(1700000000, 0).UTC(), Hook: hook, MountSource: "source", TargetCgroupID: 34, LSMEvent: true}
			input.SetType(typ)
			switch typ {
			case api.EventTypeProcess:
				input.Process = &api.ProcessEvent{Filename: input.Filename, Args: []string{"tool", "--arg", "雪"}}
			case api.EventTypeFile:
				input.File = &api.FileEvent{Path: input.Filename, Flags: 0x102, Mode: 0600, Operation: "write"}
			case api.EventTypeNetwork:
				input.Network = &api.NetworkEvent{Operation: "recvfrom", Protocol: "udp", RemoteAddr: "2001:db8::1", RemotePort: 53, LocalAddr: "::1", LocalPort: 5353, DataSize: 100}
			}
			data, err := json.Marshal(streaming.FromAPIEvent(input, nil))
			if err != nil {
				t.Fatal(err)
			}
			var recorded streaming.SecurityEvent
			if err := json.Unmarshal(data, &recorded); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(input, securityEventToAPIEvent(&recorded)) {
				t.Fatalf("type %v hook %s lost input", typ, hook)
			}
		}
	}
}

func TestReplayIncompleteEvidenceAndVersion(t *testing.T) {
	ev := newTestEvaluator(t)
	for _, input := range []*streaming.SecurityEvent{
		{EventType: "exec", Comm: "ls"},
		{SchemaVersion: 2, EventType: "exec", PolicyInput: &api.Event{Comm: "ls"}, InputIssues: []streaming.InputIssue{{Field: "process.args", State: "redacted"}}},
		{SchemaVersion: 2, EventType: "exec", PolicyInput: &api.Event{Comm: "ls"}, InputIssues: []streaming.InputIssue{{Field: "filename", State: "truncated"}}},
	} {
		res, err := Replay(context.Background(), []*streaming.SecurityEvent{input}, ev)
		if err != nil {
			t.Fatal(err)
		}
		if res.IncompleteEvents != 1 || len(res.Warnings) == 0 {
			t.Fatalf("missing caveat: %+v", res)
		}
		var output bytes.Buffer
		if err := FormatText(&output, res); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), "incomplete evidence") || strings.Contains(output.String(), "all previously-allowed events remain allowed") {
			t.Fatal(output.String())
		}
	}
	if _, err := Replay(context.Background(), []*streaming.SecurityEvent{{SchemaVersion: 999}}, ev); err == nil {
		t.Fatal("accepted unknown future schema")
	}
}

func TestLegacyReplayEstimatesAndValidation(t *testing.T) {
	ev := newTestEvaluator(t)
	for _, version := range []int{0, 1, 2} {
		event := &streaming.SecurityEvent{SchemaVersion: version, EventType: "bind", Protocol: "tcp", LocalPort: 80, Decision: "deny"}
		input := securityEventToAPIEvent(event)
		if input.Hook != "bind" || input.Network == nil || input.Network.Operation != "connect" {
			t.Fatalf("historical evaluator fallback lost: %+v", input)
		}
		res, err := Replay(context.Background(), []*streaming.SecurityEvent{event}, ev)
		if err != nil {
			t.Fatal(err)
		}
		if res.WouldAllow != 1 || res.IncompleteEvents != 1 || len(res.Warnings) == 0 {
			t.Fatalf("schema %d missing estimate warning: %+v", version, res)
		}
	}
	for _, event := range []*streaming.SecurityEvent{nil, {SchemaVersion: -1}, {SchemaVersion: streaming.EventSchemaVersion + 1}} {
		if _, err := Replay(context.Background(), []*streaming.SecurityEvent{event}, ev); err == nil {
			t.Fatal("accepted unsupported recorded event")
		}
	}
	// A writer failure must not appear to be a successfully emitted report.
	want := errors.New("report destination failed")
	if err := FormatText(failingReportWriter{want}, &SimulationResult{IncompleteEvents: 1}); !errors.Is(err, want) {
		t.Fatalf("report error = %v, want %v", err, want)
	}
}

type failingReportWriter struct{ err error }

func (w failingReportWriter) Write([]byte) (int, error) { return 0, w.err }
