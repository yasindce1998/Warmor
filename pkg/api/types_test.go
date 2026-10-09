package api

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEventTypeString(t *testing.T) {
	cases := map[EventType]string{
		EventTypeProcess: "PROCESS",
		EventTypeFile:    "FILE",
		EventTypeNetwork: "NETWORK",
		EventType(3):     "UNKNOWN",
		EventType(-1):    "UNKNOWN",
	}
	for et, want := range cases {
		if got := et.String(); got != want {
			t.Errorf("EventType(%d).String() = %q, want %q", int32(et), got, want)
		}
	}
}

func TestEventTypeMarshalJSON(t *testing.T) {
	for _, et := range []EventType{EventTypeProcess, EventTypeFile, EventTypeNetwork} {
		data, err := json.Marshal(et)
		if err != nil {
			t.Fatal(err)
		}
		if want := `"` + et.String() + `"`; string(data) != want {
			t.Errorf("Marshal(%d) = %s, want %s", int32(et), data, want)
		}
	}
	// Unknown values would encode as "UNKNOWN", which cannot be decoded, so
	// they are rejected at encode time.
	for _, et := range []EventType{EventType(42), EventType(-1), EventType(3)} {
		if data, err := json.Marshal(et); err == nil {
			t.Errorf("Marshal(%d) = %s, want error", int32(et), data)
		}
	}
	if _, err := json.Marshal(&Event{Type: EventType(99)}); err == nil {
		t.Error("Event with unknown Type marshaled without error")
	}
}

func TestEventTypeUnmarshalJSON(t *testing.T) {
	cases := []struct {
		in      string
		want    EventType
		wantErr bool
	}{
		{`"PROCESS"`, EventTypeProcess, false},
		{`"FILE"`, EventTypeFile, false},
		{`"NETWORK"`, EventTypeNetwork, false},
		{`0`, EventTypeProcess, false},
		{`1`, EventTypeFile, false},
		{`2`, EventTypeNetwork, false},
		// Unknown numerics are rejected like unknown names.
		{`99`, 0, true},
		{`3`, 0, true},
		{`-1`, 0, true},
		{`"process"`, 0, true}, // case-sensitive
		{`"UNKNOWN"`, 0, true}, // String() output for unknown types does not round-trip
		{`""`, 0, true},
		{`true`, 0, true},
		{`{}`, 0, true},
		{`1.5`, 0, true},
		{`4294967296`, 0, true}, // overflows int32
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			var et EventType
			err := json.Unmarshal([]byte(tc.in), &et)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", et)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if et != tc.want {
				t.Errorf("got %d, want %d", et, tc.want)
			}
		})
	}
}

func TestEventTypeUnmarshalErrorMessage(t *testing.T) {
	var et EventType
	err := json.Unmarshal([]byte(`true`), &et)
	if err == nil || !strings.Contains(err.Error(), "string or number") {
		t.Errorf("unexpected error: %v", err)
	}
	err = json.Unmarshal([]byte(`"BOGUS"`), &et)
	if err == nil || !strings.Contains(err.Error(), `"BOGUS"`) {
		t.Errorf("unexpected error: %v", err)
	}
	err = json.Unmarshal([]byte(`99`), &et)
	if err == nil || !strings.Contains(err.Error(), "unknown EventType: 99") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEventTypeRoundTrip(t *testing.T) {
	for _, et := range []EventType{EventTypeProcess, EventTypeFile, EventTypeNetwork} {
		data, err := json.Marshal(et)
		if err != nil {
			t.Fatal(err)
		}
		var got EventType
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		if got != et {
			t.Errorf("round trip %v -> %s -> %v", et, data, got)
		}
	}
}

func TestEventJSONRoundTrip(t *testing.T) {
	ts := time.Date(2025, 1, 2, 3, 4, 5, 6, time.UTC)
	base := func(et EventType) BaseEvent {
		return BaseEvent{Type: et, PID: 10, UID: 1000, GID: 1000, Comm: "bash", Timestamp: ts, CgroupID: 77}
	}
	events := []*Event{
		{
			PID: 10, UID: 1000, GID: 1000, Comm: "bash", Filename: "/bin/ls", Timestamp: ts,
			Type: EventTypeProcess, CgroupID: 77,
			Process: &ProcessEvent{BaseEvent: base(EventTypeProcess), Filename: "/bin/ls", Args: []string{"ls", "-l"}},
		},
		{
			PID: 10, Comm: "cat", Filename: "/etc/shadow", Timestamp: ts, Type: EventTypeFile, LSMEvent: true,
			File: &FileEvent{BaseEvent: base(EventTypeFile), Operation: "open", Path: "/etc/shadow", Flags: 2, Mode: 0o644},
		},
		{
			PID: 10, Comm: "curl", Timestamp: ts, Type: EventTypeNetwork,
			Network: &NetworkEvent{
				BaseEvent: base(EventTypeNetwork), Operation: "connect", Protocol: "tcp6",
				RemoteAddr: "::1", RemotePort: 443, LocalAddr: "::1", LocalPort: 50000, DataSize: 12,
			},
		},
		{PID: 1, Comm: "init", Filename: "/sbin/init", Timestamp: ts}, // legacy
	}
	for _, ev := range events {
		data, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		var got Event
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", data, err)
		}
		if !reflect.DeepEqual(&got, ev) {
			t.Errorf("round trip mismatch:\n got  %+v\n want %+v\n json %s", got, *ev, data)
		}
	}
}

func TestEventJSONFieldNames(t *testing.T) {
	ev := &Event{
		PID: 1, Comm: "x", Type: EventTypeNetwork, CgroupID: 5, LSMEvent: true,
		Network: &NetworkEvent{BaseEvent: BaseEvent{Type: EventTypeNetwork}, RemoteAddr: "1.2.3.4", RemotePort: 80},
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m["type"] != "NETWORK" {
		t.Errorf("type = %v, want NETWORK", m["type"])
	}
	for _, k := range []string{"pid", "uid", "gid", "comm", "filename", "timestamp", "cgroup_id", "network", "lsm_event"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q in %s", k, data)
		}
	}
	for _, k := range []string{"process", "file"} {
		if _, ok := m[k]; ok {
			t.Errorf("unexpected key %q in %s (should be omitempty)", k, data)
		}
	}
	nw, ok := m["network"].(map[string]any)
	if !ok {
		t.Fatalf("network is not an object: %s", data)
	}
	if nw["remote_addr"] != "1.2.3.4" || nw["remote_port"] != float64(80) {
		t.Errorf("network fields wrong: %v", nw)
	}
	if _, ok := nw["local_addr"]; ok {
		t.Errorf("local_addr should be omitted when empty: %v", nw)
	}
}

func TestEventUnmarshalLegacyNumericType(t *testing.T) {
	var ev Event
	if err := json.Unmarshal([]byte(`{"pid":5,"type":1,"file":{"type":1,"path":"/x"}}`), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Type != EventTypeFile || ev.File == nil || ev.File.Path != "/x" {
		t.Errorf("unexpected event %+v", ev)
	}
}

func TestEventUnmarshalRejectsUnknownType(t *testing.T) {
	var ev Event
	if err := json.Unmarshal([]byte(`{"type":"SYSCALL"}`), &ev); err == nil {
		t.Error("expected error for unknown event type")
	}
}

func TestGetType(t *testing.T) {
	cases := []struct {
		name string
		ev   Event
		want EventType
	}{
		{"explicit file", Event{Type: EventTypeFile}, EventTypeFile},
		{"explicit network", Event{Type: EventTypeNetwork}, EventTypeNetwork},
		{"legacy defaults to process", Event{}, EventTypeProcess},
		{"from process sub-event", Event{Process: &ProcessEvent{BaseEvent: BaseEvent{Type: EventTypeProcess}}}, EventTypeProcess},
		{"from file sub-event", Event{File: &FileEvent{BaseEvent: BaseEvent{Type: EventTypeFile}}}, EventTypeFile},
		{"from network sub-event", Event{Network: &NetworkEvent{BaseEvent: BaseEvent{Type: EventTypeNetwork}}}, EventTypeNetwork},
		{"explicit wins over sub-event", Event{Type: EventTypeNetwork, File: &FileEvent{BaseEvent: BaseEvent{Type: EventTypeFile}}}, EventTypeNetwork},
		// A plain literal Type: EventTypeProcess is indistinguishable from
		// unset (both zero), so the sub-event is used ...
		{"literal process type with file sub-event", Event{Type: EventTypeProcess, File: &FileEvent{BaseEvent: BaseEvent{Type: EventTypeFile}}}, EventTypeFile},
		{"process sub-event checked before file", Event{
			Process: &ProcessEvent{BaseEvent: BaseEvent{Type: EventTypeProcess}},
			File:    &FileEvent{BaseEvent: BaseEvent{Type: EventTypeFile}},
		}, EventTypeProcess},
	}
	// ... but an explicit SetType(EventTypeProcess) wins.
	explicit := Event{File: &FileEvent{BaseEvent: BaseEvent{Type: EventTypeFile}}}
	explicit.SetType(EventTypeProcess)
	cases = append(cases, struct {
		name string
		ev   Event
		want EventType
	}{"SetType process with file sub-event", explicit, EventTypeProcess})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ev.GetType(); got != tc.want {
				t.Errorf("GetType = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGetTypeExplicitProcessJSON(t *testing.T) {
	// An explicit "type":"PROCESS" (or 0) on the wire is honoured even
	// when a file sub-event is present; an absent type still infers.
	cases := []struct {
		in   string
		want EventType
	}{
		{`{"type":"PROCESS","file":{"type":"FILE","path":"/x"}}`, EventTypeProcess},
		{`{"type":0,"file":{"type":"FILE","path":"/x"}}`, EventTypeProcess},
		{`{"file":{"type":"FILE","path":"/x"}}`, EventTypeFile},
		{`{"type":null,"file":{"type":"FILE","path":"/x"}}`, EventTypeFile},
		{`{"pid":1}`, EventTypeProcess},
	}
	for _, tc := range cases {
		var ev Event
		if err := json.Unmarshal([]byte(tc.in), &ev); err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if got := ev.GetType(); got != tc.want {
			t.Errorf("%s: GetType = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestEventExplicitProcessRoundTrip(t *testing.T) {
	ev := Event{PID: 3, File: &FileEvent{BaseEvent: BaseEvent{Type: EventTypeFile}, Path: "/x"}}
	ev.SetType(EventTypeProcess)
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"type":"PROCESS"`) {
		t.Errorf("explicit process type not encoded: %s", data)
	}
	var got Event
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.GetType() != EventTypeProcess || !reflect.DeepEqual(got, ev) {
		t.Errorf("round trip = %+v (type %v), want %+v", got, got.GetType(), ev)
	}

	// An unset type is still omitted, preserving the legacy wire format.
	data, err = json.Marshal(&Event{PID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"type"`) {
		t.Errorf("unset type encoded: %s", data)
	}
	// SetType to a non-zero type then back clears the explicit marker
	// consistently with plain assignment.
	ev.SetType(EventTypeFile)
	if ev.GetType() != EventTypeFile {
		t.Errorf("GetType = %v after SetType(FILE)", ev.GetType())
	}
}

func TestToProcessEventReturnsExisting(t *testing.T) {
	pe := &ProcessEvent{Filename: "/bin/sh"}
	ev := &Event{Filename: "/other", Process: pe}
	if got := ev.ToProcessEvent(); got != pe {
		t.Errorf("ToProcessEvent returned %p, want existing %p", got, pe)
	}
}

func TestToProcessEventFromLegacy(t *testing.T) {
	ts := time.Unix(1700000000, 0)
	ev := &Event{PID: 42, UID: 1, GID: 2, Comm: "sh", Filename: "/bin/sh", Timestamp: ts, CgroupID: 9}
	got := ev.ToProcessEvent()
	want := &ProcessEvent{
		BaseEvent: BaseEvent{Type: EventTypeProcess, PID: 42, UID: 1, GID: 2, Comm: "sh", Timestamp: ts, CgroupID: 9},
		Filename:  "/bin/sh",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ToProcessEvent = %+v, want %+v", got, want)
	}
}

func TestActionString(t *testing.T) {
	cases := map[Action]string{
		ActionAllow: "ALLOW",
		ActionDeny:  "DENY",
		ActionLog:   "LOG",
		Action(7):   "UNKNOWN",
		Action(-1):  "UNKNOWN",
	}
	for a, want := range cases {
		if got := a.String(); got != want {
			t.Errorf("Action(%d).String() = %q, want %q", int32(a), got, want)
		}
	}
}

func TestActionResultJSONRoundTrip(t *testing.T) {
	ar := ActionResult{
		Action: ActionDeny, Reason: "blocked", Timestamp: time.Date(2025, 5, 5, 0, 0, 0, 0, time.UTC),
		Cached: true, Latency: 1500 * time.Microsecond, Audit: true,
	}
	data, err := json.Marshal(ar)
	if err != nil {
		t.Fatal(err)
	}
	var got ActionResult
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got != ar {
		t.Errorf("round trip = %+v, want %+v", got, ar)
	}
}

func TestEnforcementStatsJSONRoundTrip(t *testing.T) {
	s := EnforcementStats{Allowed: 1, Denied: 2, Logged: 3, AuditDenied: 4, CacheHits: 5, CacheMisses: 6, TotalLatency: time.Second}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var got EnforcementStats
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got != s {
		t.Errorf("round trip = %+v, want %+v", got, s)
	}
}
