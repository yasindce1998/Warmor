package wasm

import (
	"encoding/json"
	"testing"

	"github.com/yasindce1998/warmor/pkg/api"
)

func TestMarshalEventForWASM_ProcessEvent(t *testing.T) {
	event := &api.Event{
		PID:      100,
		UID:      1000,
		GID:      1000,
		Comm:     "cat",
		Filename: "/usr/bin/cat",
		Type:     api.EventTypeProcess,
	}

	data, err := marshalEventForWASM(event, false)
	if err != nil {
		t.Fatalf("marshalEventForWASM failed: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if m["type"] != "PROCESS" {
		t.Errorf("type = %v, want PROCESS", m["type"])
	}
	if m["pid"] != float64(100) {
		t.Errorf("pid = %v, want 100", m["pid"])
	}
	if m["uid"] != float64(1000) {
		t.Errorf("uid = %v, want 1000", m["uid"])
	}
	if m["comm"] != "cat" {
		t.Errorf("comm = %v, want cat", m["comm"])
	}
	if m["filename"] != "/usr/bin/cat" {
		t.Errorf("filename = %v, want /usr/bin/cat", m["filename"])
	}
}

func TestMarshalEventForWASM_ProcessEventWithSubStruct(t *testing.T) {
	event := &api.Event{
		PID:  200,
		UID:  0,
		GID:  0,
		Comm: "bash",
		Type: api.EventTypeProcess,
		Process: &api.ProcessEvent{
			Filename: "/bin/bash",
		},
	}

	data, err := marshalEventForWASM(event, false)
	if err != nil {
		t.Fatalf("marshalEventForWASM failed: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if m["filename"] != "/bin/bash" {
		t.Errorf("filename = %v, want /bin/bash (from Process sub-struct)", m["filename"])
	}
}

func TestMarshalEventForWASM_FileEvent(t *testing.T) {
	event := &api.Event{
		PID:  300,
		UID:  1000,
		GID:  1000,
		Comm: "vim",
		Type: api.EventTypeFile,
		File: &api.FileEvent{
			Operation: "write",
			Path:      "/etc/passwd",
			Flags:     0x241,
		},
	}

	data, err := marshalEventForWASM(event, false)
	if err != nil {
		t.Fatalf("marshalEventForWASM failed: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if m["type"] != "FILE" {
		t.Errorf("type = %v, want FILE", m["type"])
	}
	if m["operation"] != "write" {
		t.Errorf("operation = %v, want write", m["operation"])
	}
	if m["path"] != "/etc/passwd" {
		t.Errorf("path = %v, want /etc/passwd", m["path"])
	}
	if m["flags"] != float64(0x241) {
		t.Errorf("flags = %v, want %v", m["flags"], float64(0x241))
	}
}

func TestMarshalEventForWASM_FileEvent_Fallback(t *testing.T) {
	event := &api.Event{
		PID:      400,
		UID:      1000,
		GID:      1000,
		Comm:     "cat",
		Filename: "/tmp/data.txt",
		Type:     api.EventTypeFile,
	}

	data, err := marshalEventForWASM(event, false)
	if err != nil {
		t.Fatalf("marshalEventForWASM failed: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if m["type"] != "FILE" {
		t.Errorf("type = %v, want FILE", m["type"])
	}
	if m["operation"] != "open" {
		t.Errorf("operation = %v, want open (fallback)", m["operation"])
	}
	if m["path"] != "/tmp/data.txt" {
		t.Errorf("path = %v, want /tmp/data.txt", m["path"])
	}
}

func TestMarshalEventForWASM_NetworkEvent(t *testing.T) {
	event := &api.Event{
		PID:  500,
		UID:  1000,
		GID:  1000,
		Comm: "curl",
		Type: api.EventTypeNetwork,
		Network: &api.NetworkEvent{
			Operation:  "connect",
			Protocol:   "tcp",
			RemoteAddr: "93.184.216.34",
			RemotePort: 443,
			LocalPort:  54321,
		},
	}

	data, err := marshalEventForWASM(event, false)
	if err != nil {
		t.Fatalf("marshalEventForWASM failed: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if m["type"] != "NETWORK" {
		t.Errorf("type = %v, want NETWORK", m["type"])
	}
	if m["operation"] != "connect" {
		t.Errorf("operation = %v, want connect", m["operation"])
	}
	if m["protocol"] != "tcp" {
		t.Errorf("protocol = %v, want tcp", m["protocol"])
	}
	if m["remote_addr"] != "93.184.216.34" {
		t.Errorf("remote_addr = %v, want 93.184.216.34", m["remote_addr"])
	}
	if m["remote_port"] != float64(443) {
		t.Errorf("remote_port = %v, want 443", m["remote_port"])
	}
}

func TestMarshalEventForWASM_NetworkEvent_Fallback(t *testing.T) {
	event := &api.Event{
		PID:  600,
		UID:  0,
		GID:  0,
		Comm: "nc",
		Type: api.EventTypeNetwork,
	}

	data, err := marshalEventForWASM(event, false)
	if err != nil {
		t.Fatalf("marshalEventForWASM failed: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if m["type"] != "NETWORK" {
		t.Errorf("type = %v, want NETWORK", m["type"])
	}
	if m["operation"] != "connect" {
		t.Errorf("operation = %v, want connect (fallback)", m["operation"])
	}
	if m["protocol"] != "tcp" {
		t.Errorf("protocol = %v, want tcp (fallback)", m["protocol"])
	}
}

func TestMarshalEventForWASM_UnknownType(t *testing.T) {
	event := &api.Event{
		PID:      700,
		UID:      0,
		GID:      0,
		Comm:     "unknown",
		Filename: "/bin/mystery",
		Type:     api.EventType(99),
	}

	data, err := marshalEventForWASM(event, false)
	if err != nil {
		t.Fatalf("marshalEventForWASM failed: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if m["type"] != "PROCESS" {
		t.Errorf("unknown type should default to PROCESS, got %v", m["type"])
	}
}

// Policies deserialize into fixed structs; a missing key is a parse error and
// the policy denies. "filename" must therefore be present for every type.
func TestMarshalEventForWASM_FilenameAlwaysPresent(t *testing.T) {
	events := map[string]*api.Event{
		"FILE": {Type: api.EventTypeFile, Filename: "/etc/passwd",
			File: &api.FileEvent{Operation: "open", Path: "/etc/passwd"}},
		"FILE fallback": {Type: api.EventTypeFile, Filename: "/etc/passwd"},
		"NETWORK": {Type: api.EventTypeNetwork,
			Network: &api.NetworkEvent{RemoteAddr: "1.2.3.4", RemotePort: 443}},
		"NETWORK fallback": {Type: api.EventTypeNetwork},
	}
	for name, ev := range events {
		data, err := marshalEventForWASM(ev, false)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		v, ok := m["filename"]
		if !ok {
			t.Errorf("%s: filename key missing", name)
			continue
		}
		if v != "" {
			t.Errorf("%s: filename = %q, want empty for non-process events", name, v)
		}
	}
}
