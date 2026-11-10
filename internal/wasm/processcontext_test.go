package wasm

import (
	"encoding/json"
	"testing"

	"github.com/yasindce1998/warmor/pkg/api"
)

// unmarshalEvent decodes the JSON ABI document into a generic map.
func unmarshalEvent(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal event JSON: %v", err)
	}
	return m
}

func TestMarshalEventForWASM_ProcessContext(t *testing.T) {
	ev := &api.Event{
		PID: 4242, UID: 1000, GID: 1000, Comm: "curl", Filename: "/usr/bin/curl",
		CgroupID: 0xdeadbeef, ParentComm: "bash",
		Process: &api.ProcessEvent{
			Filename: "/usr/bin/curl",
			Args:     []string{"-sSL", "http://example.com"},
		},
	}
	ev.SetType(api.EventTypeProcess)

	// Version 4: the process-context keys are present.
	m := unmarshalEvent(t, mustMarshal(t, ev, 4))
	if got := m["cgroup_id"]; got != float64(0xdeadbeef) {
		t.Errorf("cgroup_id = %v, want %d", got, 0xdeadbeef)
	}
	if got := m["parent_comm"]; got != "bash" {
		t.Errorf("parent_comm = %v, want bash", got)
	}
	args, ok := m["args"].([]any)
	if !ok || len(args) != 2 || args[0] != "-sSL" || args[1] != "http://example.com" {
		t.Errorf("args = %v, want [-sSL http://example.com]", m["args"])
	}

	// Versions 0-3: none of the keys are sent, exactly as before.
	for _, v := range []uint32{0, 1, 2, 3} {
		m := unmarshalEvent(t, mustMarshal(t, ev, v))
		for _, key := range []string{"cgroup_id", "parent_comm", "args", "direction"} {
			if _, ok := m[key]; ok {
				t.Errorf("abi version %d: key %q must not be sent", v, key)
			}
		}
	}
}

func TestMarshalEventForWASM_ProcessContext_EmptyArgsAreArray(t *testing.T) {
	// A PROCESS event without a Process sub-event still carries args as an
	// array (never null), so serde Vec<String> deserialization cannot fail.
	ev := &api.Event{PID: 1, UID: 0, GID: 0, Comm: "x", Filename: "/bin/x"}
	ev.SetType(api.EventTypeProcess)

	m := unmarshalEvent(t, mustMarshal(t, ev, 4))
	args, ok := m["args"].([]any)
	if !ok || len(args) != 0 {
		t.Errorf("args = %v (%T), want empty array", m["args"], m["args"])
	}
	if got := m["parent_comm"]; got != "" {
		t.Errorf("parent_comm = %v, want \"\"", got)
	}
}

func TestMarshalEventForWASM_NetworkDirection(t *testing.T) {
	tests := []struct {
		operation string
		direction string
	}{
		{"connect", "egress"},
		{"sendto", "egress"},
		{"recvfrom", "ingress"},
	}
	for _, tc := range tests {
		ev := &api.Event{
			PID: 1, UID: 0, GID: 0, Comm: "srv", Type: api.EventTypeNetwork,
			Network: &api.NetworkEvent{
				Operation: tc.operation, Protocol: "tcp",
				RemoteAddr: "10.0.0.1", RemotePort: 443, LocalPort: 40000,
			},
		}
		m := unmarshalEvent(t, mustMarshal(t, ev, 4))
		if got := m["direction"]; got != tc.direction {
			t.Errorf("operation %s: direction = %v, want %s", tc.operation, got, tc.direction)
		}

		// Without version 4 the key is absent.
		m = unmarshalEvent(t, mustMarshal(t, ev, 0))
		if _, ok := m["direction"]; ok {
			t.Errorf("operation %s: direction must not be sent to a version-0 module", tc.operation)
		}
	}
}

func mustMarshal(t *testing.T, ev *api.Event, version uint32) []byte {
	t.Helper()
	data, err := marshalEventForWASM(ev, version)
	if err != nil {
		t.Fatalf("marshalEventForWASM: %v", err)
	}
	return data
}
