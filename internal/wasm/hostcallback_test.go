package wasm

import (
	"context"
	"testing"

	"github.com/yasindce1998/warmor/pkg/api"
)

// ---- contextWithEvent / eventFromContext ----

func TestContextWithEvent_RoundTrip(t *testing.T) {
	event := &api.Event{PID: 42, UID: 1000, Comm: "test"}
	ctx := contextWithEvent(context.Background(), event)

	got := eventFromContext(ctx)
	if got == nil {
		t.Fatal("eventFromContext returned nil after contextWithEvent")
	}
	if got.PID != 42 {
		t.Errorf("PID = %d, want 42", got.PID)
	}
	if got.UID != 1000 {
		t.Errorf("UID = %d, want 1000", got.UID)
	}
}

func TestEventFromContext_NoEvent(t *testing.T) {
	got := eventFromContext(context.Background())
	if got != nil {
		t.Errorf("eventFromContext(background) = %v, want nil", got)
	}
}

// ---- hostGetFieldU32 ----

func TestHostGetFieldU32_PID(t *testing.T) {
	event := &api.Event{PID: 1234}
	ctx := contextWithEvent(context.Background(), event)
	got := hostGetFieldU32(ctx, nil, FieldPID)
	if got != 1234 {
		t.Errorf("FieldPID = %d, want 1234", got)
	}
}

func TestHostGetFieldU32_UID(t *testing.T) {
	event := &api.Event{UID: 999}
	ctx := contextWithEvent(context.Background(), event)
	got := hostGetFieldU32(ctx, nil, FieldUID)
	if got != 999 {
		t.Errorf("FieldUID = %d, want 999", got)
	}
}

func TestHostGetFieldU32_GID(t *testing.T) {
	event := &api.Event{GID: 777}
	ctx := contextWithEvent(context.Background(), event)
	got := hostGetFieldU32(ctx, nil, FieldGID)
	if got != 777 {
		t.Errorf("FieldGID = %d, want 777", got)
	}
}

func TestHostGetFieldU32_Flags_WithFileEvent(t *testing.T) {
	event := &api.Event{
		Type: api.EventTypeFile,
		File: &api.FileEvent{Flags: 0x241},
	}
	ctx := contextWithEvent(context.Background(), event)
	got := hostGetFieldU32(ctx, nil, FieldFlags)
	if got != 0x241 {
		t.Errorf("FieldFlags = 0x%x, want 0x241", got)
	}
}

func TestHostGetFieldU32_Flags_NoFileEvent(t *testing.T) {
	event := &api.Event{Type: api.EventTypeProcess}
	ctx := contextWithEvent(context.Background(), event)
	got := hostGetFieldU32(ctx, nil, FieldFlags)
	if got != 0 {
		t.Errorf("FieldFlags (no File) = %d, want 0", got)
	}
}

func TestHostGetFieldU32_RemotePort_WithNetworkEvent(t *testing.T) {
	event := &api.Event{
		Type:    api.EventTypeNetwork,
		Network: &api.NetworkEvent{RemotePort: 443},
	}
	ctx := contextWithEvent(context.Background(), event)
	got := hostGetFieldU32(ctx, nil, FieldRemotePort)
	if got != 443 {
		t.Errorf("FieldRemotePort = %d, want 443", got)
	}
}

func TestHostGetFieldU32_RemotePort_NoNetworkEvent(t *testing.T) {
	event := &api.Event{Type: api.EventTypeProcess}
	ctx := contextWithEvent(context.Background(), event)
	got := hostGetFieldU32(ctx, nil, FieldRemotePort)
	if got != 0 {
		t.Errorf("FieldRemotePort (no Network) = %d, want 0", got)
	}
}

func TestHostGetFieldU32_LocalPort_WithNetworkEvent(t *testing.T) {
	event := &api.Event{
		Type:    api.EventTypeNetwork,
		Network: &api.NetworkEvent{LocalPort: 54321},
	}
	ctx := contextWithEvent(context.Background(), event)
	got := hostGetFieldU32(ctx, nil, FieldLocalPort)
	if got != 54321 {
		t.Errorf("FieldLocalPort = %d, want 54321", got)
	}
}

func TestHostGetFieldU32_LocalPort_NoNetworkEvent(t *testing.T) {
	event := &api.Event{Type: api.EventTypeProcess}
	ctx := contextWithEvent(context.Background(), event)
	got := hostGetFieldU32(ctx, nil, FieldLocalPort)
	if got != 0 {
		t.Errorf("FieldLocalPort (no Network) = %d, want 0", got)
	}
}

func TestHostGetFieldU32_UnknownField(t *testing.T) {
	event := &api.Event{PID: 1}
	ctx := contextWithEvent(context.Background(), event)
	got := hostGetFieldU32(ctx, nil, 9999)
	if got != 0 {
		t.Errorf("unknown field = %d, want 0", got)
	}
}

func TestHostGetFieldU32_NoEvent(t *testing.T) {
	// No event in context — all fields must return 0 safely.
	ctx := context.Background()
	for _, fieldID := range []uint32{FieldPID, FieldUID, FieldGID, FieldFlags, FieldRemotePort, FieldLocalPort} {
		got := hostGetFieldU32(ctx, nil, fieldID)
		if got != 0 {
			t.Errorf("field %d with no event = %d, want 0", fieldID, got)
		}
	}
}

// ---- getEventPath ----

func TestGetEventPath_ProcessEvent(t *testing.T) {
	event := &api.Event{
		Filename: "/bin/fallback",
		Process:  &api.ProcessEvent{Filename: "/bin/bash"},
	}
	got := getEventPath(event)
	if got != "/bin/bash" {
		t.Errorf("getEventPath = %q, want \"/bin/bash\" (from Process)", got)
	}
}

func TestGetEventPath_FileEvent(t *testing.T) {
	event := &api.Event{
		Filename: "/bin/fallback",
		File:     &api.FileEvent{Path: "/etc/passwd"},
	}
	got := getEventPath(event)
	if got != "/etc/passwd" {
		t.Errorf("getEventPath = %q, want \"/etc/passwd\" (from File)", got)
	}
}

func TestGetEventPath_NetworkEvent(t *testing.T) {
	event := &api.Event{
		Filename: "/bin/fallback",
		Network:  &api.NetworkEvent{RemoteAddr: "1.2.3.4"},
	}
	got := getEventPath(event)
	if got != "1.2.3.4" {
		t.Errorf("getEventPath = %q, want \"1.2.3.4\" (from Network)", got)
	}
}

func TestGetEventPath_Fallback(t *testing.T) {
	event := &api.Event{Filename: "/bin/ls"}
	got := getEventPath(event)
	if got != "/bin/ls" {
		t.Errorf("getEventPath (fallback) = %q, want \"/bin/ls\"", got)
	}
}

// ---- getEventOperation ----

func TestGetEventOperation_FileEvent(t *testing.T) {
	event := &api.Event{
		File: &api.FileEvent{Operation: "write"},
	}
	got := getEventOperation(event)
	if got != "write" {
		t.Errorf("getEventOperation = %q, want \"write\"", got)
	}
}

func TestGetEventOperation_NetworkEvent(t *testing.T) {
	event := &api.Event{
		Network: &api.NetworkEvent{Operation: "connect"},
	}
	got := getEventOperation(event)
	if got != "connect" {
		t.Errorf("getEventOperation = %q, want \"connect\"", got)
	}
}

func TestGetEventOperation_ProcessEvent(t *testing.T) {
	event := &api.Event{Type: api.EventTypeProcess}
	got := getEventOperation(event)
	if got != "" {
		t.Errorf("getEventOperation (process) = %q, want \"\"", got)
	}
}

// ---- Field constant values (ABI contract) ----

func TestFieldConstants(t *testing.T) {
	// These values are part of the host/WASM ABI; changes break policy modules.
	checks := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"FieldPID", FieldPID, 0},
		{"FieldUID", FieldUID, 1},
		{"FieldGID", FieldGID, 2},
		{"FieldFlags", FieldFlags, 3},
		{"FieldRemotePort", FieldRemotePort, 4},
		{"FieldLocalPort", FieldLocalPort, 5},
		{"FieldComm", FieldComm, 10},
		{"FieldPath", FieldPath, 11},
		{"FieldOperation", FieldOperation, 12},
		{"FieldProtocol", FieldProtocol, 13},
		{"FieldRemoteAddr", FieldRemoteAddr, 14},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d (ABI break)", c.name, c.got, c.want)
		}
	}
}
