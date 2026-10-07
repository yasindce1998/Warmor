package wasm

import (
	"context"
	"testing"

	"github.com/yasindce1998/warmor/pkg/api"
)

// newTestRuntime is a helper that creates a Runtime with the prebuilt fixture
// already loaded. It calls t.Fatal on any error.
func newTestRuntime(t *testing.T) *Runtime {
	t.Helper()
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if err := rt.LoadPolicy(ctx, testPolicyPath); err != nil {
		rt.Close(ctx)
		t.Fatalf("LoadPolicy: %v", err)
	}
	return rt
}

// newTestPolicy is a helper that returns a Policy backed by the fixture Runtime.
func newTestPolicy(t *testing.T, rt *Runtime) *Policy {
	t.Helper()
	ctx := context.Background()
	pol, err := NewPolicy(ctx, rt)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return pol
}

// ---- NewPolicy ----

func TestNewPolicy_Success(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)

	pol, err := NewPolicy(ctx, rt)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	defer pol.Close(ctx)

	if pol.instance == nil {
		t.Error("Policy.instance is nil after NewPolicy")
	}
	// The fixture uses the JSON ABI (evaluate_syscall), not binary ABI.
	if pol.useBinaryABI {
		t.Error("expected useBinaryABI=false for JSON-ABI fixture")
	}
}

// TestNewPool_NoModule verifies that NewPool (the public creation path) returns an
// error when the runtime has no compiled module, protecting callers from the
// Wazero panic that would occur if nil module were passed to InstantiateModule.
func TestNewPool_NoModuleGuard(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	// NewPool guards the nil-module case and must return an error.
	_, err = NewPool(ctx, rt, 1)
	if err == nil {
		t.Fatal("expected error from NewPool when runtime has no module, got nil")
	}
}

// ---- Policy.Evaluate (JSON ABI) ----

func TestPolicy_Evaluate_Allow(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)
	pol := newTestPolicy(t, rt)
	defer pol.Close(ctx)

	event := &api.Event{
		PID:      1,
		UID:      1000,
		GID:      1000,
		Comm:     "ls",
		Filename: "/bin/ls",
		Type:     api.EventTypeProcess,
	}

	action, err := pol.Evaluate(ctx, event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if action != api.ActionAllow {
		t.Errorf("action = %v, want ActionAllow", action)
	}
}

func TestPolicy_Evaluate_DenyRootBash(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)
	pol := newTestPolicy(t, rt)
	defer pol.Close(ctx)

	event := &api.Event{
		PID:      2,
		UID:      0, // root
		GID:      0,
		Comm:     "bash",
		Filename: "/bin/bash",
		Type:     api.EventTypeProcess,
	}

	action, err := pol.Evaluate(ctx, event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if action != api.ActionDeny {
		t.Errorf("action = %v, want ActionDeny (root+bash rule)", action)
	}
}

func TestPolicy_Evaluate_LogPython(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)
	pol := newTestPolicy(t, rt)
	defer pol.Close(ctx)

	event := &api.Event{
		PID:      3,
		UID:      1000,
		GID:      1000,
		Comm:     "python3",
		Filename: "/usr/bin/python3",
		Type:     api.EventTypeProcess,
	}

	action, err := pol.Evaluate(ctx, event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if action != api.ActionLog {
		t.Errorf("action = %v, want ActionLog (python rule)", action)
	}
}

func TestPolicy_Evaluate_FileEvent(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)
	pol := newTestPolicy(t, rt)
	defer pol.Close(ctx)

	event := &api.Event{
		PID:  10,
		UID:  1000,
		GID:  1000,
		Comm: "vim",
		Type: api.EventTypeFile,
		File: &api.FileEvent{
			Operation: "open",
			Path:      "/etc/hosts",
			Flags:     0,
		},
	}

	action, err := pol.Evaluate(ctx, event)
	if err != nil {
		t.Fatalf("Evaluate file event: %v", err)
	}
	if action != api.ActionAllow {
		t.Errorf("action = %v, want ActionAllow for file event", action)
	}
}

func TestPolicy_Evaluate_NetworkEvent(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)
	pol := newTestPolicy(t, rt)
	defer pol.Close(ctx)

	event := &api.Event{
		PID:  20,
		UID:  1000,
		GID:  1000,
		Comm: "curl",
		Type: api.EventTypeNetwork,
		Network: &api.NetworkEvent{
			Operation:  "connect",
			Protocol:   "tcp",
			RemoteAddr: "93.184.216.34",
			RemotePort: 443,
		},
	}

	action, err := pol.Evaluate(ctx, event)
	if err != nil {
		t.Fatalf("Evaluate network event: %v", err)
	}
	if action != api.ActionAllow {
		t.Errorf("action = %v, want ActionAllow for network event", action)
	}
}

// TestPolicy_Evaluate_MultipleCallsOnSameInstance verifies that a single Policy
// can be evaluated multiple times without state leaking between calls.
func TestPolicy_Evaluate_MultipleCallsOnSameInstance(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)
	pol := newTestPolicy(t, rt)
	defer pol.Close(ctx)

	calls := []struct {
		event  *api.Event
		want   api.Action
	}{
		{&api.Event{UID: 0, Comm: "bash", Filename: "/bin/bash", Type: api.EventTypeProcess}, api.ActionDeny},
		{&api.Event{UID: 1000, Comm: "ls", Filename: "/bin/ls", Type: api.EventTypeProcess}, api.ActionAllow},
		{&api.Event{UID: 0, Comm: "bash", Filename: "/bin/bash", Type: api.EventTypeProcess}, api.ActionDeny},
		{&api.Event{UID: 1000, Comm: "python3", Filename: "/usr/bin/python3", Type: api.EventTypeProcess}, api.ActionLog},
	}

	for i, c := range calls {
		action, err := pol.Evaluate(ctx, c.event)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if action != c.want {
			t.Errorf("call %d: action = %v, want %v", i, action, c.want)
		}
	}
}

// ---- Policy.Close ----

func TestPolicy_Close(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)
	pol := newTestPolicy(t, rt)

	if err := pol.Close(ctx); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

// ---- writeEventBinary ----

func TestWriteEventBinary_ProcessEvent(t *testing.T) {
	event := &api.Event{
		PID:  100,
		UID:  1000,
		GID:  2000,
		Comm: "test",
		Type: api.EventTypeProcess,
		Process: &api.ProcessEvent{
			Filename: "/usr/bin/test",
		},
	}

	buf := make([]byte, eventStructSize)
	writeEventBinary(buf, event)

	// PID at offset 0
	pid := uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
	if pid != 100 {
		t.Errorf("PID = %d, want 100", pid)
	}

	// UID at offset 4
	uid := uint32(buf[4]) | uint32(buf[5])<<8 | uint32(buf[6])<<16 | uint32(buf[7])<<24
	if uid != 1000 {
		t.Errorf("UID = %d, want 1000", uid)
	}

	// GID at offset 8
	gid := uint32(buf[8]) | uint32(buf[9])<<8 | uint32(buf[10])<<16 | uint32(buf[11])<<24
	if gid != 2000 {
		t.Errorf("GID = %d, want 2000", gid)
	}

	// EventType byte at offset 12
	if buf[12] != byte(api.EventTypeProcess) {
		t.Errorf("EventType byte = %d, want %d", buf[12], api.EventTypeProcess)
	}

	// Comm at offset 13 (64 bytes, null-padded)
	comm := nullTerminated(buf[13:77])
	if comm != "test" {
		t.Errorf("comm = %q, want \"test\"", comm)
	}

	// Filename at offset 77 (128 bytes)
	filename := nullTerminated(buf[77:205])
	if filename != "/usr/bin/test" {
		t.Errorf("filename = %q, want \"/usr/bin/test\"", filename)
	}
}

func TestWriteEventBinary_FileEvent(t *testing.T) {
	event := &api.Event{
		PID:  200,
		UID:  1000,
		GID:  1000,
		Comm: "vim",
		Type: api.EventTypeFile,
		File: &api.FileEvent{
			Path:      "/etc/passwd",
			Operation: "write",
			Flags:     0x241,
		},
	}

	buf := make([]byte, eventStructSize)
	writeEventBinary(buf, event)

	if buf[12] != byte(api.EventTypeFile) {
		t.Errorf("EventType = %d, want EventTypeFile(%d)", buf[12], api.EventTypeFile)
	}

	path := nullTerminated(buf[77:205])
	if path != "/etc/passwd" {
		t.Errorf("path = %q, want \"/etc/passwd\"", path)
	}

	flags := uint32(buf[205]) | uint32(buf[206])<<8 | uint32(buf[207])<<16 | uint32(buf[208])<<24
	if flags != 0x241 {
		t.Errorf("flags = 0x%x, want 0x241", flags)
	}

	op := nullTerminated(buf[213:245])
	if op != "write" {
		t.Errorf("operation = %q, want \"write\"", op)
	}
}

func TestWriteEventBinary_NetworkEvent(t *testing.T) {
	event := &api.Event{
		PID:  300,
		UID:  1000,
		GID:  1000,
		Comm: "curl",
		Type: api.EventTypeNetwork,
		Network: &api.NetworkEvent{
			RemoteAddr: "1.2.3.4",
			RemotePort: 443,
			LocalPort:  12345,
			Protocol:   "tcp",
		},
	}

	buf := make([]byte, eventStructSize)
	writeEventBinary(buf, event)

	if buf[12] != byte(api.EventTypeNetwork) {
		t.Errorf("EventType = %d, want EventTypeNetwork(%d)", buf[12], api.EventTypeNetwork)
	}

	addr := nullTerminated(buf[77:205])
	if addr != "1.2.3.4" {
		t.Errorf("remote_addr = %q, want \"1.2.3.4\"", addr)
	}

	remotePort := uint16(buf[209]) | uint16(buf[210])<<8
	if remotePort != 443 {
		t.Errorf("remote_port = %d, want 443", remotePort)
	}

	localPort := uint16(buf[211]) | uint16(buf[212])<<8
	if localPort != 12345 {
		t.Errorf("local_port = %d, want 12345", localPort)
	}

	proto := nullTerminated(buf[213:245])
	if proto != "tcp" {
		t.Errorf("protocol = %q, want \"tcp\"", proto)
	}
}

func TestWriteEventBinary_ZeroBuffer(t *testing.T) {
	// A default zero-value event should produce an all-zero buffer with no panics.
	event := &api.Event{}
	buf := make([]byte, eventStructSize)
	writeEventBinary(buf, event) // must not panic

	// EventType byte defaults to EventTypeProcess (0).
	if buf[12] != 0 {
		t.Errorf("EventType byte = %d, want 0 for zero-value event", buf[12])
	}
}

func TestWriteEventBinary_BufferIsAlwaysCleared(t *testing.T) {
	// Pre-fill the buffer with 0xFF to verify writeEventBinary always zeroes it first.
	buf := make([]byte, eventStructSize)
	for i := range buf {
		buf[i] = 0xFF
	}

	event := &api.Event{PID: 1, UID: 1, Comm: "a", Type: api.EventTypeProcess}
	writeEventBinary(buf, event)

	// Padding bytes (offset 245–255) must be zero, not 0xFF.
	for i := 245; i < eventStructSize; i++ {
		if buf[i] != 0 {
			t.Errorf("buf[%d] = 0x%02x, want 0x00 (padding should be cleared)", i, buf[i])
		}
	}
}

func TestWriteEventBinary_CommTruncation(t *testing.T) {
	// A comm string longer than 64 bytes must be silently truncated, not panic.
	longComm := string(make([]byte, 100))
	for i := range []byte(longComm) {
		longComm = longComm[:i] + "A" + longComm[i+1:]
	}

	event := &api.Event{Comm: longComm, Type: api.EventTypeProcess}
	buf := make([]byte, eventStructSize)
	writeEventBinary(buf, event) // must not panic
}

func TestWriteEventBinary_FileEventFallback(t *testing.T) {
	// File event with no File sub-struct falls back to Filename + "open".
	event := &api.Event{
		PID:      400,
		UID:      1000,
		Comm:     "cat",
		Filename: "/tmp/data.txt",
		Type:     api.EventTypeFile,
	}

	buf := make([]byte, eventStructSize)
	writeEventBinary(buf, event)

	path := nullTerminated(buf[77:205])
	if path != "/tmp/data.txt" {
		t.Errorf("fallback path = %q, want \"/tmp/data.txt\"", path)
	}

	op := nullTerminated(buf[213:245])
	if op != "open" {
		t.Errorf("fallback operation = %q, want \"open\"", op)
	}
}

// ---- GetMatchedRule ----

// TestPolicy_GetMatchedRule_NoExport verifies that a WASM module without
// get_last_matched_rule returns an empty string gracefully.
func TestPolicy_GetMatchedRule_NoExport(t *testing.T) {
	ctx := context.Background()
	rt := newTestRuntime(t)
	defer rt.Close(ctx)
	pol := newTestPolicy(t, rt)
	defer pol.Close(ctx)

	// The fixture does not export get_last_matched_rule; expect "".
	reason := pol.GetMatchedRule(ctx)
	if reason != "" {
		t.Errorf("GetMatchedRule() = %q, want empty string (no export)", reason)
	}
}

// nullTerminated extracts the null-terminated string from a byte slice.
func nullTerminated(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
