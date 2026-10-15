package simulator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

// testPolicyPath points at the prebuilt WASM fixture shipped with internal/wasm.
// Policy: uid 0 + "bash" -> DENY, "python" -> LOG, everything else -> ALLOW.
const testPolicyPath = "../wasm/testdata/allow_policy.wasm"

func newTestEvaluator(t *testing.T) *wasm.PolicyEvaluator {
	t.Helper()
	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{PoolSize: 1})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if err := rt.LoadPolicy(ctx, testPolicyPath); err != nil {
		_ = rt.Close(ctx)
		t.Fatalf("LoadPolicy: %v", err)
	}
	pool, err := wasm.NewPool(ctx, rt, 1)
	if err != nil {
		_ = rt.Close(ctx)
		t.Fatalf("NewPool: %v", err)
	}
	ev := wasm.NewPolicyEvaluator(pool, "test-host")
	t.Cleanup(func() {
		_ = ev.Close(ctx)
		_ = rt.Close(ctx)
	})
	return ev
}

func TestReplay_DecisionBreakdown(t *testing.T) {
	ev := newTestEvaluator(t)
	now := time.Now()

	events := []*streaming.SecurityEvent{
		// Previously allowed, now denied (x2, same pattern -> one unique denial with count 2).
		{Timestamp: now, EventType: "exec", UID: 0, Comm: "bash", Filename: "/bin/bash", Decision: "ALLOW"},
		{Timestamp: now, EventType: "exec", UID: 0, Comm: "bash", Filename: "/bin/bash", Decision: "ALLOW"},
		// Previously denied, now allowed (x2, same pattern).
		{Timestamp: now, EventType: "file", UID: 1000, Comm: "cat", Filename: "/etc/hosts", Decision: "DENY"},
		{Timestamp: now, EventType: "file", UID: 1000, Comm: "cat", Filename: "/etc/hosts", Decision: "DENY"},
		// Logged.
		{Timestamp: now, EventType: "exec", UID: 1000, Comm: "python3", Filename: "/usr/bin/python3", Decision: "LOG"},
		// Unchanged allows on network paths.
		{Timestamp: now, EventType: "network", UID: 1000, Comm: "curl", RemoteAddr: "10.0.0.1", RemotePort: 443, Protocol: "tcp", Decision: "ALLOW"},
		{Timestamp: now, EventType: "listen", UID: 1000, Comm: "nginx", LocalPort: 8080, Decision: "ALLOW"},
	}

	res, err := Replay(context.Background(), events, ev)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}

	if res.TotalEvents != len(events) {
		t.Errorf("TotalEvents = %d, want %d", res.TotalEvents, len(events))
	}
	if res.WouldDeny != 2 {
		t.Errorf("WouldDeny = %d, want 2", res.WouldDeny)
	}
	if res.WouldLog != 1 {
		t.Errorf("WouldLog = %d, want 1", res.WouldLog)
	}
	if res.WouldAllow != 4 {
		t.Errorf("WouldAllow = %d, want 4", res.WouldAllow)
	}

	if len(res.UniqueNewDenials) != 1 {
		t.Fatalf("UniqueNewDenials = %d, want 1", len(res.UniqueNewDenials))
	}
	d := res.UniqueNewDenials[0]
	if d.EventType != "exec" || d.Comm != "bash" || d.Target != "/bin/bash" || d.Count != 2 {
		t.Errorf("unexpected denial detail: %+v", d)
	}
	if d.Reason == "" {
		t.Error("expected non-empty denial reason")
	}

	if len(res.UniqueNewAllows) != 1 {
		t.Fatalf("UniqueNewAllows = %d, want 1", len(res.UniqueNewAllows))
	}
	a := res.UniqueNewAllows[0]
	if a.EventType != "file" || a.Comm != "cat" || a.Target != "/etc/hosts" || a.Count != 2 {
		t.Errorf("unexpected allow detail: %+v", a)
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %v, want > 0", res.Duration)
	}
}

func TestReplay_Empty(t *testing.T) {
	ev := newTestEvaluator(t)
	res, err := Replay(context.Background(), nil, ev)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if res.TotalEvents != 0 || res.WouldAllow != 0 || res.WouldDeny != 0 || res.WouldLog != 0 {
		t.Errorf("expected zero counts, got %+v", res)
	}
	if res.UniqueNewDenials != nil || res.UniqueNewAllows != nil {
		t.Error("expected nil detail slices for empty replay")
	}
}

func TestReplay_CancelledContext(t *testing.T) {
	ev := newTestEvaluator(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	events := []*streaming.SecurityEvent{{EventType: "exec", Comm: "ls", Decision: "ALLOW"}}
	res, err := Replay(ctx, events, ev)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if res != nil {
		t.Errorf("expected nil result on cancellation, got %+v", res)
	}
}

func TestSecurityEventToAPIEvent_Types(t *testing.T) {
	base := streaming.SecurityEvent{
		PID: 1, UID: 2, GID: 3, Comm: "c", Filename: "/f", CgroupID: 9,
		RemoteAddr: "1.2.3.4", RemotePort: 53, LocalPort: 5353, Protocol: "udp",
	}

	tests := []struct {
		eventType string
		wantType  api.EventType
		check     func(t *testing.T, e *api.Event)
	}{
		{"exec", api.EventTypeProcess, func(t *testing.T, e *api.Event) {
			if e.Process == nil || e.Process.Filename != "/f" || e.Process.CgroupID != 9 {
				t.Errorf("bad Process payload: %+v", e.Process)
			}
		}},
		{"file", api.EventTypeFile, func(t *testing.T, e *api.Event) {
			if e.File == nil || e.File.Path != "/f" {
				t.Errorf("bad File payload: %+v", e.File)
			}
		}},
		{"network", api.EventTypeNetwork, func(t *testing.T, e *api.Event) {
			n := e.Network
			if n == nil || n.RemoteAddr != "1.2.3.4" || n.RemotePort != 53 || n.LocalPort != 5353 || n.Protocol != "udp" {
				t.Errorf("bad Network payload: %+v", n)
			}
		}},
		{"bind", api.EventTypeNetwork, nil},
		{"listen", api.EventTypeNetwork, nil},
	}

	for _, tt := range tests {
		t.Run(tt.eventType, func(t *testing.T) {
			se := base
			se.EventType = tt.eventType
			e := securityEventToAPIEvent(&se)
			if e.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", e.Type, tt.wantType)
			}
			if e.PID != 1 || e.UID != 2 || e.GID != 3 || e.Comm != "c" || e.Filename != "/f" || e.CgroupID != 9 {
				t.Errorf("base fields not copied: %+v", e)
			}
			if tt.check != nil {
				tt.check(t, e)
			}
		})
	}

	t.Run("unknown", func(t *testing.T) {
		se := base
		se.EventType = "ptrace"
		e := securityEventToAPIEvent(&se)
		if e.Process != nil || e.File != nil || e.Network != nil {
			t.Error("expected no typed payload for unknown event type")
		}
	})
}

func TestEventTarget(t *testing.T) {
	tests := []struct {
		name string
		ev   streaming.SecurityEvent
		want string
	}{
		{"exec", streaming.SecurityEvent{EventType: "exec", Filename: "/bin/ls"}, "/bin/ls"},
		{"file", streaming.SecurityEvent{EventType: "file", Filename: "/etc/passwd"}, "/etc/passwd"},
		{"network", streaming.SecurityEvent{EventType: "network", RemoteAddr: "10.0.0.1", RemotePort: 443}, "10.0.0.1:443"},
		{"bind", streaming.SecurityEvent{EventType: "bind", LocalPort: 80}, ":80"},
		{"listen", streaming.SecurityEvent{EventType: "listen", LocalPort: 8080}, ":8080"},
		{"default", streaming.SecurityEvent{EventType: "mount", Filename: "/mnt"}, "/mnt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := eventTarget(&tt.ev); got != tt.want {
				t.Errorf("eventTarget = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatJSON(t *testing.T) {
	in := &SimulationResult{
		TotalEvents: 3, WouldAllow: 1, WouldDeny: 1, WouldLog: 1,
		UniqueNewDenials: []DenialDetail{{EventType: "exec", Comm: "bash", Target: "/bin/bash", Count: 1, Reason: "r"}},
		Duration:         time.Millisecond,
	}
	var buf bytes.Buffer
	if err := FormatJSON(&buf, in); err != nil {
		t.Fatalf("FormatJSON: %v", err)
	}
	if !strings.Contains(buf.String(), "\n  \"total_events\": 3") {
		t.Errorf("expected indented JSON, got:\n%s", buf.String())
	}
	var out SimulationResult
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.TotalEvents != 3 || len(out.UniqueNewDenials) != 1 || out.UniqueNewDenials[0].Reason != "r" {
		t.Errorf("round-trip mismatch: %+v", out)
	}
	if strings.Contains(buf.String(), "unique_new_allows") {
		t.Error("expected unique_new_allows to be omitted when empty")
	}
}

func TestFormatText_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := FormatText(&buf, &SimulationResult{}); err != nil {
		t.Fatalf("FormatText: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Policy Simulation Report",
		"Events replayed: 0",
		"ALLOW: 0 (0.0%)",
		"No new denials",
		"No new allows",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestFormatText_WithDetails(t *testing.T) {
	longTarget := "/" + strings.Repeat("a", 60)
	res := &SimulationResult{
		TotalEvents: 4, WouldAllow: 1, WouldDeny: 2, WouldLog: 1,
		UniqueNewDenials: []DenialDetail{
			{EventType: "exec", Comm: "low", Target: "/bin/low", Count: 1},
			{EventType: "exec", Comm: "high", Target: longTarget, Count: 5},
		},
		UniqueNewAllows: []AllowDetail{
			{EventType: "file", Comm: "a1", Target: "/x", Count: 2},
			{EventType: "file", Comm: "a2", Target: "/y", Count: 9},
		},
		Duration: 1500 * time.Microsecond,
	}
	var buf bytes.Buffer
	if err := FormatText(&buf, res); err != nil {
		t.Fatalf("FormatText: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"DENY:  2 (50.0%)",
		"LOG:   1 (25.0%)",
		"New denials (2 unique patterns):",
		"New allows (2 unique patterns):",
		truncate(longTarget, 40),
		"Duration:        2ms",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, longTarget) {
		t.Error("expected long target to be truncated")
	}
	// Sorted by count descending.
	if strings.Index(out, "high") > strings.Index(out, "low") {
		t.Error("denials not sorted by count descending")
	}
	if strings.Index(out, "a2") > strings.Index(out, "a1") {
		t.Error("allows not sorted by count descending")
	}
	// FormatText must not reorder the caller's slices.
	if res.UniqueNewDenials[0].Comm != "low" || res.UniqueNewAllows[0].Comm != "a1" {
		t.Error("FormatText mutated the result's slice order")
	}
}

func TestPct(t *testing.T) {
	if got := pct(1, 0); got != 0 {
		t.Errorf("pct(1,0) = %v, want 0", got)
	}
	if got := pct(1, 4); got != 25 {
		t.Errorf("pct(1,4) = %v, want 25", got)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		in   string
		max  int
		want string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is too long", 10, "this is..."},
	}
	for _, tt := range tests {
		if got := truncate(tt.in, tt.max); got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
		}
	}
}

// daemonRecording is ndjson exactly as warmor-daemon's streaming pipeline
// writes it: decisions are lowercase ("allow", "deny", "log").
const daemonRecording = `{"id":"e1","timestamp":"2026-01-02T03:04:05Z","hostname":"node-1","event_type":"exec","pid":42,"uid":0,"gid":0,"comm":"bash","filename":"/bin/bash","decision":"allow","cached":false,"enforced":false,"latency_us":12}
{"id":"e2","timestamp":"2026-01-02T03:04:06Z","hostname":"node-1","event_type":"file","pid":43,"uid":1000,"gid":1000,"comm":"cat","filename":"/etc/hosts","decision":"deny","reason":"blocked","cached":false,"enforced":true,"latency_us":9}
{"id":"e3","timestamp":"2026-01-02T03:04:07Z","hostname":"node-1","event_type":"exec","pid":44,"uid":0,"gid":0,"comm":"bash","filename":"/usr/bin/bash","decision":"log","cached":false,"enforced":false,"latency_us":7}
{"id":"e4","timestamp":"2026-01-02T03:04:08Z","hostname":"node-1","event_type":"exec","pid":45,"uid":1000,"gid":1000,"comm":"python3","filename":"/usr/bin/python3","decision":"log","cached":false,"enforced":false,"latency_us":7}
`

func TestReplay_DaemonRecordingLowercaseDecisions(t *testing.T) {
	var events []*streaming.SecurityEvent
	for _, line := range strings.Split(strings.TrimSpace(daemonRecording), "\n") {
		var e streaming.SecurityEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		events = append(events, &e)
	}

	res, err := Replay(context.Background(), events, newTestEvaluator(t))
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if res.WouldDeny != 2 || res.WouldAllow != 1 || res.WouldLog != 1 {
		t.Errorf("breakdown allow/deny/log = %d/%d/%d, want 1/2/1", res.WouldAllow, res.WouldDeny, res.WouldLog)
	}
	// allow->DENY and log->DENY (log permits the event) are both new denials.
	if len(res.UniqueNewDenials) != 2 {
		t.Errorf("UniqueNewDenials = %+v, want 2 entries", res.UniqueNewDenials)
	}
	// deny->ALLOW is a new allow; log->LOG is unchanged.
	if len(res.UniqueNewAllows) != 1 || res.UniqueNewAllows[0].Target != "/etc/hosts" {
		t.Errorf("UniqueNewAllows = %+v, want only /etc/hosts", res.UniqueNewAllows)
	}
}

func TestNormalizeDecision(t *testing.T) {
	for in, want := range map[string]string{
		"allow": "allow", "ALLOW": "allow", " Deny ": "deny", "LOG": "log", "": "", "weird": "weird",
	} {
		if got := normalizeDecision(in); got != want {
			t.Errorf("normalizeDecision(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestContainerStartRoundTrip: the container start the enforcer determined
// is recorded by sinks and replayed, so age-based temporal rules see the
// same container age in warmor-simulate as they did live.
func TestContainerStartRoundTrip(t *testing.T) {
	start := time.Unix(1_700_000_000, 0).UTC()
	ev := &api.Event{Comm: "curl", Timestamp: start.Add(time.Hour), CgroupID: 4, ContainerStart: start}
	data, err := json.Marshal(streaming.FromAPIEvent(ev, &api.ActionResult{Action: api.ActionAllow}))
	if err != nil {
		t.Fatal(err)
	}
	var se streaming.SecurityEvent
	if err := json.Unmarshal(data, &se); err != nil {
		t.Fatal(err)
	}
	if got := securityEventToAPIEvent(&se); !got.ContainerStart.Equal(start) {
		t.Errorf("replayed ContainerStart = %v, want %v (json %s)", got.ContainerStart, start, data)
	}
	// Unknown stays unknown and is not written at all.
	data, _ = json.Marshal(streaming.FromAPIEvent(&api.Event{Comm: "x"}, nil))
	if bytes.Contains(data, []byte("container_start")) {
		t.Errorf("zero ContainerStart serialized: %s", data)
	}
}
