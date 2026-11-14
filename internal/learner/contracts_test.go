package learner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/policymerge"
	"github.com/yasindce1998/warmor/internal/simulator"
	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/internal/testutil"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestLearnCompilerContracts(t *testing.T) {
	profile := newContainerProfile(1)
	for _, path := range []string{"/a.b", "/a-b", "/" + strings.Repeat("a", 80) + "x", "/" + strings.Repeat("a", 80) + "y", "$literal", "/雪"} {
		profile.Execs[path]++
	}
	profile.Networks["tcp:2001:db8::1:443"]++
	profile.Networks["tcp:[2001:db8::2]:8443"]++
	policy := Synthesize(profile, "contract")
	if err := policymerge.Validate(policy); err != nil {
		t.Fatal(err)
	}
	data, err := policymerge.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := compiler.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range parsed.Rules {
		for _, cond := range rule.Conditions.All {
			if cond.Field == "remote_port" {
				if _, ok := cond.Value.(int); !ok {
					t.Fatalf("port is not numeric: %#v", cond)
				}
			}
		}
	}
}

func TestLearnRefusesUnsupportedOrRedactedEvidence(t *testing.T) {
	for _, typ := range []string{"mount", "ptrace", "connect_unix", "future"} {
		s := NewSession(Config{})
		if err := s.Recorder().Write(context.Background(), &streaming.SecurityEvent{EventType: typ, MountType: "tmpfs", PtraceComm: "tool", Filename: "/tool"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.MarshalPolicy(); err == nil {
			t.Errorf("emitted policy for %s", typ)
		}
	}
	s := NewSession(Config{})
	if err := s.Recorder().Write(context.Background(), &streaming.SecurityEvent{EventType: "exec", Filename: "/tool", InputIssues: []streaming.InputIssue{{Field: "filename", State: "redacted"}}}); err == nil {
		t.Fatal("accepted redacted evidence")
	}
}

func TestLearnRefusesUnmatchableLongPath(t *testing.T) {
	s := NewSession(Config{})
	if err := s.Recorder().Write(context.Background(), &streaming.SecurityEvent{EventType: "exec", Filename: "/" + strings.Repeat("x", 128)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarshalPolicy(); err == nil {
		t.Fatal("emitted an exact path allow binary ABI truncation prevents matching")
	}
}

func TestLearnValidatesRecordingEvidence(t *testing.T) {
	ctx := context.Background()
	for name, event := range map[string]*streaming.SecurityEvent{
		"nil":                    nil,
		"future schema":          {SchemaVersion: streaming.EventSchemaVersion + 1},
		"negative schema":        {SchemaVersion: -1},
		"missing snapshot":       {SchemaVersion: 2, EventType: "exec", Filename: "/tool"},
		"missing legacy path":    {EventType: "file"},
		"missing legacy addr":    {EventType: "network", Protocol: "tcp", RemotePort: 443},
		"missing legacy proto":   {EventType: "bind", LocalPort: 80},
		"missing typed path":     streaming.FromAPIEvent(&api.Event{Process: &api.ProcessEvent{}}, nil),
		"missing operation":      streaming.FromAPIEvent(&api.Event{Type: api.EventTypeNetwork, Network: &api.NetworkEvent{Protocol: "tcp", RemoteAddr: "::1", RemotePort: 443}}, nil),
		"unknown snapshot":       {SchemaVersion: 2, PolicyInput: &api.Event{Filename: "/tool"}, InputIssues: []streaming.InputIssue{{Field: "policy_input", State: "unknown"}}},
		"unknown endpoint port":  {EventType: "bind", Protocol: "tcp", LocalPort: 80, InputIssues: []streaming.InputIssue{{Field: "network.local_port", State: "unknown"}}},
		"unsupported typed hook": streaming.FromAPIEvent(&api.Event{Hook: "future", Process: &api.ProcessEvent{Filename: "/tool"}}, nil),
	} {
		t.Run(name, func(t *testing.T) {
			r := NewRecorder(nil)
			if err := r.Write(ctx, event); err == nil {
				t.Fatal("accepted invalid recording evidence")
			}
			if len(r.Profiles()) != 0 {
				t.Fatal("invalid evidence changed profiles")
			}
		})
	}
	// The evaluator snapshot wins over separately editable summaries and
	// supplies the cgroup used by the recording filter.
	r := NewRecorder([]uint64{42})
	event := streaming.FromAPIEvent(&api.Event{CgroupID: 42, Process: &api.ProcessEvent{Filename: "/actual", Args: []string{}}}, nil)
	event.Filename, event.CgroupID = "/summary", 99
	if err := r.Write(ctx, event); err != nil {
		t.Fatal(err)
	}
	if p := r.Profiles()[42]; p == nil || p.Execs["/actual"] != 1 || p.Execs["/summary"] != 0 {
		t.Fatalf("learned editable summaries: %+v", p)
	}
}

// Exercise actual Rust/WASM compilation and evaluation, not only YAML shape.
func TestRecordLearnCompileReplay(t *testing.T) {
	if !compiler.CargoAvailable() {
		if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
			t.Fatal("requires cargo and wasm32-unknown-unknown")
		}
		t.Skip("requires cargo and wasm32-unknown-unknown")
	}
	ctx := context.Background()
	start := time.Unix(1700000000, 0).UTC()
	inputs := []*api.Event{
		{Comm: "tool", Filename: "/雪/tool", PPID: 2, ParentComm: "parent", Process: &api.ProcessEvent{Filename: "/雪/tool", Args: []string{"tool", "--dangerous"}}},
		{Type: api.EventTypeFile, Comm: "tool", File: &api.FileEvent{Path: "/雪/data", Operation: "write", Flags: 66}},
		{Type: api.EventTypeNetwork, Comm: "tool", Network: &api.NetworkEvent{Operation: "connect", Protocol: "tcp", RemoteAddr: "2001:db8::1", RemotePort: 443}},
		{Type: api.EventTypeNetwork, Comm: "server", Hook: "bind", Network: &api.NetworkEvent{Operation: "connect", Protocol: "udp", LocalPort: 53}},
		{Type: api.EventTypeNetwork, Comm: "server", Hook: "listen", Network: &api.NetworkEvent{Operation: "listen", Protocol: "tcp", LocalPort: 8080}},
		{Type: api.EventTypeNetwork, Comm: "server", Hook: "bind", Network: &api.NetworkEvent{Operation: "bind", Protocol: "tcp", LocalPort: 8443}},
	}
	dir := filepath.Join(testutil.PhysicalTempDir(t), "store")
	store, err := simulator.NewEventStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range inputs {
		input.Timestamp, input.ContainerStart = start.Add(time.Minute), start
		if err := store.Write(ctx, streaming.FromAPIEvent(input, &api.ActionResult{Action: api.ActionAllow})); err != nil {
			t.Fatal(err)
		}
	}
	// Legacy operation is unavailable: learn/replay use the same historical
	// connect fallback, and replay must clearly mark evidence incomplete.
	if err := store.Write(ctx, &streaming.SecurityEvent{Timestamp: start.Add(time.Minute), EventType: "bind", Comm: "old-server", Protocol: "tcp", LocalPort: 80}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	recorded, err := simulator.ReadEvents(dir, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	session := NewSession(Config{Name: "roundtrip"})
	for _, event := range recorded {
		if err := session.Recorder().Write(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	learned, err := session.MarshalPolicy()
	if err != nil {
		t.Fatal(err)
	}
	res := compileAndReplay(t, learned, recorded)
	if res.WouldAllow != len(inputs)+1 || res.EvaluationErrors != 0 {
		t.Fatalf("learned policy rejected observations: %+v\n%s", res, learned)
	}
	candidate := []byte(`name: candidate
version: 1
default_action: allow
rules:
  - name: argv
    event: process
    action: deny
    conditions:
      all:
        - args: { contains: --dangerous }
  - name: file-inputs
    event: file
    action: deny
    conditions:
      all:
        - operation: write
        - flags: 66
  - name: network-inputs
    event: network
    action: deny
    conditions:
      all:
        - operation: { any_of: [connect, bind, listen] }
`)
	res = compileAndReplay(t, candidate, recorded)
	if res.WouldDeny != len(inputs)+1 || res.EvaluationErrors != 0 {
		t.Fatalf("lost policy-visible input: %+v", res)
	}
}

func compileAndReplay(t *testing.T, data []byte, recorded []*streaming.SecurityEvent) *simulator.SimulationResult {
	t.Helper()
	policy, err := compiler.Parse(data)
	if err != nil {
		t.Fatalf("validate: %v\n%s", err, data)
	}
	built, err := compiler.Build(policy, compiler.BuildOptions{OutputPath: filepath.Join(t.TempDir(), "policy.wasm")})
	if err != nil {
		t.Fatal(err)
	}
	defer compiler.Cleanup(built)
	ctx := context.Background()
	runtime, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = runtime.Close(ctx) }()
	if err := runtime.LoadPolicy(ctx, built.WasmPath); err != nil {
		t.Fatal(err)
	}
	pool, err := wasm.NewPool(ctx, runtime, 1)
	if err != nil {
		t.Fatal(err)
	}
	ev := wasm.NewPolicyEvaluator(pool, "test")
	ev.SetTimeout(10 * time.Second)
	defer func() { _ = ev.Close(ctx) }()
	res, err := simulator.Replay(ctx, recorded, ev)
	if err != nil {
		t.Fatal(err)
	}
	return res
}
