package wasm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestCompiledPolicyArgsAndNetworkOperation(t *testing.T) {
	if !compiler.CargoAvailable() {
		if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
			t.Fatal("cargo and wasm32 target required")
		}
		t.Skip("cargo/wasm32 target unavailable")
	}
	p, err := compiler.Parse([]byte(`name: inputs
version: 1
default_action: allow
rules:
- name: args
  event: process
  action: deny
  conditions: {all: [{args: {contains: "--dangerous"}}]}
- name: recv
  event: network
  action: deny
  conditions: {all: [{operation: {eq: recvfrom}}]}
`))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "inputs.wasm")
	built, err := compiler.Build(p, compiler.BuildOptions{OutputPath: out})
	compiler.Cleanup(built)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	if err := rt.LoadPolicy(ctx, out); err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close(ctx)
	ev := NewPolicyEvaluator(pool, "test")
	for _, tc := range []struct {
		name  string
		event *api.Event
		want  api.Action
	}{
		{"bad argv", &api.Event{Process: &api.ProcessEvent{Filename: "/bin/tool", Args: []string{"tool", "--dangerous"}}}, api.ActionDeny},
		{"path is not argv", &api.Event{Process: &api.ProcessEvent{Filename: "/bin/--dangerous", Args: []string{"tool", "--safe"}}}, api.ActionAllow},
		{"missing argv", &api.Event{Process: &api.ProcessEvent{Filename: "/bin/tool"}}, api.ActionAllow},
		{"oversize argv", &api.Event{Process: &api.ProcessEvent{Args: []string{strings.Repeat("a", 16385)}}}, api.ActionDeny},
		{"invalid UTF-8 argv", &api.Event{Process: &api.ProcessEvent{Args: []string{"\xff"}}}, api.ActionDeny},
		{"recv", &api.Event{Type: api.EventTypeNetwork, Network: &api.NetworkEvent{Operation: "recvfrom"}}, api.ActionDeny},
		{"connect", &api.Event{Type: api.EventTypeNetwork, Network: &api.NetworkEvent{Operation: "connect"}}, api.ActionAllow},
		{"oversize operation", &api.Event{Type: api.EventTypeNetwork, Network: &api.NetworkEvent{Operation: strings.Repeat("a", 33)}}, api.ActionDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ev.Evaluate(ctx, tc.event)
			if err != nil || result.Action != tc.want {
				t.Fatalf("Evaluate = %+v, %v, want %v", result, err, tc.want)
			}
		})
	}
}
