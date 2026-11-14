package wasm

import (
	"context"
	"fmt"
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

func TestCompiledUnknownInputPreservesRulePosture(t *testing.T) {
	if !compiler.CargoAvailable() {
		if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
			t.Fatal("cargo and wasm32 target required")
		}
		t.Skip("cargo/wasm32 target unavailable")
	}
	for _, tc := range []struct {
		name, action, mode, extra string
		want                      api.Action
		audit                     bool
	}{
		{"audit-only", "deny", "audit", "", api.ActionDeny, true},
		{"log-only", "log", "", "", api.ActionLog, false},
		{"enforce", "deny", "", "", api.ActionDeny, false},
		{"earlier-allow", "deny", "", "- name: trusted\n  event: process\n  action: allow\n  conditions: {all: [{path: {eq: /bin/tool}}]}\n", api.ActionAllow, false},
		{"unrelated-condition", "deny", "", "", api.ActionAllow, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conditions := "{all: [{args: {contains: --dangerous}}]}"
			if tc.name == "unrelated-condition" {
				conditions = "{all: [{path: {eq: /bin/other}}, {args: {contains: --dangerous}}]}"
			}
			data := fmt.Sprintf("name: posture\nversion: 1\ndefault_action: allow\nrules:\n%s- name: argv\n  event: process\n  action: %s\n  mode: %q\n  conditions: %s\n", tc.extra, tc.action, tc.mode, conditions)
			p, err := compiler.Parse([]byte(data))
			if err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "posture.wasm")
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
			evaluator := NewPolicyEvaluator(pool, "test")
			// Simulate a sensor truncating a valid multibyte argument after
			// its first UTF-8 byte, as well as an oversized callback input.
			for _, arg := range []string{"\xff", strings.Repeat("a", 62) + "é"[:1], strings.Repeat("x", 16385)} {
				result, err := evaluator.Evaluate(ctx, &api.Event{Process: &api.ProcessEvent{Filename: "/bin/tool", Args: []string{"tool", arg}}})
				if err != nil || result.Action != tc.want || result.Audit != tc.audit {
					t.Fatalf("result=%+v err=%v want action=%v audit=%v", result, err, tc.want, tc.audit)
				}
			}
		})
	}
}
