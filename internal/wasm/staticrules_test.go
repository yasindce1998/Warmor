package wasm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

func staticTestTable(pattern string, action byte, port uint16) []byte {
	return append([]byte{action, 0, byte(port), byte(port >> 8), byte(len(pattern)), byte(len(pattern) >> 8)}, pattern...)
}

// Exercise the real compiled evaluator and its static exports together: exact
// identity changes must not change declaration-order first-match or defaults.
func TestCompiledStaticCollisionsAndLengthBoundary(t *testing.T) {
	if !compiler.CargoAvailable() {
		if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
			t.Fatal("cargo and wasm32-unknown-unknown target are required")
		}
		t.Skip("needs cargo and wasm32-unknown-unknown target")
	}
	if testing.Short() {
		t.Skip("needs cargo and wasm32-unknown-unknown target")
	}
	a, b := "/opt/warmor/collision-000079bb", "/opt/warmor/collision-00044848"
	boundary := "/" + strings.Repeat("x", 126)
	yaml := fmt.Sprintf(`name: exact-identity
version: 1
default_action: deny
rules:
  - name: first-allow
    event: process
    conditions:
      all:
        - path: %q
    action: allow
  - name: colliding-deny
    event: process
    conditions:
      all:
        - path: %q
    action: deny
  - name: shadowed-deny
    event: process
    conditions:
      all:
        - path: %q
    action: deny
  - name: shared-length-boundary
    event: process
    conditions:
      all:
        - path: %q
    action: allow
  - name: endpoint-allow
    event: network
    conditions:
      all:
        - remote_addr: 127.1.156.58
        - remote_port: 8644
    action: allow
  - name: endpoint-colliding-deny
    event: network
    conditions:
      all:
        - remote_addr: 127.1.248.57
        - remote_port: 24525
    action: deny
`, a, b, a, boundary)
	ctx := context.Background()
	file := filepath.Join(t.TempDir(), "identity.yaml")
	if err := os.WriteFile(file, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	rt, err := NewRuntime(ctx, RuntimeConfig{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := rt.Close(ctx); err != nil {
			t.Errorf("close static policy runtime: %v", err)
		}
	}()
	if err := rt.LoadPolicyFromYAML(ctx, file); err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy(ctx, rt)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := policy.Close(ctx); err != nil {
			t.Errorf("close static policy: %v", err)
		}
	}()
	process := readStaticDomain(ctx, policy, 0)
	network := readStaticDomain(ctx, policy, 2)
	if !process.Eligible || len(process.Rules) != 3 || process.Rules[0].Action != 0 || process.Rules[1].Action != 1 ||
		!network.Eligible || len(network.Rules) != 2 {
		t.Fatalf("static exports: %+v %+v", process, network)
	}
	for _, tc := range []struct {
		event *api.Event
		want  api.Action
	}{
		{&api.Event{Filename: a}, api.ActionAllow},
		{&api.Event{Filename: b}, api.ActionDeny},
		{&api.Event{Filename: "/unknown"}, api.ActionDeny},
		{&api.Event{Filename: boundary}, api.ActionAllow},
		{&api.Event{Filename: boundary + "x"}, api.ActionDeny},
		{&api.Event{Type: api.EventTypeNetwork, Network: &api.NetworkEvent{Operation: "connect", RemoteAddr: "127.1.156.58", RemotePort: 8644}}, api.ActionAllow},
		{&api.Event{Type: api.EventTypeNetwork, Network: &api.NetworkEvent{Operation: "connect", RemoteAddr: "127.1.248.57", RemotePort: 24525}}, api.ActionDeny},
		{&api.Event{Type: api.EventTypeNetwork, Network: &api.NetworkEvent{Operation: "connect", RemoteAddr: "127.1.156.58", RemotePort: 8645}}, api.ActionDeny},
	} {
		got, err := policy.Evaluate(ctx, tc.event)
		if err != nil || got != tc.want {
			t.Fatalf("%+v: action %v want %v error %v", tc.event, got, tc.want, err)
		}
	}
}

func TestParseStaticTableIdentityContractAndDuplicateDecline(t *testing.T) {
	for _, p := range []string{"", strings.Repeat("x", 128), strings.Repeat("x", 254), "a\x00b", "a\xff"} {
		if _, eligible, err := parseStaticTable(append([]byte{1}, staticTestTable(p, 0, 0)...), 0); eligible || err == nil {
			t.Fatalf("accepted incomplete process identity %q", p)
		}
	}
	for _, p := range []string{"2001:0db8::1", "::ffff:192.0.2.1", "fe80::1%eth0"} {
		if _, eligible, err := parseStaticTable(append([]byte{1}, staticTestTable(p, 0, 80)...), 2); eligible || err == nil {
			t.Fatalf("accepted noncanonical endpoint %q", p)
		}
	}
	if _, eligible, err := parseStaticTable([]byte{2}, 0); eligible || err == nil {
		t.Fatal("accepted invalid eligibility")
	}
	a, b := "/opt/warmor/collision-000079bb", "/opt/warmor/collision-00044848"
	table := append([]byte{1}, staticTestTable(a, 0, 0)...)
	table = append(table, staticTestTable(b, 1, 0)...)
	rules, eligible, err := parseStaticTable(table, 0)
	if err != nil || !eligible || len(rules) != 2 || rules[0].Action != 0 || rules[1].Action != 1 {
		t.Fatalf("distinct exact keys: %+v %v %v", rules, eligible, err)
	}
	// Compiler exports already deduplicate first-match keys. Custom duplicate
	// declarations decline optimization rather than hiding invalid metadata.
	table = append(table, staticTestTable(a, 1, 0)...)
	if _, eligible, err := parseStaticTable(table, 0); eligible || err == nil {
		t.Fatal("duplicate custom declaration promoted")
	}
}

// TestCompiledYAMLStaticRules builds a YAML allowlist policy with the real
// Rust toolchain and checks the module's static-rules declaration
// round-trips through the export ABI.
func TestCompiledYAMLStaticRules(t *testing.T) {
	if !compiler.CargoAvailable() {
		if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
			t.Fatal("cargo and wasm32-unknown-unknown target are required")
		}
		t.Skip("needs cargo and the wasm32-unknown-unknown target")
	}
	if testing.Short() {
		t.Skip("needs cargo and the wasm32-unknown-unknown target")
	}
	ctx := context.Background()
	yamlPath := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(yamlPath, []byte(`name: staticrules-e2e
version: 1
default_action: deny
rules:
  - name: allow-shell
    event: process
    conditions:
      all:
        - path: /bin/sh
    action: allow
  - name: allow-dns
    event: network
    conditions:
      all:
        - remote_addr: 10.0.0.1
        - remote_port: 53
    action: allow
  - name: audited-deny
    event: process
    conditions:
      all:
        - path: /tmp/x
    action: deny
    mode: audit
  - name: glob-rule
    event: process
    conditions:
      all:
        - path: { glob: "/usr/local/**" }
    action: allow
`), 0o600); err != nil {
		t.Fatal(err)
	}
	rt, err := NewRuntime(ctx, RuntimeConfig{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := rt.Close(ctx); err != nil {
			t.Errorf("close YAML policy runtime: %v", err)
		}
	}()
	if err := rt.LoadPolicyFromYAML(ctx, yamlPath); err != nil {
		t.Fatalf("LoadPolicyFromYAML: %v", err)
	}
	pool, err := NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pool.Close(ctx); err != nil {
			t.Errorf("close YAML policy pool: %v", err)
		}
	}()

	// The glob rule makes the process domain ineligible; the network
	// domain is eligible.
	if got := pool.StaticRulesProcess(); got.Eligible {
		t.Errorf("process domain eligible, want ineligible (glob rule)")
	}
	net := pool.StaticRulesNetwork()
	if !net.Eligible {
		t.Fatalf("network domain ineligible, want eligible")
	}
	want := []compiler.StaticRule{
		{Event: "network", Action: 0, Pattern: "10.0.0.1", Port: 53},
	}
	if !reflect.DeepEqual(net.Rules, want) {
		t.Errorf("network rules = %+v, want %+v", net.Rules, want)
	}

	// A module without the export (the hand-written fixtures) reports
	// nothing, so the kernel keeps allowing misses.
	fixture := newPoolFromBytes(t, wasmtest.ConstPolicy(0, nil), 1)
	if got := fixture.StaticRulesProcess(); got.Eligible || got.Rules != nil {
		t.Errorf("ConstPolicy process domain = %+v, want ineligible/empty", got)
	}
	if got := fixture.StaticRulesNetwork(); got.Eligible || got.Rules != nil {
		t.Errorf("ConstPolicy network domain = %+v, want ineligible/empty", got)
	}
}

// TestParseStaticTable_Malformed guards the host-side parser against
// truncated or invalid tables: anything malformed must read as ineligible,
// never as an incomplete allowlist.
func TestParseStaticTable_Malformed(t *testing.T) {
	for name, table := range map[string][]byte{
		"empty":            {},
		"ineligible":       {0},
		"header overrun":   {1, 0, 0},
		"pattern overrun":  {1, 0, 0, 0, 0, 9, 0, 'a'},
		"bad action byte":  {1, 7, 0, 0, 0, 1, 0, 'a'},
		"bad audit byte":   {1, 0, 9, 0, 0, 1, 0, 'a'},
		"trailing garbage": {1, 0, 0, 0, 0, 1, 0, 'a', 0xFF},
	} {
		rules, eligible, err := parseStaticTable(table, 0)
		if err == nil && (len(rules) > 0 || (eligible && len(table) > 1)) {
			t.Errorf("%s: parsed %+v (eligible=%v) from a malformed table", name, rules, eligible)
		}
	}
	// The one well-formed table parses.
	rules, eligible, err := parseStaticTable([]byte{1, 1, 1, 0, 0, 2, 0, 'a', 'b'}, 0)
	if err != nil || !eligible {
		t.Fatalf("well-formed table: eligible=%v err=%v", eligible, err)
	}
	want := []compiler.StaticRule{{Event: "process", Action: 1, Audit: true, Pattern: "ab"}}
	if !reflect.DeepEqual(rules, want) {
		t.Errorf("rules = %+v, want %+v", rules, want)
	}
}
