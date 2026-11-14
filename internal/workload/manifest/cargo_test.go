package manifest

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	"github.com/tetratelabs/wazero"
	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/kernelmap"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

func compileSelection(t *testing.T, b *Bundle, s Selection) *wasm.PolicyEvaluator {
	t.Helper()
	g, err := b.Compose(s)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "composed.wasm")
	result, err := g.Build(compiler.BuildOptions{OutputPath: path})
	defer compiler.Cleanup(result)
	if err != nil {
		t.Fatal(err)
	}
	// Check the actual generated ABI export, not just metadata.
	if !strings.Contains(result.RustSource, "fn abi_version() -> u32 {\n    "+strconv.Itoa(int(g.ABI()))) {
		t.Fatal("compiled ABI mismatch")
	}
	// Independently inspect the actual WASM export value as well. This runtime
	// never evaluates events; production ABI/entrypoint validation follows below.
	ctx := context.Background()
	probe := wazero.NewRuntime(ctx)
	defer probe.Close(ctx)
	_, err = probe.NewHostModuleBuilder("env").NewFunctionBuilder().
		WithFunc(func(uint32) uint32 { return 0 }).Export("get_field_u32").
		NewFunctionBuilder().WithFunc(func(uint32, uint32, uint32) uint32 { return 0 }).Export("get_field_str").Instantiate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wasmBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	module, err := probe.Instantiate(ctx, wasmBytes)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := module.ExportedFunction("abi_version").Call(ctx)
	if err != nil || len(actual) != 1 || uint32(actual[0]) != g.ABI() {
		t.Fatal("actual module ABI mismatch", actual, err)
	}
	rt, err := wasm.NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close(ctx) })
	if err := rt.LoadPolicy(ctx, path); err != nil {
		t.Fatal(err)
	}
	pool, err := wasm.NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close(ctx) })
	ev := wasm.NewPolicyEvaluator(pool, "node")
	ev.SetTimeout(5 * time.Second)
	return ev
}

// Compiler upgrades must preserve composition semantics while tightening the
// exported kernel fast-path boundary. Inspect real compiled declarations rather
// than treating a supported-version constant as compatibility evidence.
func TestCargoCompilerSevenExactStaticIdentityContract(t *testing.T) {
	requireCargo(t)
	for _, tc := range []struct {
		name, event, path, address string
		eligible                   bool
	}{
		{
			name: "complete path", event: "process", eligible: true,
			path: "/" + strings.Repeat("x", kernelmap.MaxPolicyPathBytes-1),
		},
		{
			name: "overlong path", event: "process", eligible: false,
			path: "/" + strings.Repeat("x", kernelmap.MaxPolicyPathBytes),
		},
		{
			name: "canonical IPv6", event: "network", eligible: true,
			address: "2001:db8::1",
		},
		{
			name: "noncanonical IPv6", event: "network", eligible: false,
			address: "2001:0db8::1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conditions := "[{path: " + strconv.Quote(tc.path) + "}]"
			if tc.event == "network" {
				conditions = "[{remote_addr: " + strconv.Quote(tc.address) + "}, {remote_port: 443}]"
			}
			raw := "name: static-baseline\nversion: 1\nrules:\n" +
				"  - name: exact-allow\n    event: " + tc.event +
				"\n    conditions: {all: " + conditions + "}\n    action: allow\ndefault_action: deny\n"
			doc, _ := fixture()
			base := source("system", "static-baseline", raw)
			doc.Baseline = &base
			doc.Additions = nil
			m := mustManifest(t, doc)
			b := mustBundle(t, m, map[digest.Digest][]byte{base.Artifact.Digest: []byte(raw)})
			ev := compileSelection(t, b, selectPod(t, m, "alpha"))
			declaration := ev.StaticRulesProcess()
			if tc.event == "network" {
				declaration = ev.StaticRulesNetwork()
			}
			if declaration.Eligible != tc.eligible {
				t.Fatalf("static eligibility = %v, want %v", declaration.Eligible, tc.eligible)
			}
			if tc.eligible && len(declaration.Rules) != 1 {
				t.Fatalf("static rules = %d, want exactly one", len(declaration.Rules))
			}
			if !tc.eligible && len(declaration.Rules) != 0 {
				t.Fatalf("ineligible identity exported %d kernel rules", len(declaration.Rules))
			}
			if !tc.eligible {
				return
			}
			event := &api.Event{Process: &api.ProcessEvent{Filename: tc.path}}
			event.SetType(api.EventTypeProcess)
			if tc.event == "network" {
				event.Process = nil
				event.Network = &api.NetworkEvent{RemoteAddr: tc.address, RemotePort: 443}
				event.SetType(api.EventTypeNetwork)
			}
			got, err := ev.Evaluate(context.Background(), event)
			if err != nil || got.Action != api.ActionAllow {
				t.Fatalf("exact identity decision = %+v, error %v; want allow", got, err)
			}
		})
	}
}

func TestCargoDefaultDenyBaselineWithRestrictiveAddition(t *testing.T) {
	requireCargo(t)
	doc, _ := fixture()
	doc.Additions = doc.Additions[:1]
	base := yamlPolicy("allow", "baseline-allow", "deny")
	addition := yamlPolicy("deny", "baseline-allow", "allow")
	*doc.Baseline = source("system", "baseline", base)
	doc.Additions[0].Source = source("alpha", "restrict", addition)
	a := map[digest.Digest][]byte{digest.FromString(base): []byte(base), digest.FromString(addition): []byte(addition)}
	m := mustManifest(t, doc)
	b := mustBundle(t, m, a)
	for _, ns := range []string{"alpha", "other"} {
		ev := compileSelection(t, b, selectPod(t, m, ns))
		for _, comm := range []string{"baseline-allow", "unmatched"} {
			want := api.ActionDeny
			if ns == "other" && comm == "baseline-allow" {
				want = api.ActionAllow
			}
			event := &api.Event{Comm: comm, Process: &api.ProcessEvent{Filename: "/bin/test"}}
			event.SetType(api.EventTypeProcess)
			got, err := ev.Evaluate(context.Background(), event)
			if err != nil {
				t.Fatal(err)
			}
			if got.Action != want {
				t.Fatalf("%s/%s: got %v want %v", ns, comm, got.Action, want)
			}
		}
	}
}

func requireCargo(t *testing.T) {
	t.Helper()
	if testing.Short() || !compiler.CargoAvailable() {
		if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
			t.Fatal("cargo and wasm32 target required")
		}
		t.Skip("cargo and wasm32 target required")
	}
}

func TestCargoOpposingNamespacesBaselineAndHostIsolation(t *testing.T) {
	requireCargo(t)
	doc, a := fixture()
	// The beta addition attempts to allow an explicit baseline deny. All three
	// sources deliberately reuse the same display/rule/variable names.
	raw := `name: same-name
version: 1
variables: {target: baseline-block}
rules:
  - name: same-rule
    event: process
    conditions: {all: [{comm: "$target"}]}
    action: allow
  - name: opposing
    event: process
    conditions: {all: [{comm: alpha-block}]}
    action: allow
default_action: allow
`
	delete(a, doc.Additions[1].Source.Artifact.Digest)
	doc.Additions[1].Source = source("beta", "same-uid", raw)
	a[digest.FromString(raw)] = []byte(raw)
	// Explicit unknown and known-host policies are separate from the workload
	// baseline AND namespace additions. No implicit "failed lookup => host".
	for i, h := range []*ScopeHandling{&doc.Unknown, &doc.KnownHost} {
		x := yamlPolicy("deny", []string{"unknown-block", "host-block"}[i], "allow")
		s := source("system", []string{"unknown", "host"}[i], x)
		*h = ScopeHandling{Mode: "baseline", Baseline: &s}
		a[s.Artifact.Digest] = []byte(x)
	}
	m := mustManifest(t, doc)
	b := mustBundle(t, m, a)
	u, _ := m.SelectUnknown()
	h, _ := m.SelectKnownHost()
	selections := map[string]Selection{"alpha": selectPod(t, m, "alpha"), "beta": selectPod(t, m, "beta"), "no-match": selectPod(t, m, "other"), "unknown": u, "host": h}
	for name, s := range selections {
		t.Run(name, func(t *testing.T) {
			ev := compileSelection(t, b, s)
			for _, comm := range []string{"baseline-block", "alpha-block", "host-block", "unknown-block", "unmatched"} {
				want := api.ActionAllow
				if (name == "alpha" || name == "beta" || name == "no-match") && comm == "baseline-block" || name == "alpha" && comm == "alpha-block" || name == "host" && comm == "host-block" || name == "unknown" && comm == "unknown-block" {
					want = api.ActionDeny
				}
				event := &api.Event{Comm: comm, Process: &api.ProcessEvent{Filename: "/bin/test"}}
				event.SetType(api.EventTypeProcess)
				got, err := ev.Evaluate(context.Background(), event)
				if err != nil {
					t.Fatal(err)
				}
				if got.Action != want || got.Audit {
					t.Errorf("%s: got %+v, want action %v", comm, got, want)
				}
			}
		})
	}
}

func TestCargoAuditTemporalAndExactABI(t *testing.T) {
	requireCargo(t)
	doc, a := fixture()
	// An early audit denial MUST NOT mask a later enforcing baseline denial.
	// A second audit rule uses the argv callback (ABI 5) and a temporal window.
	raw := `name: audit
version: 1
rules:
  - name: overlapping-audit
    event: process
    conditions: {all: [{comm: baseline-block}]}
    action: deny
    mode: audit
  - name: argv-audit
    event: process
    conditions: {all: [{args: {contains: secret}}]}
    action: deny
    mode: audit
    reason: audit-preserved
    temporal: {max_container_age: 1m}
default_action: allow
`
	for _, x := range doc.Additions {
		delete(a, x.Source.Artifact.Digest)
	}
	s := source("alpha", "audit", raw)
	s.ABI = 5
	doc.Additions = []Addition{{Source: s}}
	a[s.Artifact.Digest] = []byte(raw)
	m := mustManifest(t, doc)
	b := mustBundle(t, m, a)
	selected := selectPod(t, m, "alpha")
	g, err := b.Compose(selected)
	if err != nil || g.ABI() != 5 {
		t.Fatal("exact ABI", err)
	}
	if g.Policy().Rules[2].Temporal == nil {
		t.Fatal("temporal dropped")
	}
	ev := compileSelection(t, b, selected)
	for _, tc := range []struct {
		comm, args string
		age        time.Duration
		action     api.Action
		audit      bool
	}{
		{"baseline-block", "secret", 2 * time.Minute, api.ActionDeny, false},
		{"other", "secret", 2 * time.Minute, api.ActionDeny, true},
		{"other", "secret", 30 * time.Second, api.ActionAllow, false},
		{"other", "ordinary", 2 * time.Minute, api.ActionAllow, false},
	} {
		now := time.Now()
		event := &api.Event{Comm: tc.comm, Timestamp: now, ContainerStart: now.Add(-tc.age), Process: &api.ProcessEvent{Filename: "/bin/test", Args: []string{tc.args}}}
		event.SetType(api.EventTypeProcess)
		got, err := ev.Evaluate(context.Background(), event)
		if err != nil {
			t.Fatal(err)
		}
		if got.Action != tc.action || got.Audit != tc.audit {
			t.Errorf("%+v: got %+v", tc, got)
		}
		if tc.audit && got.Reason != "audit-preserved" {
			t.Fatal("audit reason lost", got.Reason)
		}
	}
}
