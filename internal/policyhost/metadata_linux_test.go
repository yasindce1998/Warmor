//go:build linux

package policyhost

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/policymeta"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestRealChildMetadataRequiresExplicitDigestTrust(t *testing.T) {
	fields := &[3]uint32{compiler.FieldBitPath, 0, compiler.FieldBitRemoteAddr | compiler.FieldBitRemotePort}
	module := wasmtest.ConstPolicy(0, fields) // absent abi_version: metadata must say 0
	s := supervisor(t, config(t))
	h := startHost(t, s, module)
	m := h.Metadata()
	if m.ModuleSHA256 != h.Digest() || m.ABIVersion != 0 || m.Encoding != policymeta.EncodingBinary || m.Events[0].FieldsRead != compiler.FieldBitPath || h.DecisionCacheEligible(0) {
		t.Fatalf("incorrect actual identity/ABI or unsafe cache: %+v", m)
	}
	h.Close()
	p := staged(t, wasmtest.AgeKnownPolicy(fields))
	c := config(t)
	c.TrustedDeclarationDigests = []string{p.Digest()}
	s = supervisor(t, c)
	// New must copy the admin configuration; changes cannot authorize modules.
	c.TrustedDeclarationDigests[0] = "modified"
	h, err := s.Start(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if h.Metadata().ABIVersion != 3 || !h.DecisionCacheEligible(0) {
		t.Fatal("trusted observed ABI lost")
	}
}

func TestCompiledMetadataEndToEnd(t *testing.T) {
	if !compiler.CargoAvailable() {
		if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
			t.Fatal("cargo/wasm32 required")
		}
		t.Skip("cargo/wasm32 unavailable")
	}
	policy, err := compiler.Parse([]byte(`name: declarations-e2e
version: 1
default_action: deny
rules:
- name: allow-tool
  event: process
  action: allow
  conditions: {all: [{path: {eq: /bin/tool}}]}
- name: ignored-later-duplicate
  event: process
  action: deny
  conditions: {all: [{path: {eq: /bin/tool}}]}
- name: audit-tool
  event: process
  action: deny
  mode: audit
  conditions: {all: [{path: {eq: /bin/audit}}]}
- name: log-tool
  event: process
  action: log
  conditions: {all: [{path: {eq: /bin/log}}]}
- name: endpoint
  event: network
  action: allow
  conditions: {all: [{remote_addr: {eq: "2001:db8::1"}}, {remote_port: {eq: 443}}]}
`))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "compiled.wasm")
	built, err := compiler.Build(policy, compiler.BuildOptions{OutputPath: out})
	defer compiler.Cleanup(built)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	p := staged(t, data)
	c := config(t)
	s := supervisor(t, c)
	untrusted, err := s.Start(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if untrusted.DecisionCacheEligible(0) || untrusted.StaticRulesProcess().Eligible {
		t.Fatal("compiler output signature implicitly authorized cache")
	}
	untrusted.Close()
	c.TrustedDeclarationDigests = []string{p.Digest()}
	s = supervisor(t, c)
	h, err := s.Start(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	m := h.Metadata()
	if m.ABIVersion != 3 || m.Encoding != policymeta.EncodingBinary || m.ModuleSHA256 != p.Digest() {
		t.Fatalf("actual compiled identity %+v", m)
	}
	if !h.DecisionCacheEligible(0) || !h.LinuxKernelCacheEligible(0) || !h.StaticRulesProcess().Eligible || !h.StaticRulesNetwork().Eligible {
		t.Fatalf("compiled metadata unusable: %+v", m)
	}
	want := []compiler.StaticRule{{Event: "process", Pattern: "/bin/tool", Action: 0}, {Event: "process", Pattern: "/bin/audit", Action: 1, Audit: true}, {Event: "process", Pattern: "/bin/log", Action: 0, Audit: true}}
	if !reflect.DeepEqual(h.StaticRulesProcess().Rules, want) {
		t.Fatalf("first-match/action/audit metadata lost: %+v", h.StaticRulesProcess())
	}
	if got := h.StaticRulesNetwork().Rules; len(got) != 1 || got[0].Pattern != "2001:db8::1" || got[0].Port != 443 {
		t.Fatalf("endpoint metadata %+v", got)
	}
	// Test-only parity: the production parent dependency check still excludes
	// wasm. Loading here verifies the common interface against legacy semantics.
	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	if err := rt.LoadPolicyBytes(ctx, data); err != nil {
		t.Fatal(err)
	}
	pool, err := wasm.NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close(ctx)
	legacy := wasm.NewPolicyEvaluator(pool, "")
	var sources = []policymeta.Source{h, legacy}
	if !reflect.DeepEqual(sources[0].Metadata(), sources[1].Metadata()) {
		t.Fatal("in-process metadata differs from supervised observation")
	}
	for _, event := range []*api.Event{{Filename: "/bin/tool"}, {Filename: "/bin/audit"}, {Filename: "/bin/log"}, {Filename: "/bin/unknown"}, {Type: api.EventTypeNetwork, Network: &api.NetworkEvent{RemoteAddr: "2001:db8::1", RemotePort: 443}}} {
		a, err := h.Evaluate(ctx, event)
		if err != nil {
			t.Fatal(err)
		}
		b, err := legacy.Evaluate(ctx, event)
		if err != nil {
			t.Fatal(err)
		}
		if a.Action != b.Action || a.Audit != b.Audit || a.Reason != b.Reason {
			t.Fatalf("evaluation semantics changed: child=%+v legacy=%+v", a, b)
		}
	}
}

func TestCompiledABI5UnknownInputsAndDeclinedStaticDomain(t *testing.T) {
	if !compiler.CargoAvailable() {
		if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
			t.Fatal("cargo/wasm32 required")
		}
		t.Skip("cargo/wasm32 unavailable")
	}
	policy, err := compiler.Parse([]byte(`name: metadata-unknown-inputs
version: 1
default_action: allow
rules:
- name: arguments
  event: process
  action: deny
  conditions: {all: [{args: {contains: --dangerous}}]}
`))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "abi5.wasm")
	built, err := compiler.Build(policy, compiler.BuildOptions{OutputPath: out})
	defer compiler.Cleanup(built)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	p := staged(t, data)
	c := config(t)
	c.TrustedDeclarationDigests = []string{p.Digest()}
	h, err := supervisor(t, c).Start(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if h.Metadata().ABIVersion != 5 || h.FieldsRead(0) != compiler.FieldBitArgs || h.LinuxKernelCacheEligible(0) || h.StaticRulesProcess().Eligible {
		t.Fatalf("ABI5 dependency metadata %+v", h.Metadata())
	}
	for _, arg := range []string{"--dangerous", "\xff"} {
		r, err := h.Evaluate(context.Background(), &api.Event{Process: &api.ProcessEvent{Args: []string{"tool", arg}}})
		if err != nil || r.Action != api.ActionDeny || r.Audit {
			t.Fatalf("unknown-input law changed: %+v %v", r, err)
		}
	}
}
