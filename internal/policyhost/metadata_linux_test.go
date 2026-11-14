//go:build linux

package policyhost

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/policybuild"
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

func TestChildBuildMetadataSharedSignedFormat(t *testing.T) {
	// The same compiler label can be appended to any guest. Matching signed
	// declarations is necessary, but must not authorize dependency trust.
	build := policybuild.Metadata{Compiler: "warmor-yaml/6", DefaultAction: "deny"}
	data, err := policybuild.Append(wasmtest.AgeKnownPolicy(nil), build)
	if err != nil {
		t.Fatal(err)
	}
	p := staged(t, data)
	h, err := supervisor(t, config(t)).Start(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	m := h.Metadata()
	if m.Build == nil || *m.Build != build || m.MatchArtifact(p.Digest(), 3, build.Compiler, "deny") != nil {
		t.Fatalf("shared build declaration not observed %+v", m)
	}
	if h.DecisionCacheEligible(0) || h.StaticRulesProcess().Eligible {
		t.Fatal("compiler display label enabled optimization")
	}
	duplicate := append(append([]byte(nil), data...), data[len(wasmtest.AgeKnownPolicy(nil)):]...)
	s := supervisor(t, config(t))
	if got, err := s.Start(context.Background(), staged(t, duplicate)); got != nil || err == nil || len(s.slots) != 0 {
		t.Fatal("duplicate build section reached ready")
	}
}

func metadataI32(v int32) []byte {
	b := []byte{0x41}
	for {
		x := byte(v & 127)
		v >>= 7
		if v == 0 && x&64 == 0 || v == -1 && x&64 != 0 {
			return append(b, x)
		}
		b = append(b, x|128)
	}
}

// Real binary guest fixture, not a fake host: only the process table is
// declared. Its data segment starts at the region returned by static malloc.
func declarationGuest(table []byte, fields uint32, abi int32) []byte {
	m := []byte{0, 97, 115, 109, 1, 0, 0, 0}
	m = append(m, section(1, []byte{3, 0x60, 1, 0x7f, 1, 0x7f, 0x60, 0, 1, 0x7f, 0x60, 3, 0x7f, 0x7f, 0x7f, 1, 0x7f})...)
	m = append(m, section(3, []byte{5, 0, 0, 1, 0, 2})...)
	m = append(m, section(5, []byte{1, 0, 2})...)
	exports := []byte{6}
	for _, entry := range []struct {
		name        string
		kind, index byte
	}{{"memory", 2, 0}, {"malloc", 0, 0}, {"evaluate_event", 0, 1}, {"abi_version", 0, 2}, {"warmor_fields_read", 0, 3}, {"warmor_static_rules", 0, 4}} {
		exports = append(exports, wasmName(entry.name)...)
		exports = append(exports, entry.kind, entry.index)
	}
	m = append(m, section(7, exports)...)
	malloc := append(metadataI32(1024), metadataI32(4096)...)
	malloc = append(malloc, 0x20, 0)
	malloc = append(malloc, metadataI32(256)...)
	malloc = append(malloc, 0x46, 0x1b) // select ptr by size==256
	static := append(metadataI32(int32(len(table))), metadataI32(0)...)
	static = append(static, 0x20, 0, 0x45, 0x1b)
	code := []byte{5}
	for _, instructions := range [][]byte{malloc, metadataI32(0), metadataI32(abi), metadataI32(int32(fields)), static} {
		body := append([]byte{0}, instructions...)
		body = append(body, 0x0b)
		code = append(code, uleb(uint32(len(body)))...)
		code = append(code, body...)
	}
	m = append(m, section(10, code)...)
	data := append([]byte{1, 0}, metadataI32(4096)...)
	data = append(data, 0x0b)
	data = append(data, uleb(uint32(len(table)))...)
	data = append(data, table...)
	return append(m, section(11, data)...)
}

func staticEntry(pattern string, port uint16, action, audit byte) []byte {
	b := []byte{action, audit, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(b[2:4], port)
	binary.LittleEndian.PutUint16(b[4:6], uint16(len(pattern)))
	return append(b, []byte(pattern)...)
}

func TestRealWorkerMalformedDeclarationsStayIneligible(t *testing.T) {
	entry := staticEntry("/bin/tool", 0, 0, 0)
	tooMany := []byte{1}
	for range policymeta.MaxStaticRules + 1 {
		tooMany = append(tooMany, entry...)
	}
	for name, table := range map[string][]byte{
		"missing":             nil,
		"bad eligibility":     {2},
		"ineligible trailing": {0, 1},
		"long pattern":        append([]byte{1}, staticEntry(strings.Repeat("a", 255), 0, 0, 0)...),
		"bad action":          append([]byte{1}, staticEntry("/bin/tool", 0, 2, 0)...),
		"bad audit":           append([]byte{1}, staticEntry("/bin/tool", 0, 0, 2)...),
		"process port":        append([]byte{1}, staticEntry("/bin/tool", 443, 0, 0)...),
		"duplicate":           append(append([]byte{1}, entry...), entry...),
		"excess count":        tooMany,
	} {
		t.Run(name, func(t *testing.T) {
			p := staged(t, declarationGuest(table, compiler.FieldBitPath, 5))
			c := config(t)
			c.TrustedDeclarationDigests = []string{p.Digest()}
			h, err := supervisor(t, c).Start(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			if h.Metadata().Domains[0].Eligible || h.StaticRulesProcess().Eligible {
				t.Fatal("malformed guest promoted even with explicit trust")
			}
			if r, err := h.Evaluate(context.Background(), &api.Event{}); err != nil || r.Action != api.ActionAllow {
				t.Fatalf("optional declaration broke evaluation: %+v %v", r, err)
			}
		})
	}
	p := staged(t, declarationGuest(append([]byte{1}, entry...), 1<<30, 5))
	c := config(t)
	c.TrustedDeclarationDigests = []string{p.Digest()}
	h, err := supervisor(t, c).Start(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if h.FieldsRead(0) != compiler.FieldsUnknown || h.DecisionCacheEligible(0) || h.StaticRulesProcess().Eligible {
		t.Fatal("future finite fields optimized")
	}
	s := supervisor(t, config(t))
	if h, err := s.Start(context.Background(), staged(t, declarationGuest(nil, 0, 6))); err == nil || h != nil || len(s.slots) != 0 {
		t.Fatal("unsupported actual ABI produced a host or leaked capacity")
	}
}

func TestCompiledStaticEndpointBoundaries(t *testing.T) {
	if !compiler.CargoAvailable() {
		if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
			t.Fatal("cargo/wasm32 required")
		}
		t.Skip("cargo/wasm32 unavailable")
	}
	for _, tc := range []struct {
		name, path, addr string
		process, network bool
	}{
		{"exact binary bounds", "/" + strings.Repeat("x", 126), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, true},
		{"binary full field", "/" + strings.Repeat("x", 127), "2001:db8::1", false, true},
		{"kernel bound exceeds binary ABI", "/" + strings.Repeat("x", 253), "2001:db8::1", false, true},
		{"overlong and alias", "/" + strings.Repeat("x", 254), "2001:0db8:0:0:0:0:0:1", false, false},
		{"mapped address", "/bin/tool", "::ffff:127.0.0.1", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := compiler.Parse([]byte(fmt.Sprintf(`name: endpoint-bounds
version: 1
default_action: deny
rules:
- name: exact-path
  event: process
  action: allow
  conditions: {all: [{path: {eq: %q}}]}
- name: zero-port
  event: network
  action: log
  conditions: {all: [{remote_addr: {eq: "0.0.0.0"}}, {remote_port: {eq: 0}}]}
- name: maximum-port
  event: network
  action: deny
  mode: audit
  conditions: {all: [{remote_addr: {eq: %q}}, {remote_port: {eq: 65535}}]}
`, tc.path, tc.addr)))
			if err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "bounds.wasm")
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
			if h.StaticRulesProcess().Eligible != tc.process || h.StaticRulesNetwork().Eligible != tc.network {
				t.Fatalf("endpoint domain eligibility %+v", h.Metadata())
			}
			if tc.network {
				rules := h.StaticRulesNetwork().Rules
				if len(rules) != 2 || rules[0].Port != 0 || rules[0].Action != 0 || !rules[0].Audit || rules[1].Port != 65535 || rules[1].Action != 1 || !rules[1].Audit {
					t.Fatalf("finite endpoints/modes changed %+v", rules)
				}
			}
			pathAction := api.ActionAllow
			if len(tc.path) > 128 {
				pathAction = api.ActionDeny
			}
			for _, test := range []struct {
				event  *api.Event
				action api.Action
				audit  bool
			}{
				{&api.Event{Filename: tc.path}, pathAction, false},
				{&api.Event{Type: api.EventTypeNetwork, Network: &api.NetworkEvent{RemoteAddr: "0.0.0.0", RemotePort: 0}}, api.ActionLog, false},
				{&api.Event{Type: api.EventTypeNetwork, Network: &api.NetworkEvent{RemoteAddr: tc.addr, RemotePort: 65535}}, api.ActionDeny, true},
			} {
				r, err := h.Evaluate(context.Background(), test.event)
				if err != nil || r.Action != test.action || r.Audit != test.audit {
					t.Fatalf("bound evaluation %+v %v", r, err)
				}
			}
			if len(tc.path) == 128 {
				// The current binary guest also allows this longer truncation
				// alias, proving why its static table is not exact/complete.
				r, err := h.Evaluate(context.Background(), &api.Event{Filename: tc.path + "suffix"})
				if err != nil || r.Action != api.ActionAllow || h.StaticRulesProcess().Eligible {
					t.Fatalf("binary alias was promoted %+v %v", r, err)
				}
			}
		})
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
	// Model the signed build writer's pre-signing step with the shared codec.
	// Production compiler integration remains owned by the signed agent.
	data, err = policybuild.Append(data, policybuild.Metadata{Compiler: "test-compiler@sha256:reviewed-build", DefaultAction: "deny"})
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
	if err := m.MatchArtifact(p.Digest(), 3, "test-compiler@sha256:reviewed-build", "deny"); err != nil {
		t.Fatal("compiled signed build comparison failed", err)
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
