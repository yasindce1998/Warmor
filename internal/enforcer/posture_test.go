package enforcer

import (
	"context"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestAuditOverridesKernelEnforcement(t *testing.T) {
	for _, learning := range []bool{false, true} {
		t.Run(map[bool]string{false: "audit", true: "learning"}[learning], func(t *testing.T) {
			isolateCacheDir(t)
			cfg := stubPlatform(t, &fakePlatform{}, nil)
			opts := &Options{AuditMode: !learning, LearningMode: learning, LSMEnforce: true, RequireLSM: true, IntegrityMode: "enforce", MetricsPort: -1}
			e, err := New(context.Background(), testPolicyPath, opts)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if cfg.LSMEnforce || cfg.IntegrityMode != "audit" || !cfg.RequireLSM || !cfg.AuditMode {
				t.Fatalf("effective platform posture = %+v, want kernel audit with required LSM", *cfg)
			}
			if !opts.LSMEnforce || opts.IntegrityMode != "enforce" {
				t.Fatal("New mutated caller options")
			}
		})
	}
}

func TestInvalidVerdictFailsClosedWithoutPersistence(t *testing.T) {
	pm := &fakePolicyMap{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyMap: pm, policyWasm: wasmtest.ConstPolicy(99, &[3]uint32{})})
	// PID zero avoids real process actions; error-derived denials must not
	// persist even when the policy declares a constant, kernel-syncable rule.
	for i := 0; i < 2; i++ {
		e.handleEvent(&api.Event{Filename: "/bin/tool"})
	}
	if e.GetStats().Denied != 2 || e.cache.Stats().Size != 0 || len(pm.snapshot()) != 0 {
		t.Fatalf("invalid verdict persisted or allowed: stats=%+v cache=%+v map=%+v", e.GetStats(), e.cache.Stats(), pm.snapshot())
	}
}

func TestPreloadStaticRuleHonorsGlobalAudit(t *testing.T) {
	pm := &fakeEndpointPolicyMap{}
	e := ddEnforcer(t, pm, true, false)
	e.applyDefaultDeny(fakeStaticSource{
		proc: wasm.StaticDomain{Eligible: true, Rules: []compiler.StaticRule{{Event: "process", Pattern: "/bin/tool", Action: 1}}},
		net:  wasm.StaticDomain{Eligible: true, Rules: []compiler.StaticRule{{Event: "network", Pattern: "127.0.0.1", Port: 443, Action: 1}}},
	})
	if len(pm.snapshot()) != 1 || len(pm.endpoints) != 1 {
		t.Fatal("expected both static deny rules to preload")
	}
	for _, rule := range pm.snapshot() {
		if !rule.audit {
			t.Fatalf("audit preload produced enforceable rule: %+v", rule)
		}
	}
	if !pm.endpoints[0].audit {
		t.Fatal("audit network preload produced enforceable rule")
	}
}
