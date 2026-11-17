package enforcer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestReloadPolicy_ClearsKernelPolicyMap(t *testing.T) {
	isolateCacheDir(t)
	pm := &fakePolicyMap{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyMap: pm})

	// A decision the old policy compiled into the kernel map.
	_ = pm.SetRule(7, 0, "/bin/bash", 0, false)

	if err := e.ReloadPolicy(); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}
	if got := pm.clearCount(); got != 1 {
		t.Fatalf("policy map Clear calls = %d, want 1", got)
	}
	if rules := pm.snapshot(); len(rules) != 0 {
		t.Fatalf("stale kernel rules survived reload: %+v", rules)
	}
}

// The legacy reload path reuses one decision cache across evaluators. A
// verdict cached under the old policy must never be served after the userspace
// swap, even though the new policy would decide differently for the same event.
func TestReloadPolicy_DropsDecisionCacheFromOldPolicy(t *testing.T) {
	isolateCacheDir(t)
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyWasm: wasmtest.ConstPolicy(0, &[3]uint32{})})
	event := &api.Event{PID: 0, UID: 1000, Comm: "tool", Filename: "/bin/tool"}

	// Cache an allow decision made by the old policy.
	e.handleEvent(event)
	if n := e.cache.Stats().Size; n != 1 {
		t.Fatalf("cache size before reload = %d, want 1", n)
	}
	if _, hit := e.cache.Get(event); !hit {
		t.Fatal("old policy decision was not cached")
	}

	newPath := filepath.Join(t.TempDir(), "deny.wasm")
	if err := os.WriteFile(newPath, wasmtest.ConstPolicy(1, &[3]uint32{}), 0o600); err != nil {
		t.Fatal(err)
	}
	e.policyPath = newPath
	if err := e.ReloadPolicy(); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}
	if n := e.cache.Stats().Size; n != 0 {
		t.Fatalf("stale decisions survived reload: %d cached", n)
	}

	e.handleEvent(event)
	if got := e.GetStats(); got.Allowed != 1 || got.Denied != 1 {
		t.Fatalf("stats = %+v, want 1 allow (old policy) and 1 deny (new policy)", got)
	}
}

func TestReloadPolicy_FailedLoadKeepsKernelPolicyMap(t *testing.T) {
	isolateCacheDir(t)
	pm := &fakePolicyMap{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyMap: pm})
	_ = pm.SetRule(7, 0, "/bin/bash", 1, false)
	e.policyPath = filepath.Join(t.TempDir(), "missing.wasm")

	if err := e.ReloadPolicy(); err == nil {
		t.Fatal("ReloadPolicy with a missing policy must fail")
	}
	// The old policy is still active, so its kernel decisions stay valid.
	if got := pm.clearCount(); got != 0 {
		t.Fatalf("policy map cleared on failed reload (%d calls)", got)
	}
	if len(pm.snapshot()) != 1 {
		t.Fatal("kernel rules must survive a failed reload")
	}
}

func TestReloadPolicy_ClearErrorIsReturned(t *testing.T) {
	isolateCacheDir(t)
	pm := &fakePolicyMap{clearErr: errors.New("EPERM")}
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyMap: pm})
	oldEval := e.evaluator

	err := e.ReloadPolicy()
	if err == nil || !strings.Contains(err.Error(), "EPERM") {
		t.Fatalf("ReloadPolicy error = %v, want the Clear failure", err)
	}
	// A prepared module alone is not successful activation.
	if e.evaluator != oldEval {
		t.Error("evaluator swapped despite failed kernel preparation")
	}
}

func TestSyncToPolicyMap_DropsDecisionFromReplacedPolicy(t *testing.T) {
	pm := &fakePolicyMap{}
	e := &Enforcer{policyMap: pm}
	gen := e.policyGen.Load()
	e.policyGen.Add(1) // a reload happened while the evaluation was in flight

	_ = e.syncToPolicyMap(&api.Event{Filename: "/bin/sh"}, &api.ActionResult{Action: api.ActionAllow}, gen, 0)
	if rules := pm.snapshot(); len(rules) != 0 {
		t.Fatalf("stale-generation decision written to kernel map: %+v", rules)
	}
	_ = e.syncToPolicyMap(&api.Event{Filename: "/bin/sh"}, &api.ActionResult{Action: api.ActionAllow}, e.policyGen.Load(), 0)
	if len(pm.snapshot()) != 1 {
		t.Fatal("current-generation decision not written")
	}
}

func TestNew_HonoursLogLevel(t *testing.T) {
	isolateCacheDir(t)
	for _, tc := range []struct{ in, want string }{
		{"", "info"},
		{"debug", "debug"},
		{"error", "error"},
	} {
		stubPlatform(t, &fakePlatform{}, nil)
		e, err := New(context.Background(), testPolicyPath, &Options{MetricsPort: -1, LogLevel: tc.in})
		if err != nil {
			t.Fatalf("New(LogLevel=%q): %v", tc.in, err)
		}
		got := e.logger.Level()
		e.Close()
		if got != tc.want {
			t.Errorf("LogLevel %q: logger level = %q, want %q", tc.in, got, tc.want)
		}
	}

	stubPlatform(t, &fakePlatform{}, nil)
	if _, err := New(context.Background(), testPolicyPath, &Options{MetricsPort: -1, LogLevel: "loud"}); err == nil {
		t.Error("an unknown log level must be rejected")
	}
}
