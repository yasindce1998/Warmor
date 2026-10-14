package enforcer

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

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
	// The new policy is still swapped in: userspace must not keep the old one.
	if e.evaluator == oldEval {
		t.Error("evaluator not swapped despite successful load")
	}
}

func TestSyncToPolicyMap_DropsDecisionFromReplacedPolicy(t *testing.T) {
	pm := &fakePolicyMap{}
	e := &Enforcer{policyMap: pm}
	gen := e.policyGen.Load()
	e.policyGen.Add(1) // a reload happened while the evaluation was in flight

	e.syncToPolicyMap(&api.Event{Filename: "/bin/sh"}, &api.ActionResult{Action: api.ActionAllow}, gen)
	if rules := pm.snapshot(); len(rules) != 0 {
		t.Fatalf("stale-generation decision written to kernel map: %+v", rules)
	}
	e.syncToPolicyMap(&api.Event{Filename: "/bin/sh"}, &api.ActionResult{Action: api.ActionAllow}, e.policyGen.Load())
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
