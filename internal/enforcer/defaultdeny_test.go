package enforcer

import (
	"errors"
	"reflect"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/ebpf"
	"github.com/yasindce1998/warmor/internal/wasm"
)

// errDDTest is returned by the fake policy map's failing paths.
var errDDTest = errors.New("fake map failure")

// fakeStaticSource fakes the evaluator's kernel default-deny declaration.
type fakeStaticSource struct {
	proc wasm.StaticDomain
	net  wasm.StaticDomain
}

func (f fakeStaticSource) StaticRulesProcess() wasm.StaticDomain { return f.proc }
func (f fakeStaticSource) StaticRulesNetwork() wasm.StaticDomain { return f.net }

// ddEnforcer builds a minimal enforcer around a fake policy map for
// applyDefaultDeny tests.
func ddEnforcer(t *testing.T, pm PolicyMapSyncer, audit, learning bool) *Enforcer {
	t.Helper()
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyMap: pm, audit: audit, learning: learning})
	e.defaultDeny = true
	return e
}

func TestApplyDefaultDeny_MarksEligibleDomainsInOrder(t *testing.T) {
	pm := &fakeEndpointPolicyMap{}
	e := ddEnforcer(t, pm, false, false)

	e.applyDefaultDeny(fakeStaticSource{
		proc: wasm.StaticDomain{
			Eligible: true,
			Rules: []compiler.StaticRule{
				{Event: "process", Action: 0, Pattern: "/bin/sh"},
				{Event: "process", Action: 1, Audit: true, Pattern: "/tmp/x"},
			},
		},
		net: wasm.StaticDomain{Eligible: true, Rules: []compiler.StaticRule{
			{Event: "network", Action: 0, Pattern: "10.0.0.1", Port: 53},
		}},
	})

	// The marking goes in last, after the entries it covers.
	wantLog := []string{
		"clear-dd",
		"rule:/bin/sh",
		"rule:/tmp/x",
		"mark:0:1", // exec, deny mode
		"endpoint:10.0.0.1:53",
		"mark:2:1", // connect, deny mode
	}
	if got := pm.eventLog(); !reflect.DeepEqual(got, wantLog) {
		t.Errorf("event log = %v, want %v", got, wantLog)
	}

	rules := pm.snapshot()
	wantRules := []policyRule{
		{0, ebpf.EventTypeExec, "/bin/sh", 0, false},
		{0, ebpf.EventTypeExec, "/tmp/x", 1, true},
	}
	if !reflect.DeepEqual(rules, wantRules) {
		t.Errorf("rules = %+v, want %+v", rules, wantRules)
	}
	wantEndpoints := []endpointRule{{0, ebpf.EventTypeNetwork, "10.0.0.1", 53, 0, false}}
	if !reflect.DeepEqual(pm.endpoints, wantEndpoints) {
		t.Errorf("endpoints = %+v, want %+v", pm.endpoints, wantEndpoints)
	}
}

func TestApplyDefaultDeny_IneligibleDomainNotMarked(t *testing.T) {
	pm := &fakeEndpointPolicyMap{}
	e := ddEnforcer(t, pm, false, false)

	e.applyDefaultDeny(fakeStaticSource{
		proc: wasm.StaticDomain{Eligible: false}, // e.g. a glob rule
		net:  wasm.StaticDomain{Eligible: true, Rules: []compiler.StaticRule{{Event: "network", Action: 0, Pattern: "10.0.0.1", Port: 53}}},
	})

	if got := pm.eventLog(); !reflect.DeepEqual(got, []string{"clear-dd", "endpoint:10.0.0.1:53", "mark:2:1"}) {
		t.Errorf("event log = %v, want only the network domain", got)
	}
	if len(pm.snapshot()) != 0 {
		t.Errorf("rules = %+v, want none (the network rule is endpoint-keyed)", pm.snapshot())
	}
	if len(pm.endpoints) != 1 {
		t.Errorf("endpoints = %+v, want the network rule", pm.endpoints)
	}
}

func TestApplyDefaultDeny_AuditModeMarksAudit(t *testing.T) {
	pm := &fakePolicyMap{}
	e := ddEnforcer(t, pm, true, false)

	e.applyDefaultDeny(fakeStaticSource{
		proc: wasm.StaticDomain{Eligible: true, Rules: []compiler.StaticRule{{Event: "process", Action: 0, Pattern: "/bin/sh"}}},
	})

	want := []ddMark{{ebpf.EventTypeExec, ebpf.DefaultDenyModeAudit}}
	if !reflect.DeepEqual(pm.ddMarks, want) {
		t.Errorf("marks = %v, want %v", pm.ddMarks, want)
	}
}

func TestApplyDefaultDeny_LearningModeNeverMarks(t *testing.T) {
	pm := &fakePolicyMap{}
	e := ddEnforcer(t, pm, false, true)

	e.applyDefaultDeny(fakeStaticSource{
		proc: wasm.StaticDomain{Eligible: true, Rules: []compiler.StaticRule{{Event: "process", Action: 0, Pattern: "/bin/sh"}}},
	})

	if len(pm.ddMarks) != 0 {
		t.Errorf("marks = %v, want none in learning mode", pm.ddMarks)
	}
	if pm.ddClears != 1 {
		t.Errorf("ddClears = %d, want 1 (marking cleared)", pm.ddClears)
	}
}

func TestApplyDefaultDeny_DisabledOnlyClears(t *testing.T) {
	pm := &fakePolicyMap{}
	e := ddEnforcer(t, pm, false, false)
	e.defaultDeny = false

	e.applyDefaultDeny(fakeStaticSource{
		proc: wasm.StaticDomain{Eligible: true, Rules: []compiler.StaticRule{{Event: "process", Action: 0, Pattern: "/bin/sh"}}},
	})

	if len(pm.ddMarks) != 0 || len(pm.snapshot()) != 0 {
		t.Errorf("marks=%v rules=%v, want none with default-deny off", pm.ddMarks, pm.snapshot())
	}
	if pm.ddClears != 1 {
		t.Errorf("ddClears = %d, want 1 (stale marking cleared)", pm.ddClears)
	}
}

func TestApplyDefaultDeny_PreloadErrorLeavesDomainUnmarked(t *testing.T) {
	// setErr fails SetRule (the exec path) but not the endpoint syncer, so
	// exec stays unmarked while connect still marks.
	pm := &fakeEndpointPolicyMap{}
	pm.setErr = errDDTest
	e := ddEnforcer(t, pm, false, false)

	e.applyDefaultDeny(fakeStaticSource{
		proc: wasm.StaticDomain{Eligible: true, Rules: []compiler.StaticRule{{Event: "process", Action: 0, Pattern: "/bin/sh"}}},
		net:  wasm.StaticDomain{Eligible: true, Rules: []compiler.StaticRule{{Event: "network", Action: 0, Pattern: "10.0.0.1", Port: 53}}},
	})

	if len(pm.ddMarks) != 1 || pm.ddMarks[0].eventType != ebpf.EventTypeNetwork {
		t.Errorf("marks = %v, want only connect", pm.ddMarks)
	}
}

func TestApplyDefaultDeny_MarkErrorIsSurfacedNotFatal(t *testing.T) {
	pm := &fakePolicyMap{ddMarkErr: errDDTest}
	e := ddEnforcer(t, pm, false, false)

	e.applyDefaultDeny(fakeStaticSource{
		proc: wasm.StaticDomain{Eligible: true, Rules: []compiler.StaticRule{{Event: "process", Action: 0, Pattern: "/bin/sh"}}},
	})

	if len(pm.snapshot()) != 1 {
		t.Errorf("rules = %+v, want the preloaded entry despite the mark error", pm.snapshot())
	}
}

func TestApplyDefaultDeny_MapWithoutSupportIsSkipped(t *testing.T) {
	// A policy map that implements neither default-deny method (e.g. a
	// platform without the kernel map): nothing to clear or mark, no crash.
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyMap: plainPolicyMap{}})
	e.defaultDeny = true
	e.applyDefaultDeny(fakeStaticSource{
		proc: wasm.StaticDomain{Eligible: true, Rules: []compiler.StaticRule{{Event: "process", Action: 0, Pattern: "/bin/sh"}}},
	})
}

// plainPolicyMap implements only PolicyMapSyncer.
type plainPolicyMap struct{}

func (plainPolicyMap) SetRule(uint64, uint8, string, uint8, bool) error { return nil }
func (plainPolicyMap) Clear() error                                     { return nil }
