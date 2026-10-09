package policydiff

import (
	"testing"

	"github.com/yasindce1998/warmor/internal/policymerge"
)

func TestDiffNoOverlap(t *testing.T) {
	a := &policymerge.PolicyYAML{
		Name: "a", Version: 1, DefaultAction: "deny",
		Rules: []policymerge.RuleYAML{{
			Name: "r1", Event: "process", Action: "allow",
			Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"path": map[string]any{"eq": "/bin/a"}}}},
		}},
	}
	b := &policymerge.PolicyYAML{
		Name: "b", Version: 1, DefaultAction: "deny",
		Rules: []policymerge.RuleYAML{{
			Name: "r2", Event: "file", Action: "allow",
			Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"path": map[string]any{"eq": "/etc/b"}}}},
		}},
	}

	result := Diff(a, b)
	if len(result.OnlyA) != 1 {
		t.Errorf("OnlyA = %d, want 1", len(result.OnlyA))
	}
	if len(result.OnlyB) != 1 {
		t.Errorf("OnlyB = %d, want 1", len(result.OnlyB))
	}
	if len(result.Both) != 0 {
		t.Errorf("Both = %d, want 0", len(result.Both))
	}
}

func TestDiffFullOverlap(t *testing.T) {
	rule := policymerge.RuleYAML{
		Name: "shared", Event: "process", Action: "allow",
		Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"path": map[string]any{"eq": "/bin/x"}}}},
	}
	a := &policymerge.PolicyYAML{Name: "a", Version: 1, DefaultAction: "deny", Rules: []policymerge.RuleYAML{rule}}
	b := &policymerge.PolicyYAML{Name: "b", Version: 1, DefaultAction: "deny", Rules: []policymerge.RuleYAML{rule}}

	result := Diff(a, b)
	if len(result.Both) != 1 {
		t.Errorf("Both = %d, want 1", len(result.Both))
	}
	if len(result.OnlyA) != 0 || len(result.OnlyB) != 0 {
		t.Errorf("OnlyA=%d OnlyB=%d, want 0,0", len(result.OnlyA), len(result.OnlyB))
	}
}

func TestDiffPartialOverlap(t *testing.T) {
	shared := policymerge.RuleYAML{
		Name: "shared", Event: "process", Action: "allow",
		Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"path": map[string]any{"eq": "/bin/x"}}}},
	}
	onlyInA := policymerge.RuleYAML{
		Name: "a-only", Event: "file", Action: "allow",
		Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"path": map[string]any{"eq": "/etc/a"}}}},
	}
	onlyInB := policymerge.RuleYAML{
		Name: "b-only", Event: "network", Action: "deny",
		Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"remote_addr": map[string]any{"eq": "10.0.0.1"}}}},
	}

	a := &policymerge.PolicyYAML{Name: "a", Version: 1, DefaultAction: "deny", Rules: []policymerge.RuleYAML{shared, onlyInA}}
	b := &policymerge.PolicyYAML{Name: "b", Version: 1, DefaultAction: "deny", Rules: []policymerge.RuleYAML{shared, onlyInB}}

	result := Diff(a, b)
	if len(result.Both) != 1 {
		t.Errorf("Both = %d, want 1", len(result.Both))
	}
	if len(result.OnlyA) != 1 {
		t.Errorf("OnlyA = %d, want 1", len(result.OnlyA))
	}
	if len(result.OnlyB) != 1 {
		t.Errorf("OnlyB = %d, want 1", len(result.OnlyB))
	}
}

func TestDiffSameConditionsDifferentAction(t *testing.T) {
	ruleA := policymerge.RuleYAML{
		Name: "r", Event: "process", Action: "allow",
		Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"path": map[string]any{"eq": "/bin/x"}}}},
	}
	ruleB := policymerge.RuleYAML{
		Name: "r", Event: "process", Action: "deny",
		Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"path": map[string]any{"eq": "/bin/x"}}}},
	}

	a := &policymerge.PolicyYAML{Name: "a", Version: 1, DefaultAction: "deny", Rules: []policymerge.RuleYAML{ruleA}}
	b := &policymerge.PolicyYAML{Name: "b", Version: 1, DefaultAction: "deny", Rules: []policymerge.RuleYAML{ruleB}}

	result := Diff(a, b)
	// Same event+conditions but allow vs deny is a decision change.
	if len(result.Changed) != 1 || len(result.Both) != 0 {
		t.Errorf("Changed = %d, Both = %d, want 1, 0", len(result.Changed), len(result.Both))
	}
}

func TestFormatSummary(t *testing.T) {
	r := &DiffResult{
		OnlyA: make([]policymerge.RuleYAML, 3),
		OnlyB: make([]policymerge.RuleYAML, 2),
		Both:  make([]policymerge.RuleYAML, 5),
	}
	s := FormatSummary(r, "sbom.yaml", "audit.yaml")
	if s == "" {
		t.Fatal("empty summary")
	}
}
