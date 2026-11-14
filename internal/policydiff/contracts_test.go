package policydiff

import (
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/policymerge"
)

func TestDiffPolicyInputsAndFirstMatchOrder(t *testing.T) {
	allow := policymerge.RuleYAML{Name: "allow", Event: "process", Action: "allow", Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"comm": "$tool"}}}}
	deny := allow
	deny.Name, deny.Action = "deny", "deny"
	a := &policymerge.PolicyYAML{Variables: map[string]any{"tool": "sh"}, Rules: []policymerge.RuleYAML{allow, deny}}
	b := &policymerge.PolicyYAML{DefaultAction: "deny", Variables: map[string]any{"tool": "bash"}, Rules: []policymerge.RuleYAML{deny, allow}}
	r := Diff(a, b)
	if r.DefaultA != "allow" || r.DefaultB != "deny" || len(r.Variables) != 1 || !r.OrderChanged {
		t.Fatalf("missing changes: %+v", r)
	}
	for _, output := range []string{FormatSummary(r, "a", "b"), FormatDetailed(r, "a", "b")} {
		for _, want := range []string{"allow -> deny", "order changed", "not a proof"} {
			if !strings.Contains(output, want) {
				t.Errorf("missing %q in %s", want, output)
			}
		}
	}
	if output := FormatDetailed(r, "a", "b"); !strings.Contains(output, `Variable tool: "sh" -> "bash"`) {
		t.Fatal(output)
	}
}

func TestDiffImplicitDefaultAndInsertion(t *testing.T) {
	x := policymerge.RuleYAML{Name: "x", Event: "process", Action: "allow"}
	y := policymerge.RuleYAML{Name: "y", Event: "file", Action: "allow"}
	r := Diff(&policymerge.PolicyYAML{Rules: []policymerge.RuleYAML{x}}, &policymerge.PolicyYAML{DefaultAction: "allow", Rules: []policymerge.RuleYAML{y, x}})
	if r.DefaultA != r.DefaultB || r.OrderChanged {
		t.Fatalf("false change: %+v", r)
	}
}

func TestDiffReportsVariableAdditionRemovalAndTemporalChange(t *testing.T) {
	a := &policymerge.PolicyYAML{Variables: map[string]any{"removed": "old"}, Rules: []policymerge.RuleYAML{{Name: "window", Event: "process", Action: "deny"}}}
	b := &policymerge.PolicyYAML{Variables: map[string]any{"added": "new"}, Rules: []policymerge.RuleYAML{{Name: "window", Event: "process", Action: "deny", Temporal: map[string]any{"max_container_age": "5m"}}}}
	r := Diff(a, b)
	if len(r.Variables) != 2 || len(r.Changed) != 1 {
		t.Fatalf("missing semantic notices: %+v", r)
	}
	output := FormatDetailed(r, "a", "b")
	for _, want := range []string{`Variable added: <absent> -> "new"`, `Variable removed: "old" -> <absent>`, "temporal none ->", "not a proof of decision equivalence"} {
		if !strings.Contains(output, want) {
			t.Errorf("missing %q in %s", want, output)
		}
	}
}
