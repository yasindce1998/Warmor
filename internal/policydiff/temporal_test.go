package policydiff

import (
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/policymerge"
)

func TestDiffTemporalWindowChange(t *testing.T) {
	rule := func(temporal map[string]any) policymerge.RuleYAML {
		return policymerge.RuleYAML{
			Name: "curl", Event: "network", Action: "deny", Temporal: temporal,
			Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"comm": map[string]any{"eq": "curl"}}}},
		}
	}
	pol := func(r policymerge.RuleYAML) *policymerge.PolicyYAML {
		return &policymerge.PolicyYAML{Name: "p", Version: 1, Rules: []policymerge.RuleYAML{r}}
	}
	five := map[string]any{"max_container_age": "5m"}
	hour := map[string]any{"max_container_age": "1h"}

	for _, tc := range []struct {
		name   string
		a, b   map[string]any
		change string
	}{
		{"window changed", five, hour, `temporal {"max_container_age":"5m"} -> {"max_container_age":"1h"}`},
		{"window added", nil, five, `temporal none -> {"max_container_age":"5m"}`},
		{"window removed", five, nil, `temporal {"max_container_age":"5m"} -> none`},
	} {
		res := Diff(pol(rule(tc.a)), pol(rule(tc.b)))
		if len(res.Changed) != 1 || len(res.Both) != 0 {
			t.Errorf("%s: changed=%d both=%d, want the rule reported as changed", tc.name, len(res.Changed), len(res.Both))
			continue
		}
		if got := describeChange(res.Changed[0].A, res.Changed[0].B); !strings.Contains(got, tc.change) {
			t.Errorf("%s: change %q, want %q", tc.name, got, tc.change)
		}
	}
	if res := Diff(pol(rule(five)), pol(rule(map[string]any{"max_container_age": "5m"}))); len(res.Both) != 1 {
		t.Errorf("identical windows: %+v", res)
	}
}
