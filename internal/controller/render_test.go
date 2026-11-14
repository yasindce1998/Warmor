package controller

import (
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/policymerge"
)

func testCR(name string, mutate func(*WarmorPolicySpec)) *WarmorPolicy {
	spec := WarmorPolicySpec{
		Name:          name,
		Version:       1,
		DefaultAction: "allow",
		Rules: []PolicyRule{{
			Name:  "block-tmp",
			Event: "process",
			Conditions: &RuleConditions{All: []map[string]any{
				{"path": map[string]any{"glob": "/tmp/**"}},
			}},
			Action: "deny",
		}},
	}
	if mutate != nil {
		mutate(&spec)
	}
	return &WarmorPolicy{Metadata: ObjectMeta{Name: name, Namespace: "warmor-system"}, Spec: spec}
}

func TestRenderPolicy_TranslatesVocabulary(t *testing.T) {
	// The CRD says audit; the daemon schema says log.
	cr := testCR("audity", func(s *WarmorPolicySpec) {
		s.DefaultAction = "audit"
		s.Rules[0].Action = "audit"
	})
	rendered, err := renderPolicy(cr)
	if err != nil {
		t.Fatal(err)
	}
	if rendered.DefaultAction != "log" || rendered.Rules[0].Action != "log" {
		t.Errorf("rendered = %q/%q, want log/log", rendered.DefaultAction, rendered.Rules[0].Action)
	}
}

func TestRenderPolicy_RejectsInvalidActions(t *testing.T) {
	cr := testCR("bad", func(s *WarmorPolicySpec) { s.Rules[0].Action = "block" })
	if _, err := renderPolicy(cr); err == nil {
		t.Fatal("invalid rule action accepted")
	}
	cr = testCR("bad-default", func(s *WarmorPolicySpec) { s.DefaultAction = "watch" })
	if _, err := renderPolicy(cr); err == nil {
		t.Fatal("invalid defaultAction accepted")
	}
}

func TestRenderPolicy_NamespacesVariables(t *testing.T) {
	cr := testCR("alpha", func(s *WarmorPolicySpec) {
		s.Variables = map[string]any{"blocked_bins": []any{"/usr/bin/nc"}}
		s.Variables["alias"] = "$blocked_bins"
		s.Rules[0].Conditions.All = []map[string]any{
			{"path": map[string]any{"any_of": "$alias"}},
			{"comm": "$$unknown_stays_literal"},
		}
	})
	rendered, err := renderPolicy(cr)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rendered.Variables["alpha__blocked_bins"]; !ok {
		t.Fatalf("variables = %v, want the namespaced name", rendered.Variables)
	}
	if _, ok := rendered.Variables["blocked_bins"]; ok {
		t.Error("the un-namespaced variable name leaked through")
	}

	glob, ok := rendered.Rules[0].Conditions.All[0]["path"].(map[string]any)
	if !ok {
		t.Fatalf("path condition = %T, want a map", rendered.Rules[0].Conditions.All[0]["path"])
	}
	if glob["any_of"] != "$alpha__alias" {
		t.Errorf("any_of = %v, want the namespaced reference", glob["any_of"])
	}
	comm := rendered.Rules[0].Conditions.All[1]["comm"]
	if comm != "$$unknown_stays_literal" {
		t.Errorf("unknown $ref = %v, want it untouched", comm)
	}

	// The rendered policy must pass the compiler's parser (variable
	// resolves, condition fields are valid for the event).
	yamlBytes, err := policymerge.Marshal(rendered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compiler.Parse(yamlBytes); err != nil {
		t.Fatalf("rendered policy does not parse: %v", err)
	}
}

func TestRenderPolicy_PrefixesRuleNames(t *testing.T) {
	rendered, err := renderPolicy(testCR("alpha", nil))
	if err != nil {
		t.Fatal(err)
	}
	if rendered.Rules[0].Name != "alpha/block-tmp" {
		t.Errorf("rule name = %q, want the policy-prefixed name", rendered.Rules[0].Name)
	}
}

func TestEffectivePolicy_OrdersMostRestrictiveFirst(t *testing.T) {
	// allow from one policy, deny from another: first-match-wins means
	// the deny must be emitted first or the allow would shadow it.
	allow := &policymerge.PolicyYAML{Name: "a", Version: 1, DefaultAction: "allow", Rules: []policymerge.RuleYAML{
		{Name: "a/ok", Event: "process", Action: "allow",
			Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"uid": 0}}}},
	}}
	deny := &policymerge.PolicyYAML{Name: "b", Version: 1, DefaultAction: "deny", Rules: []policymerge.RuleYAML{
		{Name: "b/no", Event: "process", Action: "deny",
			Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"uid": 0}}}},
	}}

	effective := effectivePolicy("merged", []*policymerge.PolicyYAML{allow, deny})
	if effective.Rules[0].Action != "deny" {
		t.Errorf("first rule action = %q, want deny (most restrictive first)", effective.Rules[0].Action)
	}
	if effective.DefaultAction != "deny" {
		t.Errorf("default action = %q, want deny (strictest across policies)", effective.DefaultAction)
	}

	audit := &policymerge.PolicyYAML{Name: "c", Version: 1, DefaultAction: "log", Rules: []policymerge.RuleYAML{
		{Name: "c/watch", Event: "process", Action: "log",
			Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"uid": 0}}}},
	}}
	effective = effectivePolicy("merged", []*policymerge.PolicyYAML{allow, audit})
	if effective.DefaultAction != "log" {
		t.Errorf("default action = %q, want log (audit beats allow)", effective.DefaultAction)
	}
	if len(effective.Rules) != 2 || effective.Rules[0].Action != "log" {
		t.Errorf("rules = %+v, want log emitted before allow", effective.Rules)
	}
}

func TestEffectivePolicy_SinglePolicyPassesThrough(t *testing.T) {
	only := &policymerge.PolicyYAML{Name: "solo", Version: 7, DefaultAction: "deny", Rules: []policymerge.RuleYAML{
		{Name: "solo/allow-nginx", Event: "process", Action: "allow",
			Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"path": "/usr/bin/nginx"}}}},
		{Name: "solo/deny-broad", Event: "process", Action: "deny",
			Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"uid": 0}}}},
	}}
	effective := effectivePolicy("merged", []*policymerge.PolicyYAML{only})
	if effective.Version != 7 || effective.DefaultAction != "deny" || len(effective.Rules) != 2 {
		t.Errorf("pass-through = %+v", effective)
	}
	if effective.Name != "merged" {
		t.Errorf("name = %q, want the effective policy name", effective.Name)
	}
	// The author's rule order IS their precedence (first-match-wins): a
	// lone policy must not have its rules re-ordered by action.
	if effective.Rules[0].Name != "solo/allow-nginx" || effective.Rules[1].Name != "solo/deny-broad" {
		t.Errorf("rule order = [%s, %s], want the author's order preserved for a single policy",
			effective.Rules[0].Name, effective.Rules[1].Name)
	}
}

func TestEffectivePolicy_MergesIntoCompilablePolicy(t *testing.T) {
	// Two policies defining the same variable name and same-shaped rules:
	// the merged result must keep both variables disjoint and parse.
	render := func(name string) *policymerge.PolicyYAML {
		cr := testCR(name, func(s *WarmorPolicySpec) {
			s.Variables = map[string]any{"bins": []any{"/usr/bin/nc"}}
			s.Rules[0].Conditions.All = []map[string]any{
				{"path": map[string]any{"any_of": "$bins"}},
			}
		})
		rendered, err := renderPolicy(cr)
		if err != nil {
			t.Fatal(err)
		}
		return rendered
	}
	effective := effectivePolicy("merged", []*policymerge.PolicyYAML{render("alpha"), render("beta")})
	yamlBytes, err := policymerge.Marshal(effective)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := compiler.Parse(yamlBytes)
	if err != nil {
		t.Fatalf("merged policy does not parse: %v", err)
	}
	if len(parsed.Rules) != 2 {
		t.Errorf("merged rules = %d, want 2", len(parsed.Rules))
	}
}

func TestRenderPolicy_VariableInListIsRewritten(t *testing.T) {
	// A $ref nested inside a list of operator values.
	cr := testCR("alpha", func(s *WarmorPolicySpec) {
		s.Variables = map[string]any{"bins": "/usr/bin/nc"}
		s.Rules[0].Conditions.All = []map[string]any{
			{"path": map[string]any{"any_of": []any{"$bins", "/bin/sh"}}},
		}
	})
	rendered, err := renderPolicy(cr)
	if err != nil {
		t.Fatal(err)
	}
	glob, ok := rendered.Rules[0].Conditions.All[0]["path"].(map[string]any)
	if !ok {
		t.Fatalf("path condition = %T, want a map", rendered.Rules[0].Conditions.All[0]["path"])
	}
	list, ok := glob["any_of"].([]any)
	if !ok {
		t.Fatalf("any_of = %T, want a list", glob["any_of"])
	}
	if list[0] != "$alpha__bins" || list[1] != "/bin/sh" {
		t.Errorf("rewritten list = %v", list)
	}
}

func TestRenderPolicy_EmptyRulesRejected(t *testing.T) {
	// The CRD schema requires rules but the daemon also requires at least
	// one condition per rule; both surface as parse errors in classify,
	// not here. renderPolicy stays mechanical; sanity-check one case.
	cr := testCR("nocond", func(s *WarmorPolicySpec) {
		s.Rules[0].Conditions = nil
	})
	rendered, err := renderPolicy(cr)
	if err != nil {
		t.Fatal(err)
	}
	yamlBytes, _ := policymerge.Marshal(rendered)
	if _, err := compiler.Parse(yamlBytes); err == nil {
		t.Fatal("rule without conditions parsed, but the daemon would reject it")
	} else if !strings.Contains(err.Error(), "at least one condition") {
		t.Errorf("unexpected parse error: %v", err)
	}
}
