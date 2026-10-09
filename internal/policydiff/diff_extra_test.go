package policydiff

import (
	"math"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/policymerge"
)

func rule(name, event, action, path string) policymerge.RuleYAML {
	return policymerge.RuleYAML{
		Name: name, Event: event, Action: action,
		Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"path": map[string]any{"eq": path}}}},
	}
}

func policy(name string, rules ...policymerge.RuleYAML) *policymerge.PolicyYAML {
	return &policymerge.PolicyYAML{Name: name, Version: 1, DefaultAction: "deny", Rules: rules}
}

func names(rules []policymerge.RuleYAML) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.Name
	}
	return out
}

func TestDiffEmptyPolicies(t *testing.T) {
	r := Diff(policy("a"), policy("b"))
	if len(r.OnlyA)+len(r.OnlyB)+len(r.Both) != 0 {
		t.Errorf("expected empty result, got %+v", r)
	}
	if got := FormatDetailed(r, "a", "b"); got != "" {
		t.Errorf("FormatDetailed on empty diff = %q, want empty", got)
	}
}

func TestDiffOneSideEmpty(t *testing.T) {
	a := policy("a", rule("x", "file", "allow", "/x"), rule("y", "file", "allow", "/y"))
	r := Diff(a, policy("b"))
	if len(r.OnlyA) != 2 || len(r.OnlyB) != 0 || len(r.Both) != 0 {
		t.Errorf("got OnlyA=%d OnlyB=%d Both=%d", len(r.OnlyA), len(r.OnlyB), len(r.Both))
	}
	r = Diff(policy("a"), a)
	if len(r.OnlyA) != 0 || len(r.OnlyB) != 2 || len(r.Both) != 0 {
		t.Errorf("reversed: got OnlyA=%d OnlyB=%d Both=%d", len(r.OnlyA), len(r.OnlyB), len(r.Both))
	}
}

func TestDiffSymmetry(t *testing.T) {
	shared := rule("shared", "process", "allow", "/bin/x")
	a := policy("a", shared, rule("a1", "file", "allow", "/a1"))
	b := policy("b", shared, rule("b1", "file", "allow", "/b1"), rule("b2", "file", "allow", "/b2"))
	ab := Diff(a, b)
	ba := Diff(b, a)
	if strings.Join(names(ab.OnlyA), ",") != strings.Join(names(ba.OnlyB), ",") ||
		strings.Join(names(ab.OnlyB), ",") != strings.Join(names(ba.OnlyA), ",") ||
		len(ab.Both) != len(ba.Both) {
		t.Errorf("Diff not symmetric: ab=%+v ba=%+v", ab, ba)
	}
}

func TestDiffResultsSortedByName(t *testing.T) {
	a := policy("a",
		rule("zeta", "file", "allow", "/z"),
		rule("alpha", "file", "allow", "/a"),
		rule("mid", "file", "allow", "/m"),
		rule("s2", "process", "allow", "/s2"),
		rule("s1", "process", "allow", "/s1"),
	)
	b := policy("b",
		rule("s1", "process", "allow", "/s1"),
		rule("s2", "process", "allow", "/s2"),
		rule("yy", "network", "deny", "/yy"),
		rule("bb", "network", "deny", "/bb"),
	)
	for i := 0; i < 20; i++ { // map iteration is randomised; repeat
		r := Diff(a, b)
		if got := strings.Join(names(r.OnlyA), ","); got != "alpha,mid,zeta" {
			t.Fatalf("OnlyA order = %s", got)
		}
		if got := strings.Join(names(r.OnlyB), ","); got != "bb,yy" {
			t.Fatalf("OnlyB order = %s", got)
		}
		if got := strings.Join(names(r.Both), ","); got != "s1,s2" {
			t.Fatalf("Both order = %s", got)
		}
	}
}

func TestDiffIgnoresNameActionModeReason(t *testing.T) {
	ra := rule("name-a", "file", "allow", "/etc/passwd")
	ra.Mode, ra.Reason = "audit", "why a"
	rb := rule("name-b", "file", "deny", "/etc/passwd")
	rb.Mode, rb.Reason = "enforce", "why b"
	r := Diff(policy("a", ra), policy("b", rb))
	if len(r.Both) != 1 || len(r.OnlyA) != 0 || len(r.OnlyB) != 0 {
		t.Errorf("expected match on event+conditions only, got %+v", r)
	}
	// Both reports the rule from policy A.
	if r.Both[0].Name != "name-a" {
		t.Errorf("Both[0] = %q, want rule from A", r.Both[0].Name)
	}
}

func TestDiffEventDistinguishes(t *testing.T) {
	r := Diff(policy("a", rule("r", "file", "allow", "/x")), policy("b", rule("r", "process", "allow", "/x")))
	if len(r.Both) != 0 || len(r.OnlyA) != 1 || len(r.OnlyB) != 1 {
		t.Errorf("different events should not match: %+v", r)
	}
}

func TestDiffConditionKindDistinguishes(t *testing.T) {
	cond := []map[string]any{{"path": map[string]any{"eq": "/x"}}}
	all := policymerge.RuleYAML{Name: "all", Event: "file", Conditions: policymerge.ConditionsYAML{All: cond}}
	anyR := policymerge.RuleYAML{Name: "any", Event: "file", Conditions: policymerge.ConditionsYAML{Any: cond}}
	not := policymerge.RuleYAML{Name: "not", Event: "file", Conditions: policymerge.ConditionsYAML{Not: cond}}
	r := Diff(policy("a", all, anyR), policy("b", not))
	if len(r.Both) != 0 || len(r.OnlyA) != 2 || len(r.OnlyB) != 1 {
		t.Errorf("all/any/not should be distinct: %+v", r)
	}
}

func TestDiffConditionMapKeyOrderIrrelevant(t *testing.T) {
	// encoding/json sorts map keys, so insertion order must not matter.
	m1 := map[string]any{}
	m1["path"] = "/x"
	m1["uid"] = 0
	m2 := map[string]any{}
	m2["uid"] = 0
	m2["path"] = "/x"
	a := policymerge.RuleYAML{Name: "a", Event: "file", Conditions: policymerge.ConditionsYAML{All: []map[string]any{m1}}}
	b := policymerge.RuleYAML{Name: "b", Event: "file", Conditions: policymerge.ConditionsYAML{All: []map[string]any{m2}}}
	if fingerprint(a) != fingerprint(b) {
		t.Error("fingerprint depends on map insertion order")
	}
}

func TestDiffConditionListOrderMatters(t *testing.T) {
	c1 := map[string]any{"path": "/a"}
	c2 := map[string]any{"path": "/b"}
	a := policymerge.RuleYAML{Event: "file", Conditions: policymerge.ConditionsYAML{All: []map[string]any{c1, c2}}}
	b := policymerge.RuleYAML{Event: "file", Conditions: policymerge.ConditionsYAML{All: []map[string]any{c2, c1}}}
	if fingerprint(a) == fingerprint(b) {
		t.Error("expected condition list order to affect fingerprint (current semantics)")
	}
}

func TestDiffDuplicateRulesCollapse(t *testing.T) {
	// Two rules with identical event+conditions in one policy collapse into
	// a single fingerprint entry (the last one wins).
	a := policy("a", rule("first", "file", "allow", "/x"), rule("second", "file", "deny", "/x"))
	r := Diff(a, policy("b"))
	if len(r.OnlyA) != 1 {
		t.Fatalf("OnlyA = %d, want 1 (duplicates collapse)", len(r.OnlyA))
	}
	if r.OnlyA[0].Name != "second" {
		t.Errorf("kept %q, want last duplicate", r.OnlyA[0].Name)
	}
}

func TestFingerprintFormat(t *testing.T) {
	fp := fingerprint(rule("r", "file", "allow", "/x"))
	if len(fp) != 16 {
		t.Errorf("fingerprint length = %d, want 16 hex chars", len(fp))
	}
	for _, c := range fp {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("non-hex char in fingerprint %q", fp)
		}
	}
	if fp != fingerprint(rule("other", "file", "deny", "/x")) {
		t.Error("fingerprint not deterministic over event+conditions")
	}
}

func TestFingerprintUnmarshalableConditionsCollide(t *testing.T) {
	// json.Marshal errors are ignored in fingerprint, so any two rules whose
	// conditions cannot be marshalled (e.g. NaN, which YAML ".nan" yields)
	// hash identically regardless of event. Documents current behaviour.
	a := policymerge.RuleYAML{Event: "file", Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"v": math.NaN()}}}}
	b := policymerge.RuleYAML{Event: "network", Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"w": math.Inf(1)}}}}
	if fingerprint(a) != fingerprint(b) {
		t.Skip("fingerprint now distinguishes unmarshalable conditions")
	}
}

func TestFormatSummaryContent(t *testing.T) {
	r := &DiffResult{
		OnlyA: make([]policymerge.RuleYAML, 3),
		OnlyB: make([]policymerge.RuleYAML, 2),
		Both:  make([]policymerge.RuleYAML, 5),
	}
	got := FormatSummary(r, "sbom.yaml", "audit.yaml")
	want := "Only in sbom.yaml: 3 rules\nOnly in audit.yaml: 2 rules\nIn both:    5 rules\n"
	if got != want {
		t.Errorf("FormatSummary =\n%q\nwant\n%q", got, want)
	}
}

func TestFormatDetailedAllSections(t *testing.T) {
	r := &DiffResult{
		OnlyA: []policymerge.RuleYAML{{Name: "a1", Event: "file", Action: "allow"}},
		OnlyB: []policymerge.RuleYAML{{Name: "b1", Event: "network", Action: "deny"}, {Name: "b2", Event: "process", Action: "log"}},
		Both:  []policymerge.RuleYAML{{Name: "s1", Event: "process", Action: "allow"}},
	}
	got := FormatDetailed(r, "left.yaml", "right.yaml")
	want := "=== Only in left.yaml (1 rules) ===\n" +
		"  - [file] a1 (allow)\n\n" +
		"=== Only in right.yaml (2 rules) ===\n" +
		"  - [network] b1 (deny)\n" +
		"  - [process] b2 (log)\n\n" +
		"=== In both (1 rules) ===\n" +
		"  - [process] s1 (allow)\n\n"
	if got != want {
		t.Errorf("FormatDetailed =\n%s\nwant\n%s", got, want)
	}
}

func TestFormatDetailedOmitsEmptySections(t *testing.T) {
	cases := []struct {
		name    string
		r       *DiffResult
		want    []string
		notWant []string
	}{
		{"only A", &DiffResult{OnlyA: []policymerge.RuleYAML{{Name: "x"}}},
			[]string{"Only in A"}, []string{"Only in B", "In both"}},
		{"only B", &DiffResult{OnlyB: []policymerge.RuleYAML{{Name: "x"}}},
			[]string{"Only in B"}, []string{"Only in A", "In both"}},
		{"only both", &DiffResult{Both: []policymerge.RuleYAML{{Name: "x"}}},
			[]string{"In both"}, []string{"Only in A", "Only in B"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FormatDetailed(tc.r, "A", "B")
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("missing %q in %q", w, got)
				}
			}
			for _, nw := range tc.notWant {
				if strings.Contains(got, nw) {
					t.Errorf("unexpected %q in %q", nw, got)
				}
			}
		})
	}
}

func TestDiffThenFormatEndToEnd(t *testing.T) {
	a := policy("a", rule("shared", "process", "allow", "/bin/x"), rule("a-only", "file", "allow", "/etc/a"))
	b := policy("b", rule("shared", "process", "allow", "/bin/x"))
	out := FormatDetailed(Diff(a, b), "a.yaml", "b.yaml")
	if !strings.Contains(out, "=== Only in a.yaml (1 rules) ===\n  - [file] a-only (allow)") {
		t.Errorf("unexpected output:\n%s", out)
	}
	if !strings.Contains(out, "=== In both (1 rules) ===\n  - [process] shared (allow)") {
		t.Errorf("unexpected output:\n%s", out)
	}
	if strings.Contains(out, "Only in b.yaml") {
		t.Errorf("unexpected B section:\n%s", out)
	}
}
