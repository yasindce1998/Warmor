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

func TestDiffIgnoresName(t *testing.T) {
	// A rename alone is not a decision change.
	r := Diff(policy("a", rule("name-a", "file", "deny", "/etc/passwd")), policy("b", rule("name-b", "file", "deny", "/etc/passwd")))
	if len(r.Both) != 1 || len(r.OnlyA)+len(r.OnlyB)+len(r.Changed) != 0 {
		t.Fatalf("expected match ignoring name, got %+v", r)
	}
	// Both reports the rule from policy A.
	if r.Both[0].Name != "name-a" {
		t.Errorf("Both[0] = %q, want rule from A", r.Both[0].Name)
	}
}

func TestDiffDecisionChangesReported(t *testing.T) {
	// Same event+conditions but a different action, mode or reason must be
	// surfaced as Changed, never silently reported as "In both".
	base := rule("r", "file", "allow", "/etc/passwd")
	cases := map[string]func(*policymerge.RuleYAML){
		"action": func(r *policymerge.RuleYAML) { r.Action = "deny" },
		"mode":   func(r *policymerge.RuleYAML) { r.Mode = "audit" },
		"reason": func(r *policymerge.RuleYAML) { r.Reason = "changed" },
		"all": func(r *policymerge.RuleYAML) {
			r.Name, r.Action, r.Mode, r.Reason = "r2", "deny", "enforce", "why b"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rb := base
			mutate(&rb)
			r := Diff(policy("a", base), policy("b", rb))
			if len(r.Changed) != 1 || len(r.Both)+len(r.OnlyA)+len(r.OnlyB) != 0 {
				t.Fatalf("expected one Changed, got %+v", r)
			}
			if r.Changed[0].A.Name != base.Name || r.Changed[0].B.Name != rb.Name ||
				r.Changed[0].A.Action != base.Action || r.Changed[0].B.Action != rb.Action {
				t.Errorf("unexpected pair %+v", r.Changed[0])
			}
		})
	}
}

func TestFormatDetailedChanged(t *testing.T) {
	ra := rule("r", "file", "allow", "/etc/shadow")
	rb := rule("r2", "file", "deny", "/etc/shadow")
	rb.Mode = "enforce"
	out := FormatDetailed(Diff(policy("a", ra), policy("b", rb)), "a.yaml", "b.yaml")
	want := "=== Changed (1 rules) ===\n  - [file] r -> r2: action allow -> deny, mode \"\" -> \"enforce\"\n\n"
	if out != want {
		t.Errorf("FormatDetailed =\n%q\nwant\n%q", out, want)
	}
	if s := FormatSummary(Diff(policy("a", ra), policy("b", rb)), "a", "b"); !strings.Contains(s, "Changed:    1 rules") {
		t.Errorf("summary missing changed count: %q", s)
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

func TestDiffDuplicateRulesKept(t *testing.T) {
	// Rules with identical event+conditions in one policy are all kept.
	a := policy("a", rule("first", "file", "allow", "/x"), rule("second", "file", "deny", "/x"))
	r := Diff(a, policy("b"))
	if got := strings.Join(names(r.OnlyA), ","); got != "first,second" {
		t.Fatalf("OnlyA = %s, want first,second", got)
	}

	// Duplicates are matched one-for-one: A has the rule twice, B once, so
	// one copy is shared and the other is only in A.
	dup := rule("d", "file", "allow", "/d")
	r = Diff(policy("a", dup, dup), policy("b", dup))
	if len(r.Both) != 1 || len(r.OnlyA) != 1 || len(r.OnlyB)+len(r.Changed) != 0 {
		t.Errorf("expected Both=1 OnlyA=1, got %+v", r)
	}

	// A conflicting duplicate in A is paired with B's differing rule only
	// after the identical copy has been matched.
	deny := rule("d", "file", "deny", "/d")
	r = Diff(policy("a", deny, dup), policy("b", dup, dup))
	if len(r.Both) != 1 || len(r.Changed) != 1 || len(r.OnlyA)+len(r.OnlyB) != 0 {
		t.Fatalf("expected Both=1 Changed=1, got %+v", r)
	}
	if r.Changed[0].A.Action != "deny" || r.Changed[0].B.Action != "allow" {
		t.Errorf("unexpected change %+v", r.Changed[0])
	}
}

func TestDiffSortStableTiebreak(t *testing.T) {
	// Same-named rules must come out in a deterministic order regardless of
	// input order.
	r1 := rule("same", "file", "allow", "/b")
	r2 := rule("same", "file", "allow", "/a")
	r3 := rule("same", "file", "deny", "/c")
	r4 := rule("same", "network", "allow", "/a")
	want := ""
	for i, in := range [][]policymerge.RuleYAML{{r1, r2, r3, r4}, {r4, r3, r2, r1}, {r3, r1, r4, r2}} {
		got := ""
		for _, x := range Diff(policy("a", in...), policy("b")).OnlyA {
			got += x.Event + "/" + x.Action + "/" + conditionsKey(x.Conditions) + ";"
		}
		if i == 0 {
			want = got
		} else if got != want {
			t.Errorf("order depends on input:\n%s\n%s", got, want)
		}
	}
	if want != "file/allow/"+conditionsKey(r2.Conditions)+";file/allow/"+conditionsKey(r1.Conditions)+";file/deny/"+conditionsKey(r3.Conditions)+";network/allow/"+conditionsKey(r4.Conditions)+";" {
		t.Errorf("unexpected order %s", want)
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
		t.Error("match fingerprint should cover only event+conditions")
	}
}

func TestFingerprintUnmarshalableConditions(t *testing.T) {
	// Conditions JSON cannot encode (NaN/Inf, which YAML ".nan"/".inf"
	// yield) must still fingerprint distinctly and deterministically.
	mk := func(event string, v any) policymerge.RuleYAML {
		return policymerge.RuleYAML{Event: event, Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"v": v}}}}
	}
	nan, inf, ninf := mk("file", math.NaN()), mk("file", math.Inf(1)), mk("file", math.Inf(-1))
	fps := map[string]string{
		"nan": fingerprint(nan), "inf": fingerprint(inf), "-inf": fingerprint(ninf),
		"nan-network": fingerprint(mk("network", math.NaN())),
		"nan-string":  fingerprint(mk("file", "NaN")),
		"key":         fingerprint(policymerge.RuleYAML{Event: "file", Conditions: policymerge.ConditionsYAML{All: []map[string]any{{"w": math.NaN()}}}}),
	}
	seen := map[string]string{}
	for k, fp := range fps {
		if other, ok := seen[fp]; ok {
			t.Errorf("%s and %s share fingerprint %s", k, other, fp)
		}
		seen[fp] = k
	}
	if fingerprint(nan) != fingerprint(mk("file", math.NaN())) {
		t.Error("NaN fingerprint not deterministic")
	}
	r := Diff(policy("a", nan), policy("b", inf))
	if len(r.OnlyA) != 1 || len(r.OnlyB) != 1 {
		t.Errorf("NaN vs Inf conditions matched: %+v", r)
	}
}

func TestFormatSummaryContent(t *testing.T) {
	r := &DiffResult{
		OnlyA: make([]policymerge.RuleYAML, 3),
		OnlyB: make([]policymerge.RuleYAML, 2),
		Both:  make([]policymerge.RuleYAML, 5),
	}
	r.Changed = make([]RuleChange, 1)
	got := FormatSummary(r, "sbom.yaml", "audit.yaml")
	want := "Only in sbom.yaml: 3 rules\nOnly in audit.yaml: 2 rules\nChanged:    1 rules\nIn both:    5 rules\n"
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
			[]string{"In both"}, []string{"Only in A", "Only in B", "Changed"}},
		{"only changed", &DiffResult{Changed: []RuleChange{{A: policymerge.RuleYAML{Name: "x"}, B: policymerge.RuleYAML{Name: "x", Action: "deny"}}}},
			[]string{"Changed (1 rules)"}, []string{"Only in A", "Only in B", "In both"}},
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
