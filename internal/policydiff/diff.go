package policydiff

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/yasindce1998/warmor/internal/policymerge"
)

type DiffResult struct {
	DefaultA     string
	DefaultB     string
	Variables    []VariableChange
	OrderChanged bool
	OrderA       []string
	OrderB       []string
	OnlyA        []policymerge.RuleYAML
	OnlyB        []policymerge.RuleYAML
	// Changed holds rules that match on (event, conditions) but whose
	// decision (action, mode, reason or temporal window) differs between
	// the policies.
	Changed []RuleChange
	Both    []policymerge.RuleYAML
}

type VariableChange struct {
	Name     string
	A        any
	B        any
	PresentA bool
	PresentB bool
}

// RuleChange pairs a rule in policy A with the rule in policy B that has the
// same event and conditions but a different decision.
type RuleChange struct {
	A policymerge.RuleYAML
	B policymerge.RuleYAML
}

// Diff compares the rules of a and b. Rules are matched on (event,
// conditions); a matched pair is in Both if action, mode, reason and temporal
// window are also
// equal, otherwise in Changed. Duplicate rules within one policy are kept
// and matched one-for-one, so their counts are reported faithfully.
func Diff(a, b *policymerge.PolicyYAML) *DiffResult {
	ea := entries(a.Rules)
	eb := entries(b.Rules)
	usedA := make([]bool, len(ea))
	usedB := make([]bool, len(eb))

	result := &DiffResult{DefaultA: effectiveDefault(a.DefaultAction), DefaultB: effectiveDefault(b.DefaultAction)}
	keys := make(map[string]bool)
	for k := range a.Variables {
		keys[k] = true
	}
	for k := range b.Variables {
		keys[k] = true
	}
	for k := range keys {
		av, oka := a.Variables[k]
		bv, okb := b.Variables[k]
		if oka != okb || string(canonical(av)) != string(canonical(bv)) {
			result.Variables = append(result.Variables, VariableChange{k, av, bv, oka, okb})
		}
	}
	sort.Slice(result.Variables, func(i, j int) bool { return result.Variables[i].Name < result.Variables[j].Name })
	// Track matched pairs in source order: inserting an unrelated rule should
	// not look like reordering, but a relative first-match change must be shown.
	pairs := make(map[int]int)

	// Pass 1: identical rules (same conditions and decision).
	byFull := make(map[string][]int, len(eb))
	for j, e := range eb {
		byFull[e.full] = append(byFull[e.full], j)
	}
	for i, e := range ea {
		if q := byFull[e.full]; len(q) > 0 {
			byFull[e.full] = q[1:]
			usedA[i], usedB[q[0]] = true, true
			pairs[i] = q[0]
			result.Both = append(result.Both, e.rule)
		}
	}

	// Pass 2: same conditions, different decision.
	byMatch := make(map[string][]int, len(eb))
	for j, e := range eb {
		if !usedB[j] {
			byMatch[e.match] = append(byMatch[e.match], j)
		}
	}
	for i, e := range ea {
		if usedA[i] {
			continue
		}
		if q := byMatch[e.match]; len(q) > 0 {
			byMatch[e.match] = q[1:]
			usedA[i], usedB[q[0]] = true, true
			pairs[i] = q[0]
			result.Changed = append(result.Changed, RuleChange{A: e.rule, B: eb[q[0]].rule})
		}
	}

	for i, e := range ea {
		if !usedA[i] {
			result.OnlyA = append(result.OnlyA, e.rule)
		}
	}
	for j, e := range eb {
		if !usedB[j] {
			result.OnlyB = append(result.OnlyB, e.rule)
		}
	}

	last := -1
	for i := range ea {
		if j, ok := pairs[i]; ok {
			if j < last {
				result.OrderChanged = true
			}
			last = j
			result.OrderA = append(result.OrderA, ea[i].rule.Name)
		}
	}
	for j := range eb {
		if usedB[j] {
			result.OrderB = append(result.OrderB, eb[j].rule.Name)
		}
	}
	sortRules(result.OnlyA)
	sortRules(result.OnlyB)
	sortRules(result.Both)
	sort.SliceStable(result.Changed, func(i, j int) bool {
		if c := compareRules(result.Changed[i].A, result.Changed[j].A); c != 0 {
			return c < 0
		}
		return compareRules(result.Changed[i].B, result.Changed[j].B) < 0
	})

	return result
}

type entry struct {
	rule  policymerge.RuleYAML
	match string // fingerprint of (event, conditions)
	full  string // match plus decision fields
}

func effectiveDefault(action string) string {
	if action == "" {
		return "allow"
	}
	return action
}

func entries(rules []policymerge.RuleYAML) []entry {
	out := make([]entry, len(rules))
	for i, r := range rules {
		fp := fingerprint(r)
		out[i] = entry{rule: r, match: fp, full: fp + "\x00" + decisionKey(r)}
	}
	return out
}

func decisionKey(r policymerge.RuleYAML) string {
	return r.Action + "\x00" + r.Mode + "\x00" + r.Reason + "\x00" + temporalKey(r.Temporal)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// temporalKey renders a rule's temporal block canonically ("" for none).
func temporalKey(t map[string]any) string {
	if len(t) == 0 {
		return ""
	}
	return string(canonical(t))
}

// sortRules orders rules by name with a full tiebreak on every other field
// so the output is deterministic even for same-named or duplicate rules.
func sortRules(rules []policymerge.RuleYAML) {
	sort.SliceStable(rules, func(i, j int) bool { return compareRules(rules[i], rules[j]) < 0 })
}

func compareRules(a, b policymerge.RuleYAML) int {
	for _, p := range [][2]string{
		{a.Name, b.Name},
		{a.Event, b.Event},
		{a.Action, b.Action},
		{a.Mode, b.Mode},
		{a.Reason, b.Reason},
		{conditionsKey(a.Conditions), conditionsKey(b.Conditions)},
		{temporalKey(a.Temporal), temporalKey(b.Temporal)},
	} {
		if c := strings.Compare(p[0], p[1]); c != 0 {
			return c
		}
	}
	return 0
}

// fingerprint identifies a rule by (event, conditions); it is the key on
// which rules in the two policies are matched.
func fingerprint(r policymerge.RuleYAML) string {
	obj := struct {
		Event      string                     `json:"event"`
		Conditions policymerge.ConditionsYAML `json:"conditions"`
	}{Event: r.Event, Conditions: r.Conditions}
	h := sha256.Sum256(canonical(obj))
	return fmt.Sprintf("%x", h[:8])
}

func conditionsKey(c policymerge.ConditionsYAML) string {
	return string(canonical(c))
}

// canonical renders v as JSON (which sorts map keys). Values JSON cannot
// encode, such as NaN or ±Inf from YAML ".nan"/".inf", fall back to a %#v
// rendering, which also sorts map keys and keeps distinct values distinct;
// the prefix keeps it disjoint from any JSON rendering.
func canonical(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		return []byte(fmt.Sprintf("fmt:%#v", v))
	}
	return data
}

func FormatSummary(r *DiffResult, nameA, nameB string) string {
	return fmt.Sprintf("Only in %s: %d rules\nOnly in %s: %d rules\nChanged:    %d rules\nIn both:    %d rules\nEffective defaults: %s -> %s\nVariable changes: %d\nRule order changed: %t\nStructural comparison only; not a proof of decision equivalence.\n",
		nameA, len(r.OnlyA), nameB, len(r.OnlyB), len(r.Changed), len(r.Both), r.DefaultA, r.DefaultB, len(r.Variables), r.OrderChanged)
}

func FormatDetailed(r *DiffResult, nameA, nameB string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Effective default action: %s -> %s\n", r.DefaultA, r.DefaultB)
	for _, v := range r.Variables {
		av, bv := "<absent>", "<absent>"
		if v.PresentA {
			av = string(canonical(v.A))
		}
		if v.PresentB {
			bv = string(canonical(v.B))
		}
		fmt.Fprintf(&b, "Variable %s: %s -> %s\n", v.Name, av, bv)
	}
	if r.OrderChanged {
		fmt.Fprintf(&b, "Rule order changed (first match wins):\n  %s: %s\n  %s: %s\n", nameA, strings.Join(r.OrderA, ", "), nameB, strings.Join(r.OrderB, ", "))
	}
	b.WriteString("Structural comparison only; not a proof of decision equivalence.\n\n")

	if len(r.OnlyA) > 0 {
		fmt.Fprintf(&b, "=== Only in %s (%d rules) ===\n", nameA, len(r.OnlyA))
		for _, rule := range r.OnlyA {
			fmt.Fprintf(&b, "  - [%s] %s (%s)\n", rule.Event, rule.Name, rule.Action)
		}
		b.WriteByte('\n')
	}

	if len(r.OnlyB) > 0 {
		fmt.Fprintf(&b, "=== Only in %s (%d rules) ===\n", nameB, len(r.OnlyB))
		for _, rule := range r.OnlyB {
			fmt.Fprintf(&b, "  - [%s] %s (%s)\n", rule.Event, rule.Name, rule.Action)
		}
		b.WriteByte('\n')
	}

	if len(r.Changed) > 0 {
		fmt.Fprintf(&b, "=== Changed (%d rules) ===\n", len(r.Changed))
		for _, c := range r.Changed {
			name := c.A.Name
			if c.B.Name != c.A.Name {
				name = c.A.Name + " -> " + c.B.Name
			}
			fmt.Fprintf(&b, "  - [%s] %s: %s\n", c.A.Event, name, describeChange(c.A, c.B))
		}
		b.WriteByte('\n')
	}

	if len(r.Both) > 0 {
		fmt.Fprintf(&b, "=== In both (%d rules) ===\n", len(r.Both))
		for _, rule := range r.Both {
			fmt.Fprintf(&b, "  - [%s] %s (%s)\n", rule.Event, rule.Name, rule.Action)
		}
		b.WriteByte('\n')
	}

	return b.String()
}

// describeChange lists the decision fields that differ between a and b.
func describeChange(a, b policymerge.RuleYAML) string {
	var parts []string
	if a.Action != b.Action {
		parts = append(parts, fmt.Sprintf("action %s -> %s", a.Action, b.Action))
	}
	if a.Mode != b.Mode {
		parts = append(parts, fmt.Sprintf("mode %q -> %q", a.Mode, b.Mode))
	}
	if a.Reason != b.Reason {
		parts = append(parts, fmt.Sprintf("reason %q -> %q", a.Reason, b.Reason))
	}
	if ta, tb := temporalKey(a.Temporal), temporalKey(b.Temporal); ta != tb {
		parts = append(parts, fmt.Sprintf("temporal %s -> %s", orNone(ta), orNone(tb)))
	}
	return strings.Join(parts, ", ")
}
