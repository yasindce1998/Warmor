package policymerge

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

func LoadFile(path string) (*PolicyYAML, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var p PolicyYAML
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("%s: policy name is required", path)
	}
	return &p, nil
}

func LoadDir(dir string) ([]*PolicyYAML, []string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("read directory %s: %w", dir, err)
	}

	var policies []*PolicyYAML
	var names []string

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		p, err := LoadFile(path)
		if err != nil {
			return nil, nil, err
		}
		policies = append(policies, p)
		names = append(names, e.Name())
	}

	if len(policies) == 0 {
		return nil, nil, fmt.Errorf("no .yaml/.yml policy files found in %s", dir)
	}
	return policies, names, nil
}

type sourcedRule struct {
	rule   RuleYAML
	source string
}

func Merge(policies []*PolicyYAML, sources []string, opts MergeOptions) (*MergeResult, error) {
	if len(policies) < 2 {
		return nil, fmt.Errorf("at least 2 policies required to merge, got %d", len(policies))
	}

	if opts.Strategy == "" {
		opts.Strategy = "union"
	}

	merged := &PolicyYAML{
		Name:      opts.Name,
		Version:   1,
		Variables: make(map[string]any),
	}

	if merged.Name == "" {
		merged.Name = "merged-policy"
	}

	merged.DefaultAction = strictestAction(policies)

	for _, p := range policies {
		if p.Version > merged.Version {
			merged.Version = p.Version
		}
	}

	for _, p := range policies {
		for k, v := range p.Variables {
			if existing, ok := merged.Variables[k]; ok {
				merged.Variables[k] = mergeVariableValues(existing, v)
			} else {
				merged.Variables[k] = v
			}
		}
	}

	var allRules []sourcedRule
	for i, p := range policies {
		src := ""
		if len(sources) > i {
			src = sources[i]
		}
		for _, r := range p.Rules {
			allRules = append(allRules, sourcedRule{rule: r, source: src})
		}
	}

	totalRules := len(allRules)
	dedupedCount := 0

	switch opts.Strategy {
	case "union":
		merged.Rules = applyUnion(allRules, opts, &dedupedCount)
	case "intersection":
		merged.Rules = applyIntersection(allRules, opts, &dedupedCount)

	case "deny-wins":
		merged.Rules = applyDenyWins(allRules, opts, &dedupedCount)
	default:
		return nil, fmt.Errorf("unknown strategy %q (use union, intersection, or deny-wins)", opts.Strategy)
	}

	// Dedup variable values
	if opts.Dedup {
		for k, v := range merged.Variables {
			merged.Variables[k] = dedupVariable(v)
		}
	}

	if len(merged.Variables) == 0 {
		merged.Variables = nil
	}

	// Description
	if opts.Description != "" {
		merged.Description = opts.Description
	} else {
		merged.Description = fmt.Sprintf("Merged policy from %d sources (%d rules, %d deduplicated)",
			len(policies), len(merged.Rules), dedupedCount)
	}

	return &MergeResult{
		Policy:       merged,
		TotalRules:   totalRules,
		DedupedRules: dedupedCount,
		Sources:      len(policies),
	}, nil
}

func Marshal(p *PolicyYAML) ([]byte, error) {
	return yaml.Marshal(p)
}

func applyUnion(rules []sourcedRule, opts MergeOptions, dedupCount *int) []RuleYAML {
	seen := make(map[string]int) // fingerprint → index in result
	var result []RuleYAML

	for _, sr := range rules {
		fp := ruleFingerprint(sr.rule)

		if idx, exists := seen[fp]; exists && opts.Dedup {
			*dedupCount++
			// Merge reasons
			if opts.Annotate && sr.source != "" {
				existing := result[idx].Reason
				if !strings.Contains(existing, sr.source) {
					result[idx].Reason = existing + " + " + sr.source
				}
			}
			continue
		}

		r := sr.rule
		if opts.Annotate && sr.source != "" {
			if r.Reason != "" {
				r.Reason = r.Reason + " [" + sr.source + "]"
			} else {
				r.Reason = "Source: " + sr.source
			}
		}

		// Handle name collisions
		r.Name = uniqueName(r.Name, result)

		seen[fp] = len(result)
		result = append(result, r)
	}

	return result
}

func applyIntersection(rules []sourcedRule, opts MergeOptions, dedupCount *int) []RuleYAML {
	// Only keep rules whose fingerprint appears in at least 2 sources
	type fpSource struct {
		sources []string
		rule    RuleYAML
	}
	fpMap := make(map[string]*fpSource)

	for _, sr := range rules {
		fp := ruleFingerprint(sr.rule)
		if entry, exists := fpMap[fp]; exists {
			found := false
			for _, s := range entry.sources {
				if s == sr.source {
					found = true
					break
				}
			}
			if !found {
				entry.sources = append(entry.sources, sr.source)
			}
		} else {
			fpMap[fp] = &fpSource{
				sources: []string{sr.source},
				rule:    sr.rule,
			}
		}
	}

	var result []RuleYAML
	totalSkipped := 0

	for _, entry := range fpMap {
		if len(entry.sources) < 2 {
			totalSkipped++
			continue
		}

		r := entry.rule
		if opts.Annotate {
			r.Reason = "Confirmed by: " + strings.Join(entry.sources, ", ")
		}
		r.Name = uniqueName(r.Name, result)
		result = append(result, r)
	}

	*dedupCount = totalSkipped
	return result
}

func applyDenyWins(rules []sourcedRule, opts MergeOptions, dedupCount *int) []RuleYAML {
	// Group by fingerprint; if any source has deny, final is deny
	type fpEntry struct {
		rule     RuleYAML
		sources  []string
		hasDeny  bool
		hasAllow bool
	}
	fpMap := make(map[string]*fpEntry)
	var order []string

	for _, sr := range rules {
		fp := ruleFingerprint(sr.rule)
		if entry, exists := fpMap[fp]; exists {
			*dedupCount++
			entry.sources = append(entry.sources, sr.source)
			if sr.rule.Action == "deny" {
				entry.hasDeny = true
			}
			if sr.rule.Action == "allow" {
				entry.hasAllow = true
			}
		} else {
			fpMap[fp] = &fpEntry{
				rule:     sr.rule,
				sources:  []string{sr.source},
				hasDeny:  sr.rule.Action == "deny",
				hasAllow: sr.rule.Action == "allow",
			}
			order = append(order, fp)
		}
	}

	var result []RuleYAML
	for _, fp := range order {
		entry := fpMap[fp]
		r := entry.rule
		if entry.hasDeny {
			r.Action = "deny"
		}
		if opts.Annotate {
			r.Reason = "Source: " + strings.Join(entry.sources, ", ")
			if entry.hasDeny && entry.hasAllow {
				r.Reason += " (deny wins)"
			}
		}
		r.Name = uniqueName(r.Name, result)
		result = append(result, r)
	}

	return result
}

func ruleFingerprint(r RuleYAML) string {
	// Fingerprint based on event type + conditions + temporal window
	// (ignoring name, action, reason). Rules with different windows are
	// different rules: merging them would keep only one window.
	fp := struct {
		Event      string
		Conditions ConditionsYAML
		Temporal   map[string]any `json:",omitempty"`
	}{
		Event:      r.Event,
		Conditions: r.Conditions,
		Temporal:   r.Temporal,
	}
	data, _ := json.Marshal(fp)
	return string(data)
}

func uniqueName(name string, existing []RuleYAML) string {
	taken := make(map[string]bool)
	for _, r := range existing {
		taken[r.Name] = true
	}
	if !taken[name] {
		return name
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s-%d", name, i)
		if !taken[candidate] {
			return candidate
		}
	}
}

func strictestAction(policies []*PolicyYAML) string {
	// deny > log > allow
	hasDeny := false
	hasLog := false
	for _, p := range policies {
		switch p.DefaultAction {
		case "deny":
			hasDeny = true
		case "log":
			hasLog = true
		}
	}
	if hasDeny {
		return "deny"
	}
	if hasLog {
		return "log"
	}
	return "deny" // default to deny for security
}

func mergeVariableValues(a, b any) any {
	aSlice := toStringSlice(a)
	bSlice := toStringSlice(b)
	if aSlice == nil && bSlice == nil {
		return b
	}
	combined := append(aSlice, bSlice...)
	return dedupStrings(combined)
}

func dedupVariable(v any) any {
	sl := toStringSlice(v)
	if sl == nil {
		return v
	}
	return dedupStrings(sl)
}

func toStringSlice(v any) []string {
	switch val := v.(type) {
	case []string:
		return val
	case []any:
		var result []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}

func dedupStrings(items []string) []string {
	seen := make(map[string]bool, len(items))
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	sort.Strings(result)
	return result
}
