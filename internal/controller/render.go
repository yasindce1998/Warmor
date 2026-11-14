package controller

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/yasindce1998/warmor/internal/policymerge"
)

// The CRD's action vocabulary is allow/deny/audit; the daemon's policy
// schema is allow/deny/log. Audit (observe, do not enforce) is what the
// daemon calls log, so rendering translates between the two vocabularies.
var crdActionToDaemon = map[string]string{
	"allow": "allow",
	"deny":  "deny",
	"audit": "log",
}

// strictestCRAction orders default actions by restrictiveness:
// deny (block unmatched events) beats audit — the daemon's "log" —
// (observe unmatched events) beats allow. It accepts both vocabularies
// because rendered policies carry the daemon's. When several policies
// are merged into one effective policy, the strictest default wins, so
// merging can never quietly open a hole.
func strictestCRAction(actions []string) string {
	hasDeny, hasAudit := false, false
	for _, a := range actions {
		switch a {
		case "deny":
			hasDeny = true
		case "audit", "log":
			hasAudit = true
		}
	}
	switch {
	case hasDeny:
		return "deny"
	case hasAudit:
		return "log"
	default:
		return "allow"
	}
}

// actionRestrictiveness ranks daemon actions for merge ordering: rules
// are emitted most-restrictive-first (deny, then log, then allow) because
// the compiled policy is first-match-wins — an allow rule emitted before
// a deny rule from another WarmorPolicy would silently shadow the deny.
func actionRestrictiveness(action string) int {
	switch action {
	case "deny":
		return 0
	case "log":
		return 1
	default:
		return 2
	}
}

// variablePrefix is prepended to every variable a WarmorPolicy defines,
// so the same variable name in two policies cannot collide once the
// policies are merged into one file.
func variablePrefix(cr *WarmorPolicy) string {
	// Injectively encode the complete tuple, not a delimiter-joined name or
	// truncated hash. Hex also yields valid variable identifier characters.
	identity, _ := json.Marshal([]string{cr.Metadata.Namespace, cr.Metadata.Name, cr.Metadata.UID})
	return "cr_" + hex.EncodeToString(identity) + "__"
}

// renderPolicy converts a WarmorPolicy spec into the daemon's policy
// format. It is purely mechanical translation plus namespacing:
//   - actions map from the CRD vocabulary (allow/deny/audit) to the
//     daemon's (allow/deny/log);
//   - variables are keyed by namespace/name/UID and $-references inside
//     conditions are rewritten to match, so merged policies never share a
//     variable namespace;
//   - rule names are prefixed with "<namespace>/<policy>/<UID>/" so reasons stay
//     attributable when rules from several policies land in one module.
//
// Semantic validation (condition fields, operators, variables actually
// resolving, temporal constraints) is deliberately NOT done here — the
// merged result is run through the full compiler parser before it is
// compiled, which is the same check the daemon performs at load time.
func renderPolicy(cr *WarmorPolicy) (*policymerge.PolicyYAML, error) {
	if cr.Spec.Name == "" {
		return nil, fmt.Errorf("spec.name is required")
	}
	if cr.Spec.Version < 1 {
		return nil, fmt.Errorf("spec.version must be >= 1")
	}

	daemonDefault, ok := crdActionToDaemon[cr.Spec.DefaultAction]
	if !ok {
		return nil, fmt.Errorf("spec.defaultAction %q is invalid (allow, deny or audit)", cr.Spec.DefaultAction)
	}

	prefix := variablePrefix(cr)
	variables := make(map[string]any, len(cr.Spec.Variables))
	for name, value := range cr.Spec.Variables {
		rewritten, err := rewriteValue(value, prefix, cr.Spec.Variables)
		if err != nil {
			return nil, fmt.Errorf("variable %q: %w", name, err)
		}
		variables[prefix+name] = rewritten
	}

	rendered := &policymerge.PolicyYAML{
		Name:          cr.Spec.Name,
		Version:       cr.Spec.Version,
		Description:   cr.Spec.Description,
		Variables:     variables,
		DefaultAction: daemonDefault,
	}
	if len(rendered.Variables) == 0 {
		rendered.Variables = nil
	}

	for i, rule := range cr.Spec.Rules {
		action, ok := crdActionToDaemon[rule.Action]
		if !ok {
			return nil, fmt.Errorf("rules[%d].action %q is invalid (allow, deny or audit)", i, rule.Action)
		}
		if rule.Name == "" {
			return nil, fmt.Errorf("rules[%d].name is required", i)
		}
		renderedRule := policymerge.RuleYAML{
			Name:   cr.Metadata.Namespace + "/" + cr.Metadata.Name + "/" + cr.Metadata.UID + "/" + rule.Name,
			Event:  rule.Event,
			Action: action,
			Reason: rule.Reason,
		}
		if rule.Conditions != nil {
			var err error
			if renderedRule.Conditions.All, err = rewriteConditions(rule.Conditions.All, prefix, cr.Spec.Variables); err != nil {
				return nil, fmt.Errorf("rules[%d] %q: %w", i, rule.Name, err)
			}
			if renderedRule.Conditions.Any, err = rewriteConditions(rule.Conditions.Any, prefix, cr.Spec.Variables); err != nil {
				return nil, fmt.Errorf("rules[%d] %q: %w", i, rule.Name, err)
			}
		}
		rendered.Rules = append(rendered.Rules, renderedRule)
	}

	return rendered, nil
}

// rewriteConditions rewrites $variable references in raw condition maps
// to their namespaced names. Unknown references pass through for the
// compiler to reject; $$ escapes a literal leading dollar.
func rewriteConditions(conditions []map[string]any, prefix string, variables map[string]any) ([]map[string]any, error) {
	if len(conditions) == 0 {
		return nil, nil
	}
	out := make([]map[string]any, len(conditions))
	for i, cond := range conditions {
		rewritten, err := rewriteValue(cond, prefix, variables)
		if err != nil {
			return nil, fmt.Errorf("conditions[%d]: %w", i, err)
		}
		m, ok := rewritten.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("conditions[%d]: not a map", i)
		}
		out[i] = m
	}
	return out, nil
}

// rewriteValue walks a condition value (maps, slices, scalars) rewriting
// "$name" strings for names the policy defines. JSON-decoded input has
// map[string]any and []any containers; YAML round-trips are avoided by
// marshaling the merged policy once and letting the compiler parse it.
func rewriteValue(value any, prefix string, variables map[string]any) (any, error) {
	switch v := value.(type) {
	case string:
		if strings.HasPrefix(v, "$") && len(v) > 1 {
			name := v[1:]
			if _, defined := variables[name]; defined {
				return "$" + prefix + name, nil
			}
		}
		return v, nil
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			rewritten, err := rewriteValue(item, prefix, variables)
			if err != nil {
				return nil, err
			}
			out[k] = rewritten
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			rewritten, err := rewriteValue(item, prefix, variables)
			if err != nil {
				return nil, err
			}
			out[i] = rewritten
		}
		return out, nil
	default:
		return value, nil
	}
}

// effectivePolicy merges the rendered policies of every accepted CR into
// the single policy the agents run.
//
// Rules are always re-ordered most-restrictive-first (deny, then log,
// then allow; the compiled module is first-match-wins, so an allow
// emitted before another policy's deny would silently shadow it) and
// deterministically (source namespace/name, then rule order as written), and the
// effective default action is the strictest across the merged policies.
func effectivePolicy(name string, rendered []*policymerge.PolicyYAML) *policymerge.PolicyYAML {
	if len(rendered) == 0 {
		return nil
	}

	sorted := make([]*policymerge.PolicyYAML, len(rendered))
	copy(sorted, rendered)
	// Reconcile provides namespace/name order. spec.name is display metadata,
	// not a source identity, and must not influence composition order.

	defaults := make([]string, len(sorted))
	for i, p := range sorted {
		defaults[i] = p.DefaultAction
	}

	effective := &policymerge.PolicyYAML{
		Name:          name,
		Version:       1,
		DefaultAction: strictestCRAction(defaults),
	}
	if len(sorted) == 1 {
		// Keep display metadata, but use identical composition semantics
		// regardless of source count.
		effective.Version = sorted[0].Version
		effective.Description = sorted[0].Description
	} else {
		effective.Description = fmt.Sprintf("Effective policy merged from %d WarmorPolicy resources", len(sorted))
		for _, p := range sorted {
			if p.Version > effective.Version {
				effective.Version = p.Version
			}
		}
	}

	for _, p := range sorted {
		for k, v := range p.Variables {
			if effective.Variables == nil {
				effective.Variables = make(map[string]any)
			}
			effective.Variables[k] = v
		}
		effective.Rules = append(effective.Rules, p.Rules...)
	}

	// Adding a second CR must not change precedence inside an existing CR.
	sort.SliceStable(effective.Rules, func(i, j int) bool {
		return actionRestrictiveness(effective.Rules[i].Action) < actionRestrictiveness(effective.Rules[j].Action)
	})
	return effective
}
