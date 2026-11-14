package learner

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/yasindce1998/warmor/internal/policymerge"
)

// Synthesize proposes path/endpoint allows, not an exact behavioral model.
// Session.MarshalPolicy rejects unsupported observations and validates output.
func Synthesize(profile *ContainerProfile, name string) *policymerge.PolicyYAML {
	if name == "" {
		name = fmt.Sprintf("learned-policy-cgroup-%d", profile.CgroupID)
	}

	var rules []policymerge.RuleYAML

	rules = append(rules, synthesizeExecRules(profile.Execs)...)
	rules = append(rules, synthesizeFileRules(profile.Files)...)
	rules = append(rules, synthesizeNetworkRules(profile.Networks)...)
	rules = append(rules, synthesizeBindRules(profile.Binds)...)
	rules = append(rules, synthesizeListenRules(profile.Listens)...)
	// Sanitization and truncation are not injective: preserve unique rule names.
	seen := make(map[string]bool)
	for i := range rules {
		base := rules[i].Name
		for n := 2; seen[rules[i].Name]; n++ {
			rules[i].Name = fmt.Sprintf("%s-%d", base, n)
		}
		seen[rules[i].Name] = true
	}

	return &policymerge.PolicyYAML{
		Name:          name,
		Version:       1,
		Description:   fmt.Sprintf("Auto-generated policy from observed behavior (cgroup %d)", profile.CgroupID),
		Rules:         rules,
		DefaultAction: "deny",
	}
}

// SynthesizeAll converts all profiles into a single merged policy.
func SynthesizeAll(profiles map[uint64]*ContainerProfile, name string) *policymerge.PolicyYAML {
	if name == "" {
		name = "learned-policy"
	}

	merged := newContainerProfile(0)
	for _, p := range profiles {
		for k, v := range p.Execs {
			merged.Execs[k] += v
		}
		for k, v := range p.Files {
			merged.Files[k] += v
		}
		for k, v := range p.Networks {
			merged.Networks[k] += v
		}
		for k, v := range p.Binds {
			merged.Binds[k] += v
		}
		for k, v := range p.Listens {
			merged.Listens[k] += v
		}
		for k, v := range p.Mounts {
			merged.Mounts[k] += v
		}
		for k, v := range p.Ptrace {
			merged.Ptrace[k] += v
		}
	}

	return Synthesize(merged, name)
}

func synthesizeExecRules(execs map[string]int) []policymerge.RuleYAML {
	paths := sortedKeys(execs)
	rules := make([]policymerge.RuleYAML, 0, len(paths))
	for _, path := range paths {
		rules = append(rules, policymerge.RuleYAML{
			Name:  fmt.Sprintf("allow-exec-%s", sanitizeName(path)),
			Event: "process",
			Conditions: policymerge.ConditionsYAML{
				All: []map[string]any{{"path": literal(path)}},
			},
			Action: "allow",
			Reason: fmt.Sprintf("observed %d times during learning", execs[path]),
		})
	}
	return rules
}

func synthesizeFileRules(files map[string]int) []policymerge.RuleYAML {
	paths := sortedKeys(files)
	rules := make([]policymerge.RuleYAML, 0, len(paths))
	for _, path := range paths {
		rules = append(rules, policymerge.RuleYAML{
			Name:  fmt.Sprintf("allow-file-%s", sanitizeName(path)),
			Event: "file",
			Conditions: policymerge.ConditionsYAML{
				All: []map[string]any{{"path": literal(path)}},
			},
			Action: "allow",
			Reason: fmt.Sprintf("observed %d times during learning", files[path]),
		})
	}
	return rules
}

func synthesizeNetworkRules(networks map[string]int) []policymerge.RuleYAML {
	keys := sortedKeys(networks)
	rules := make([]policymerge.RuleYAML, 0, len(keys))
	for _, key := range keys {
		operation, endpoint := splitOperation(key, "connect")
		parts := strings.SplitN(endpoint, ":", 2)
		if len(parts) != 2 {
			continue
		}
		// Accept both new bracketed IPv6 and historical unbracketed keys.
		last := strings.LastIndex(parts[1], ":")
		if last < 0 {
			continue
		}
		addr := strings.Trim(parts[1][:last], "[]")
		port, err := strconv.ParseUint(parts[1][last+1:], 10, 16)
		if err != nil {
			continue
		}
		conds := []map[string]any{
			{"operation": literal(operation)},
			{"protocol": literal(parts[0])},
			{"remote_addr": literal(addr)},
			{"remote_port": int(port)},
		}
		rules = append(rules, policymerge.RuleYAML{
			Name:  fmt.Sprintf("allow-connect-%s", sanitizeName(key)),
			Event: "network",
			Conditions: policymerge.ConditionsYAML{
				All: conds,
			},
			Action: "allow",
			Reason: fmt.Sprintf("observed %d times during learning", networks[key]),
		})
	}
	return rules
}

func synthesizeBindRules(binds map[string]int) []policymerge.RuleYAML {
	keys := sortedKeys(binds)
	rules := make([]policymerge.RuleYAML, 0, len(keys))
	for _, key := range keys {
		operation, endpoint := splitOperation(key, "connect") // historical bind evaluator operation
		parts := strings.SplitN(endpoint, ":", 2)
		if len(parts) != 2 {
			continue
		}
		port, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			continue
		}
		conds := []map[string]any{
			{"operation": literal(operation)},
			{"protocol": literal(parts[0])},
			{"local_port": int(port)},
		}
		rules = append(rules, policymerge.RuleYAML{
			Name:  fmt.Sprintf("allow-bind-%s", sanitizeName(key)),
			Event: "network",
			Conditions: policymerge.ConditionsYAML{
				All: conds,
			},
			Action: "allow",
			Reason: fmt.Sprintf("observed %d times during learning", binds[key]),
		})
	}
	return rules
}

func synthesizeListenRules(listens map[string]int) []policymerge.RuleYAML {
	keys := sortedKeys(listens)
	rules := make([]policymerge.RuleYAML, 0, len(keys))
	for _, key := range keys {
		operation, endpoint := splitOperation(key, "connect") // historical listen evaluator operation
		parts := strings.SplitN(endpoint, ":", 2)
		if len(parts) != 2 {
			continue
		}
		port, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			continue
		}
		conds := []map[string]any{
			{"operation": literal(operation)},
			{"protocol": literal(parts[0])},
			{"local_port": int(port)},
		}
		rules = append(rules, policymerge.RuleYAML{
			Name:  fmt.Sprintf("allow-listen-%s", sanitizeName(key)),
			Event: "network",
			Conditions: policymerge.ConditionsYAML{
				All: conds,
			},
			Action: "allow",
			Reason: fmt.Sprintf("observed %d times during learning", listens[key]),
		})
	}
	return rules
}

func splitOperation(key, fallback string) (string, string) {
	if op, endpoint, ok := strings.Cut(key, "|"); ok {
		return op, endpoint
	}
	return fallback, key
}

func literal(value string) string {
	if strings.HasPrefix(value, "$") {
		return "$" + value
	}
	return value
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sanitizeName(s string) string {
	r := strings.NewReplacer("/", "-", ":", "-", ".", "-", " ", "-")
	name := r.Replace(s)
	if len(name) > 60 {
		name = name[:60]
	}
	return strings.Trim(name, "-")
}
