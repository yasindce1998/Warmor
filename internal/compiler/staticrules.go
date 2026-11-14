package compiler

import (
	"fmt"
	"net"
	"strings"
	"unicode/utf8"

	"github.com/yasindce1998/warmor/internal/kernelmap"
)

// StaticRulesExport is the name of the exported static-rules table.
//
//	warmor_static_rules(event_type: u32, buf: *mut u8, cap: u32) -> u32
//
// It returns the table's byte size and, when cap >= size, copies it to buf.
// The host uses it to preload the kernel policy map and mark default-deny
// domains (docs/design/kernel-default-deny.md). The table is
//
//	[eligible u8][entry]*
//
// where an entry is [action u8][audit u8][port u16][len u16][pattern bytes]
// (port is 0 for process rules, host byte order for network rules). A module
// without the export, or an empty/ineligible table, is simply never marked.
const StaticRulesExport = "warmor_static_rules"

// StaticRule is one exactly-enumerable policy rule, as preloaded into the
// kernel policy map for the global (cgroup_id = 0) domain.
type StaticRule struct {
	// Event is the YAML event name: "process" or "network".
	Event string
	// Action is 0 (allow) or 1 (deny), matching the policy map value.
	Action uint8
	// Audit marks a would-deny (mode: audit) or log rule.
	Audit bool
	// Pattern is the exec path for process rules, the remote address for
	// network rules.
	Pattern string
	// Port is the remote port (host byte order) for network rules.
	Port uint16
}

// StaticRules analyses a policy for kernel default-deny eligibility, per
// event type ("process" = exec, "network" = connect).
//
// A domain is eligible when its policy-map entries can be a *complete*
// allowlist: the policy defaults to deny, and every rule for the event type
// is exactly enumerable — only eq conditions on the kernel key fields (path
// for process; remote_addr and remote_port, both required, for network), no
// glob/starts_with/contains/not/any_of/none_of, no other fields, no temporal
// block — and its pattern fits the shared exact-input contract. For an
// eligible domain it returns the rules in declaration order; duplicate keys
// keep the first rule, matching the WASM's first-match semantics. An
// ineligible domain contributes no rules (and its table is emitted with
// eligible=0).
//
// The returned error slice holds one human-readable reason per ineligible
// domain that has at least one rule, for logging why default-deny is off.
func StaticRules(policy *Policy) (rules []StaticRule, ineligible map[string]string) {
	ineligible = map[string]string{}
	for _, event := range []string{"process", "network"} {
		domainRules, reason := staticRulesForEvent(policy, event)
		if reason != "" {
			if len(rulesForEvent(policy, event)) > 0 {
				ineligible[event] = reason
			}
			continue
		}
		rules = append(rules, domainRules...)
	}
	return rules, ineligible
}

// staticRulesForEvent returns the domain's static rules, or the reason the
// domain is not eligible ("" means eligible, even with no rules: a default
// deny policy with no network rules denies every connect).
func staticRulesForEvent(policy *Policy, event string) (rules []StaticRule, reason string) {
	if policy.DefaultAction != "deny" {
		return nil, fmt.Sprintf("default_action is %q, not deny", policy.DefaultAction)
	}

	seen := map[string]bool{}
	for _, r := range rulesForEvent(policy, event) {
		sr, err := staticRule(r, event)
		if err != nil {
			return nil, fmt.Sprintf("rule %q: %v", r.Name, err)
		}
		// First match wins in the WASM evaluator, so a later rule on the
		// same key is dead there and must not overwrite the entry.
		key := sr.patternKey()
		if seen[key] {
			continue
		}
		seen[key] = true
		rules = append(rules, sr)
	}
	return rules, ""
}

// staticRule converts one rule to its preloadable form, or reports why it
// cannot be enumerated exactly.
func staticRule(r Rule, event string) (StaticRule, error) {
	if r.Temporal != nil {
		return StaticRule{}, fmt.Errorf("temporal block")
	}
	if len(r.Conditions.Any) > 0 || len(r.Conditions.Not) > 0 {
		return StaticRule{}, fmt.Errorf("conditions.any/not are not exactly enumerable")
	}

	sr := StaticRule{Event: event}
	switch r.Action {
	case "allow":
		sr.Action = 0
	case "deny":
		sr.Action = 1
	case "log":
		// log = allow, but audited — the policy map's allow+audit encoding.
		sr.Action = 0
		sr.Audit = true
	default:
		return StaticRule{}, fmt.Errorf("action %q", r.Action)
	}
	if r.Mode == "audit" && r.Action == "deny" {
		sr.Audit = true
	}

	// Collect the eq conditions by field; anything else disqualifies.
	eq := map[string]any{}
	for _, c := range r.Conditions.All {
		if c.Operator != "eq" {
			return StaticRule{}, fmt.Errorf("%s condition on %s is not eq", c.Operator, c.Field)
		}
		if _, dup := eq[c.Field]; dup {
			return StaticRule{}, fmt.Errorf("duplicate condition on %s", c.Field)
		}
		eq[c.Field] = c.Value
	}

	switch event {
	case "process":
		if len(eq) != 1 {
			return StaticRule{}, fmt.Errorf("must have exactly one path eq condition")
		}
		path, ok := eq["path"].(string)
		if !ok {
			return StaticRule{}, fmt.Errorf("path condition is not a string")
		}
		// The sensor and binary WASM ABI must both see the entire path.
		if path == "" || len(path) > kernelmap.MaxPolicyPathBytes || strings.IndexByte(path, 0) >= 0 || !utf8.ValidString(path) {
			return StaticRule{}, fmt.Errorf("path %q is not kernel-matchable", path)
		}
		sr.Pattern = path
	case "network":
		if len(eq) != 2 {
			return StaticRule{}, fmt.Errorf("must have exactly remote_addr and remote_port eq conditions")
		}
		addr, ok := eq["remote_addr"].(string)
		if !ok {
			return StaticRule{}, fmt.Errorf("remote_addr condition is not a string")
		}
		ip := net.ParseIP(addr)
		if ip == nil || ip.String() != addr {
			return StaticRule{}, fmt.Errorf("remote_addr %q is not a canonical sensor IP", addr)
		}
		port, ok := toPort(eq["remote_port"])
		if !ok {
			return StaticRule{}, fmt.Errorf("remote_port condition is not a port number")
		}
		sr.Pattern = addr
		sr.Port = port
	default:
		return StaticRule{}, fmt.Errorf("event %q has no default-deny domain", event)
	}
	return sr, nil
}

// toPort converts a YAML port value (int or float64 from the decoder) to a
// host-byte-order uint16.
func toPort(v any) (uint16, bool) {
	switch p := v.(type) {
	case int:
		if p >= 0 && p <= 65535 {
			return uint16(p), true
		}
	case int64:
		if p >= 0 && p <= 65535 {
			return uint16(p), true
		}
	case float64:
		if p == float64(int64(p)) && p >= 0 && p <= 65535 {
			return uint16(int64(p)), true
		}
	}
	return 0, false
}

// patternKey identifies the policy-map entry the rule compiles to.
func (sr StaticRule) patternKey() string {
	return fmt.Sprintf("%s/%d/%s", sr.Event, sr.Port, sr.Pattern)
}

// encodeStaticRules serializes a domain's rules into the export table
// format: [eligible u8] followed by entries
// [action u8][audit u8][port u16 LE][len u16 LE][pattern bytes]. An
// ineligible domain encodes as the single byte 0.
func encodeStaticRules(rules []StaticRule, event string, eligible bool) []byte {
	buf := []byte{0}
	if !eligible {
		return buf
	}
	buf[0] = 1
	for _, r := range rules {
		if r.Event != event {
			continue
		}
		audit := uint8(0)
		if r.Audit {
			audit = 1
		}
		buf = append(buf, r.Action, audit)
		buf = append(buf, byte(r.Port), byte(r.Port>>8))
		pattern := []byte(r.Pattern)
		buf = append(buf, byte(len(pattern)), byte(len(pattern)>>8))
		buf = append(buf, pattern...)
	}
	return buf
}

// rustByteSlice renders buf as a Rust byte-array literal.
func rustByteSlice(buf []byte) string {
	var b strings.Builder
	b.WriteString("&[")
	for i, x := range buf {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%d", x)
	}
	b.WriteString("]")
	return b.String()
}
