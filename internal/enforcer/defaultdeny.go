package enforcer

import (
	"fmt"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/ebpf"
	"github.com/yasindce1998/warmor/internal/kernelmap"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/wasm"
)

// defaultDenySyncer is implemented by policy maps whose kernel programs
// deny a policy-map miss in domains userspace has marked (the Linux
// default_deny map; see docs/design/kernel-default-deny.md).
type defaultDenySyncer interface {
	SetDefaultDeny(eventType uint8, mode uint8) error
	ClearDefaultDeny() error
}

// staticRulesSource is the evaluator's kernel default-deny declaration:
// the module's static-rules tables (compiler.StaticRulesExport).
type staticRulesSource interface {
	StaticRulesProcess() wasm.StaticDomain
	StaticRulesNetwork() wasm.StaticDomain
}

// applyDefaultDeny preloads the policy's static rules into the kernel
// policy map and marks the eligible domains default-deny. It runs at
// startup and after every policy reload, and is the only writer of the
// default-deny marking.
//
// Order matters: the marking is what flips a miss from allow to deny, so it
// goes in last. ClearDefaultDeny first (misses allow while rebuilding, i.e.
// exactly the behaviour without default-deny), then the policy map is
// cleared (by the caller, under the same decisionMu hold), then every
// static entry is preloaded for the global domain, then the domains are
// marked. Between the steps the worst state is the pre-default-deny
// behaviour; the marking itself is never present without its entries
// outside the preload window.
//
// The caller holds decisionMu exclusively (so no persistDecision can inter-
// leave) and passes the evaluator of the *current* policy generation.
func (e *Enforcer) applyDefaultDeny(src staticRulesSource) {
	metrics.SetDefaultDeny("exec", false)
	metrics.SetDefaultDeny("connect", false)

	dd, ok := e.policyMap.(defaultDenySyncer)
	if !ok {
		if e.defaultDeny {
			e.logger.LogInfo("Kernel default-deny unavailable: no default-deny capable policy map" +
				" (requires LSM enforcement; userspace enforcement is unchanged)")
		}
		return
	}

	// Unmark first: from here until the marking goes back in, misses allow.
	if err := dd.ClearDefaultDeny(); err != nil {
		e.logger.LogError(err, "clear kernel default-deny domains (old markings may remain)")
	}

	if !e.defaultDeny || e.learningMode {
		return
	}

	// Audit mode marks the domains audit-only: the kernel emits the miss for
	// userspace evaluation (the WASM policy denies it, since it defaults to
	// deny) and allows the operation through, so --audit is a faithful
	// rehearsal of default-deny.
	mode := uint8(ebpf.DefaultDenyModeDeny)
	if e.auditMode {
		mode = ebpf.DefaultDenyModeAudit
	}

	domains := []struct {
		name      string
		eventType uint8
		domain    wasm.StaticDomain
	}{
		{"exec", ebpf.EventTypeExec, src.StaticRulesProcess()},
		{"connect", ebpf.EventTypeNetwork, src.StaticRulesNetwork()},
	}

	for _, d := range domains {
		if !d.domain.Eligible {
			e.logger.LogInfo(fmt.Sprintf(
				"Kernel default-deny off for %s: the policy is not a complete allowlist"+
					" (needs default_action: deny and exact eq rules on the kernel key);"+
					" misses stay allowed", d.name))
			continue
		}
		if err := e.preloadDomain(dd, d.eventType, d.name, d.domain.Rules, mode); err != nil {
			e.logger.LogError(err, fmt.Sprintf("activate kernel default-deny for %s"+
				" (misses stay allowed)", d.name))
			continue
		}
		metrics.SetDefaultDeny(d.name, true)
		e.logger.LogInfo(fmt.Sprintf(
			"✓ Kernel default-deny active for %s (%d rules preloaded)", d.name, len(d.domain.Rules)))
	}
}

// preloadDomain writes every static rule of one domain into the kernel
// policy map and marks the domain. An entry that cannot be written must not
// be masked by a marking that denies its events, so any failure leaves the
// whole domain unmarked.
func (e *Enforcer) preloadDomain(dd defaultDenySyncer, eventType uint8, name string, rules []compiler.StaticRule, mode uint8) error {
	for _, r := range rules {
		if err := e.preloadStaticRule(r); err != nil {
			return fmt.Errorf("preload %s rule %q: %w", name, r.Pattern, err)
		}
	}
	if err := dd.SetDefaultDeny(eventType, mode); err != nil {
		return fmt.Errorf("mark the %s domain: %w", name, err)
	}
	return nil
}

// preloadStaticRule writes one static rule into the kernel policy map for
// the global (cgroup_id = 0) domain, keyed exactly as the BPF programs look
// it up.
func (e *Enforcer) preloadStaticRule(r compiler.StaticRule) error {
	audit := r.Audit
	action := r.Action // 0 allow, 1 deny — the policy map's encoding

	switch r.Event {
	case "process":
		return e.policyMap.SetRule(0, ebpf.EventTypeExec, r.Pattern, action, audit)
	case "network":
		ep, ok := e.policyMap.(endpointPolicyMapSyncer)
		if !ok {
			return fmt.Errorf("policy map cannot key endpoint rules: %w", kernelmap.ErrNotKernelMatchable)
		}
		return ep.SetEndpointRule(0, ebpf.EventTypeNetwork, r.Pattern, r.Port, action, audit)
	default:
		return fmt.Errorf("event %q has no default-deny domain", r.Event)
	}
}
