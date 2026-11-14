package wasm

import (
	"github.com/yasindce1998/warmor/internal/policymeta"
	"github.com/yasindce1998/warmor/pkg/api"
)

var _ policymeta.Source = (*PolicyEvaluator)(nil)

// Metadata returns a defensive snapshot of actual loaded identity/ABI and
// structurally usable declarations. It does not prove guest declarations are
// exhaustive; legacy in-process FieldsRead/StaticRules methods retain their
// original trust semantics for compatibility until explicit enforcer migration.
func (p *Pool) Metadata() policymeta.Module {
	if p == nil {
		return policymeta.Module{}
	}
	return p.metadata.Clone()
}

func (e *PolicyEvaluator) Metadata() policymeta.Module {
	if e == nil {
		return policymeta.Module{}
	}
	return e.pool.Metadata()
}

// Eligibility methods preserve the legacy assumption that in-process guest
// declarations are publisher-trusted, but decline absent/unknown ABI, unknown
// fields and temporal dependencies. They do not alter existing enforcer wiring.
func (e *PolicyEvaluator) DecisionCacheEligible(t api.EventType) bool {
	if e == nil || e.pool == nil || t < api.EventTypeProcess || t > api.EventTypeNetwork || len(e.pool.metadata.Events) != 3 {
		return false
	}
	return e.pool.metadata.Events[t].Flags&policymeta.FlagDecisionCache != 0
}

func (e *PolicyEvaluator) LinuxKernelCacheEligible(t api.EventType) bool {
	if e == nil || e.pool == nil || t < api.EventTypeProcess || t > api.EventTypeNetwork || len(e.pool.metadata.Events) != 3 {
		return false
	}
	return e.pool.metadata.Events[t].Flags&policymeta.FlagLinuxKernelKey != 0
}
