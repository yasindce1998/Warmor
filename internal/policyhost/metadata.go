package policyhost

import (
	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/policymeta"
	"github.com/yasindce1998/warmor/pkg/api"
)

var _ policymeta.Source = (*Host)(nil)

// Metadata returns observations authenticated by the pinned trusted worker and
// module digest, NOT a proof of guest honesty. Use the conservative effective
// methods below for routing; never enable caching from raw observation flags.
func (h *Host) Metadata() policymeta.Module {
	if h == nil {
		return policymeta.Module{}
	}
	return h.metadata.Clone()
}

func (h *Host) eventMetadata(t api.EventType) (policymeta.Event, bool) {
	if h == nil || t < api.EventTypeProcess || t > api.EventTypeNetwork || len(h.metadata.Events) != 3 {
		return policymeta.Event{}, false
	}
	return h.metadata.Events[t], true
}
func (h *Host) FieldsRead(t api.EventType) uint32 {
	e, ok := h.eventMetadata(t)
	if !ok || !h.declarationsTrusted || h.metadata.ABIVersion == 0 {
		return compiler.FieldsUnknown
	}
	return e.FieldsRead
}
func (h *Host) DecisionCacheEligible(t api.EventType) bool {
	e, ok := h.eventMetadata(t)
	return ok && h.declarationsTrusted && e.Flags&policymeta.FlagDecisionCache != 0
}
func (h *Host) LinuxKernelCacheEligible(t api.EventType) bool {
	e, ok := h.eventMetadata(t)
	return ok && h.declarationsTrusted && e.Flags&policymeta.FlagLinuxKernelKey != 0
}

// TimeDependent is deliberately true when optimizations are not authorized,
// preserving the legacy cache interface's "do not cache" behavior. Raw actual
// temporal dependence remains available in Metadata, independent of trust.
func (h *Host) TimeDependent(t api.EventType) bool { return !h.DecisionCacheEligible(t) }
func (h *Host) ReadsContainerAge(t api.EventType) bool {
	e, ok := h.eventMetadata(t)
	if !ok {
		return true
	}
	// Untrusted guest masks must not suppress context enrichment either.
	// ABI <3 never receives age; ABI >=3 may read it despite claiming not to.
	if !h.declarationsTrusted {
		return h.metadata.ABIVersion >= 3
	}
	return e.Flags&policymeta.FlagContainerAge != 0
}
func (h *Host) staticDomain(index int) policymeta.StaticDomain {
	if h == nil || !h.declarationsTrusted || len(h.metadata.Domains) != 2 {
		return policymeta.StaticDomain{}
	}
	return h.metadata.Clone().Domains[index].StaticDomain
}
func (h *Host) StaticRulesProcess() policymeta.StaticDomain { return h.staticDomain(0) }
func (h *Host) StaticRulesNetwork() policymeta.StaticDomain { return h.staticDomain(1) }
