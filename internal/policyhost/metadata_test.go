package policyhost

import (
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/policymeta"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestMetadataTrustDefaultsAndCopies(t *testing.T) {
	m := policymeta.Observe(strings.Repeat("a", 64), 5, policymeta.EncodingJSON, [3]uint32{compiler.FieldBitPath, 0, compiler.FieldBitRemoteAddr | compiler.FieldBitRemotePort}, policymeta.StaticDomain{Eligible: true}, policymeta.StaticDomain{Eligible: true})
	h := &Host{metadata: m}
	if h.DecisionCacheEligible(0) || h.LinuxKernelCacheEligible(0) || !h.TimeDependent(0) || h.FieldsRead(0) != compiler.FieldsUnknown || h.StaticRulesProcess().Eligible {
		t.Fatal("guest observations trusted by default")
	}
	h.declarationsTrusted = true
	if !h.DecisionCacheEligible(0) || !h.LinuxKernelCacheEligible(0) || h.TimeDependent(0) || h.FieldsRead(0) != compiler.FieldBitPath || !h.StaticRulesProcess().Eligible {
		t.Fatal("explicit trust lost usable observations")
	}
	if h.DecisionCacheEligible(99) || h.FieldsRead(99) != compiler.FieldsUnknown {
		t.Fatal("unknown event optimized")
	}
	copy := h.Metadata()
	copy.Events[0].Flags = 0
	if !h.DecisionCacheEligible(api.EventTypeProcess) {
		t.Fatal("metadata aliases internal state")
	}
	var nilHost *Host
	if nilHost.FieldsRead(0) != compiler.FieldsUnknown || !nilHost.TimeDependent(0) || nilHost.StaticRulesNetwork().Eligible {
		t.Fatal("nil source optimized")
	}
}
