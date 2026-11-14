package wasm

import (
	"context"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/policymeta"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
)

func TestMetadataSanitizesMalformedGuestDeclarations(t *testing.T) {
	for _, mask := range []uint32{1 << 30, compiler.FieldsUnknown} {
		pool := newPoolFromBytes(t, wasmtest.AgeKnownPolicy(&[3]uint32{mask, mask, mask}), 1)
		m := pool.Metadata()
		if err := m.Validate(m.ModuleSHA256); err != nil {
			t.Fatal(err)
		}
		if m.Events[0].FieldsRead != compiler.FieldsUnknown || m.Events[0].Flags&policymeta.FlagDecisionCache != 0 {
			t.Fatal("unknown field declaration optimized")
		}
	}
	for name, table := range map[string][]byte{
		"invalid eligibility": {2},
		"ineligible trailing": {0, 0},
		"empty path":          {1, 0, 0, 0, 0, 0, 0},
		"excess count":        append([]byte{1}, make([]byte, policymeta.MaxStaticTableBytes)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, eligible, err := parseStaticTable(table, 0); err == nil && eligible {
				t.Fatal("malformed static table eligible")
			}
		})
	}
	// Valid byte-level framing but contradictory full keys: observations must
	// decline rather than collapse first-match audit/action semantics.
	rules := []compiler.StaticRule{{Event: "process", Pattern: "/bin/tool"}, {Event: "process", Pattern: "/bin/tool", Action: 1, Audit: true}}
	m := policymeta.Observe(strings.Repeat("a", 64), 5, policymeta.EncodingBinary, [3]uint32{compiler.FieldBitPath, 0, 0}, StaticDomain{Eligible: true, Rules: rules}, StaticDomain{})
	if m.Domains[0].Eligible {
		t.Fatal("duplicate guest rules promoted")
	}
}

func TestMetadataActualUnknownABIFailsLoad(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	// Replace the fixture's actual abi_version return from 3 to 6 without
	// providing any separate policy-supplied metadata document.
	module := wasmtest.AgeKnownPolicy(nil)
	for i := len(module) - 3; i >= 0; i-- {
		if module[i] == 0x41 && module[i+1] == 3 && module[i+2] == 0x0b {
			module[i+1] = 6
			break
		}
	}
	if err := rt.LoadPolicyBytes(ctx, module); err == nil {
		t.Fatal("future ABI published metadata")
	}
}
