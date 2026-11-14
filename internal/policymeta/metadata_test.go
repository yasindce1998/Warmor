package policymeta

import (
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/pkg/api"
)

func goodModule() Module {
	return Observe(strings.Repeat("a", 64), 5, EncodingJSON, [3]uint32{compiler.FieldBitPath, 0, compiler.FieldBitRemoteAddr | compiler.FieldBitRemotePort}, StaticDomain{Eligible: true, Rules: []compiler.StaticRule{{Event: "process", Pattern: "/bin/tool", Action: 1, Audit: true}}}, StaticDomain{Eligible: true, Rules: []compiler.StaticRule{{Event: "network", Pattern: "2001:db8::1", Port: 443, Action: 0, Audit: true}}})
}

func TestMetadataBoundsAndAmbiguity(t *testing.T) {
	m := goodModule()
	if err := m.Validate(m.ModuleSHA256); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Module){
		"missing events":         func(m *Module) { m.Events = nil },
		"duplicate event":        func(m *Module) { m.Events[1] = m.Events[0] },
		"missing domain":         func(m *Module) { m.Domains = m.Domains[:1] },
		"duplicate domain":       func(m *Module) { m.Domains[1] = m.Domains[0] },
		"unknown version":        func(m *Module) { m.Version++ },
		"unknown ABI":            func(m *Module) { m.ABIVersion = 6 },
		"missing ABI with flags": func(m *Module) { m.ABIVersion = 0 },
		"unknown encoding":       func(m *Module) { m.Encoding = "future" },
		"identity mismatch":      func(m *Module) { m.ModuleSHA256 = strings.Repeat("b", 64) },
		"unknown field bit":      func(m *Module) { m.Events[0].FieldsRead = 1 << 30 },
		"unknown flags":          func(m *Module) { m.Events[0].Flags |= 1 << 30 },
		"lying time flags":       func(m *Module) { m.Events[0].FieldsRead = compiler.FieldBitTime },
		"duplicate key":          func(m *Module) { m.Domains[0].Rules = append(m.Domains[0].Rules, m.Domains[0].Rules[0]) },
		"conflicting duplicate key": func(m *Module) {
			r := m.Domains[0].Rules[0]
			r.Action = 0
			r.Audit = false
			m.Domains[0].Rules = append(m.Domains[0].Rules, r)
		},
		"too many rules":     func(m *Module) { m.Domains[0].Rules = make([]compiler.StaticRule, MaxStaticRules+1) },
		"long pattern":       func(m *Module) { m.Domains[0].Rules[0].Pattern = strings.Repeat("x", MaxPatternBytes+1) },
		"NUL":                func(m *Module) { m.Domains[0].Rules[0].Pattern = "/bin/\x00tool" },
		"UTF8":               func(m *Module) { m.Domains[0].Rules[0].Pattern = "/bin/\xff" },
		"unknown action":     func(m *Module) { m.Domains[0].Rules[0].Action = 2 },
		"process port":       func(m *Module) { m.Domains[0].Rules[0].Port = 1 },
		"wrong event":        func(m *Module) { m.Domains[0].Rules[0].Event = "file" },
		"ineligible entries": func(m *Module) { m.Domains[0].Eligible = false },
		"non-key dependency": func(m *Module) {
			m.Events[0].FieldsRead = compiler.FieldBitUID
			m.Events[0].Flags = Flags(5, 0, compiler.FieldBitUID)
		},
		"endpoint alias":  func(m *Module) { m.Domains[1].Rules[0].Pattern = "2001:0db8:0:0:0:0:0:1" },
		"mapped endpoint": func(m *Module) { m.Domains[1].Rules[0].Pattern = "::ffff:127.0.0.1" },
		"endpoint zone":   func(m *Module) { m.Domains[1].Rules[0].Pattern = "fe80::1%eth0" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := m.Clone()
			mutate(&bad)
			if bad.Validate(m.ModuleSHA256) == nil {
				t.Fatal("accepted invalid metadata")
			}
		})
	}
}

func TestFiniteFlagsUnknownAndTemporal(t *testing.T) {
	for _, tc := range []struct {
		abi    uint32
		fields uint32
		flags  uint32
	}{
		{0, 0, 0}, {6, 0, 0}, {5, 1 << 30, 0},
		{5, compiler.FieldsUnknown, FlagTimeDependent | FlagContainerAge},
		{2, compiler.FieldsUnknown, 0},
		{5, compiler.FieldBitPath, FlagDecisionCache | FlagLinuxKernelKey},
		{5, compiler.FieldBitUID, FlagDecisionCache},
		{5, compiler.FieldBitTime, FlagTimeDependent},
	} {
		if got := Flags(tc.abi, api.EventTypeProcess, tc.fields); got != tc.flags {
			t.Fatalf("flags(%d,%x)=%x want %x", tc.abi, tc.fields, got, tc.flags)
		}
	}
	if Flags(5, 99, 0) != 0 {
		t.Fatal("unknown event optimized")
	}
	m := Observe(strings.Repeat("a", 64), 0, EncodingBinary, [3]uint32{0, 0, 0}, StaticDomain{Eligible: true}, StaticDomain{Eligible: true})
	if err := m.Validate(m.ModuleSHA256); err != nil {
		t.Fatal(err)
	}
	if m.Domains[0].Eligible || m.Events[0].Flags != 0 {
		t.Fatal("undeclared ABI optimized")
	}
}

func TestExactKeysCapacityAndDefensiveCopies(t *testing.T) {
	m := goodModule()
	// Distinct full paths must remain distinct even if a hash-only backend
	// would collide. No 32-bit fingerprint crosses this contract.
	a := compiler.StaticRule{Event: "process", Pattern: "/bin/costarring"}
	b := compiler.StaticRule{Event: "process", Pattern: "/bin/liquid"}
	ka, err := ValidateRule(0, a)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := ValidateRule(0, b)
	if err != nil || ka == kb {
		t.Fatal("lost exact identity")
	}
	m.Domains[1].Rules = append(m.Domains[1].Rules, compiler.StaticRule{Event: "network", Pattern: "2001:db8::1", Port: 444})
	if err := m.Validate(m.ModuleSHA256); err != nil {
		t.Fatal("distinct ports collide", err)
	}
	clone := m.Clone()
	clone.Domains[0].Rules[0].Audit = false
	clone.Events[0].FieldsRead = 0
	if !m.Domains[0].Rules[0].Audit || m.Events[0].FieldsRead == 0 {
		t.Fatal("clone aliases original")
	}
	d := Domain{Type: 0, StaticDomain: StaticDomain{Eligible: true}}
	for i := range MaxStaticRules {
		d.Rules = append(d.Rules, compiler.StaticRule{Event: "process", Pattern: "/bin/" + strings.Repeat("x", i/100) + string(rune(0x100+i))})
	}
	if err := ValidateDomain(d, compiler.FieldBitPath); err != nil {
		t.Fatal("capacity endpoint rejected", err)
	}
	d.Rules = append(d.Rules, a)
	if ValidateDomain(d, compiler.FieldBitPath) == nil {
		t.Fatal("capacity overflow accepted")
	}
}
