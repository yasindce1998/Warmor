// Package policymeta defines bounded policy observations shared by in-process
// evaluators and the supervised host. It contains no WASM parser or runtime.
package policymeta

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/pkg/api"
)

const (
	Version             = 1
	MaxStaticRules      = 4096 // total across both domains, below kernel map capacity
	MaxPatternBytes     = 254
	MaxStaticTableBytes = 1 + MaxStaticRules*(6+MaxPatternBytes)
	KnownFields         = compiler.FieldBitContainerAge*2 - 1
	TemporalFields      = compiler.FieldBitTime | compiler.FieldBitContainerAge
	EncodingBinary      = "binary"
	EncodingJSON        = "json"
)

const (
	FlagDecisionCache uint32 = 1 << iota
	FlagTimeDependent
	FlagContainerAge
	// FlagLinuxKernelKey means dependencies fit the Linux exec/endpoint key.
	// It is not permission to install rules, nor a claim about other platforms.
	FlagLinuxKernelKey
)

var ErrMetadata = errors.New("invalid policy metadata")

type StaticDomain struct {
	Eligible bool
	Rules    []compiler.StaticRule
}

// Source is the metadata surface available to a future evaluator interface.
// Existing wasm.PolicyEvaluator and policyhost.Host both implement it. Effective
// optimizations on Host additionally require explicit module-digest trust.
type Source interface {
	Metadata() Module
	FieldsRead(api.EventType) uint32
	TimeDependent(api.EventType) bool
	ReadsContainerAge(api.EventType) bool
	StaticRulesProcess() StaticDomain
	StaticRulesNetwork() StaticDomain
	DecisionCacheEligible(api.EventType) bool
	LinuxKernelCacheEligible(api.EventType) bool
}

// Module contains worker observations, NOT proof that arbitrary guest declarations
// are exhaustive or stateless. Flags are derived and independently checked; they
// only describe structural eligibility under truthful-declaration assumptions.
type Module struct {
	Version      uint32
	ModuleSHA256 string
	ABIVersion   uint32 // 0 means absent, never an inferred ABI version
	Encoding     string // selected entry point, not a guest-provided string
	Events       []Event
	Domains      []Domain
}
type Event struct {
	Type       api.EventType
	FieldsRead uint32
	Flags      uint32
}
type Domain struct {
	Type api.EventType
	StaticDomain
}

func ValidDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func ValidFields(mask uint32) bool {
	return mask == compiler.FieldsUnknown || mask & ^uint32(KnownFields) == 0
}
func KernelFields(t api.EventType) uint32 {
	switch t {
	case api.EventTypeProcess:
		return compiler.FieldBitPath
	case api.EventTypeNetwork:
		return compiler.FieldBitRemoteAddr | compiler.FieldBitRemotePort
	default:
		return 0
	}
}
func Flags(abi uint32, t api.EventType, fields uint32) uint32 {
	if abi == 0 || abi > 5 || t < api.EventTypeProcess || t > api.EventTypeNetwork || !ValidFields(fields) {
		return 0
	}
	var flags uint32
	if abi >= 3 && fields&TemporalFields != 0 {
		flags |= FlagTimeDependent
	}
	if abi >= 3 && fields&compiler.FieldBitContainerAge != 0 {
		flags |= FlagContainerAge
	}
	if fields != compiler.FieldsUnknown && flags&FlagTimeDependent == 0 {
		flags |= FlagDecisionCache
		if key := KernelFields(t); key != 0 && fields & ^key == 0 {
			flags |= FlagLinuxKernelKey
		}
	}
	return flags
}

// RuleKey preserves complete keys rather than hashes. Endpoint text must match
// the sensor's canonical rendering: normalizing an alias would change string-eq
// guest semantics. Duplicate canonical endpoints/paths must never overwrite a
// first-match result (including its action and audit mode).
type RuleKey struct {
	Type    api.EventType
	Pattern string
	Port    uint16
}

func ValidateRule(t api.EventType, r compiler.StaticRule) (RuleKey, error) {
	if r.Action > 1 || r.Pattern == "" || len(r.Pattern) > MaxPatternBytes || !utf8.ValidString(r.Pattern) || strings.IndexByte(r.Pattern, 0) >= 0 {
		return RuleKey{}, ErrMetadata
	}
	switch t {
	case api.EventTypeProcess:
		if r.Event != "process" || r.Port != 0 {
			return RuleKey{}, ErrMetadata
		}
	case api.EventTypeNetwork:
		addr, err := netip.ParseAddr(r.Pattern)
		if r.Event != "network" || err != nil || addr.Zone() != "" || addr.Is4In6() || addr.String() != r.Pattern {
			return RuleKey{}, ErrMetadata
		}
	default:
		return RuleKey{}, ErrMetadata
	}
	return RuleKey{Type: t, Pattern: r.Pattern, Port: r.Port}, nil
}

func ValidateDomain(d Domain, fields uint32) error {
	if d.Type != api.EventTypeProcess && d.Type != api.EventTypeNetwork || len(d.Rules) > MaxStaticRules {
		return ErrMetadata
	}
	if !d.Eligible {
		if len(d.Rules) != 0 {
			return ErrMetadata
		}
		return nil
	}
	if fields == compiler.FieldsUnknown || !ValidFields(fields) || fields & ^KernelFields(d.Type) != 0 {
		return ErrMetadata
	}
	seen := make(map[RuleKey]bool, len(d.Rules))
	for _, r := range d.Rules {
		key, err := ValidateRule(d.Type, r)
		if err != nil || seen[key] {
			return ErrMetadata
		}
		seen[key] = true
	}
	return nil
}

func (m Module) Validate(expectedDigest string) error {
	if m.Version != Version || !ValidDigest(m.ModuleSHA256) || m.ModuleSHA256 != expectedDigest || m.ABIVersion > 5 || m.Encoding != EncodingBinary && m.Encoding != EncodingJSON || len(m.Events) != 3 || len(m.Domains) != 2 {
		return ErrMetadata
	}
	for i, e := range m.Events {
		if e.Type != api.EventType(i) || !ValidFields(e.FieldsRead) || e.Flags != Flags(m.ABIVersion, e.Type, e.FieldsRead) {
			return ErrMetadata
		}
	}
	if m.Domains[0].Type != api.EventTypeProcess || m.Domains[1].Type != api.EventTypeNetwork || len(m.Domains[0].Rules)+len(m.Domains[1].Rules) > MaxStaticRules {
		return ErrMetadata
	}
	for _, d := range m.Domains {
		if m.ABIVersion == 0 && d.Eligible {
			return ErrMetadata
		}
		if err := ValidateDomain(d, m.Events[d.Type].FieldsRead); err != nil {
			return err
		}
	}
	return nil
}

func (m Module) Clone() Module {
	m.Events = append([]Event(nil), m.Events...)
	m.Domains = append([]Domain(nil), m.Domains...)
	for i := range m.Domains {
		m.Domains[i].Rules = append([]compiler.StaticRule(nil), m.Domains[i].Rules...)
	}
	return m
}

// Observe sanitizes unusable guest declarations to conservative unknown/empty
// observations. Identity and actual ABI must still validate before publication.
func Observe(digest string, abi uint32, encoding string, fields [3]uint32, process, network StaticDomain) Module {
	m := Module{Version: Version, ModuleSHA256: digest, ABIVersion: abi, Encoding: encoding}
	for t, f := range fields {
		if !ValidFields(f) {
			f = compiler.FieldsUnknown
		}
		typ := api.EventType(t)
		m.Events = append(m.Events, Event{Type: typ, FieldsRead: f, Flags: Flags(abi, typ, f)})
	}
	for i, d := range []StaticDomain{process, network} {
		t := api.EventTypeProcess
		if i == 1 {
			t = api.EventTypeNetwork
		}
		domain := Domain{Type: t, StaticDomain: d}
		if abi == 0 || ValidateDomain(domain, m.Events[t].FieldsRead) != nil {
			domain.StaticDomain = StaticDomain{}
		}
		m.Domains = append(m.Domains, domain)
	}
	if len(m.Domains[0].Rules)+len(m.Domains[1].Rules) > MaxStaticRules {
		for i := range m.Domains {
			m.Domains[i].StaticDomain = StaticDomain{}
		}
	}
	return m.Clone()
}
