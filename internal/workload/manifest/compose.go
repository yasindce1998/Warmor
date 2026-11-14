package manifest

import (
	"encoding/json"
	"errors"
	"sort"

	"github.com/opencontainers/go-digest"
	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/workload"
)

type Scope string

const (
	VerifiedPod Scope = "verified-pod"
	Unknown     Scope = "unknown"
	KnownHost   Scope = "known-host"
)

// Selection is an immutable preparation result, NOT an active evaluator lease.
// Matched distinguishes verified no-match from all unavailable/host handling.
type Selection struct {
	manifest  digest.Digest
	digest    digest.Digest
	scope     Scope
	matched   bool
	auditOnly bool
	sources   []Source
}

func (s Selection) Digest() digest.Digest { return s.digest }
func (s Selection) Scope() Scope          { return s.scope }
func (s Selection) Matched() bool         { return s.matched }
func (s Selection) AuditOnly() bool       { return s.auditOnly }
func (s Selection) Sources() []Source {
	var out []Source
	data, _ := json.Marshal(s.sources)
	_ = json.Unmarshal(data, &out)
	return out
}

// SelectPod accepts only an immutable corroborated identity plus Verified reason.
// Unknown/stale identity must use SelectUnknown instead, never an empty-label Pod.
// The caller still owns freshness and epoch/lifetime fencing at activation time.
func (m *Manifest) SelectPod(identity workload.Identity, reason workload.Reason) (Selection, error) {
	if !m.valid() || reason != workload.Verified || identity.PodUID() == "" {
		return Selection{}, errors.New("verified Pod identity required")
	}
	sources := []Source{*m.doc.Baseline}
	selected := m.catalog.Select(identity)
	for _, p := range selected {
		for _, a := range m.doc.Additions {
			if reference(a.Source) == p {
				sources = append(sources, a.Source)
				break
			}
		}
	}
	return m.selection(VerifiedPod, len(selected) > 0, false, sources), nil
}

func (m *Manifest) SelectUnknown() (Selection, error) { return m.selectScope(Unknown) }

// SelectKnownHost requires positive host evidence supplied by the router. A
// failed Pod lookup is never evidence of known host.
func (m *Manifest) SelectKnownHost() (Selection, error) { return m.selectScope(KnownHost) }
func (m *Manifest) selectScope(scope Scope) (Selection, error) {
	if !m.valid() {
		return Selection{}, errors.New("manifest required")
	}
	h := m.doc.Unknown
	if scope == KnownHost {
		h = m.doc.KnownHost
	}
	var sources []Source
	if h.Baseline != nil {
		sources = []Source{*h.Baseline}
	}
	return m.selection(scope, false, h.Mode == "audit-only", sources), nil
}
func (m *Manifest) selection(scope Scope, matched, audit bool, sources []Source) Selection {
	data, _ := json.Marshal(struct {
		Manifest digest.Digest `json:"manifest"`
		Scope    Scope         `json:"scope"`
		Sources  []Source      `json:"sources"`
	}{m.digest, scope, sources})
	return Selection{manifest: m.digest, digest: digest.FromBytes(data), scope: scope, matched: matched, auditOnly: audit, sources: sources}
}

// Generation is one typed program, to be compiled ONCE and routed exclusively to
// this selection. Never combine independently compiled first-match verdicts.
type Generation struct {
	digest    digest.Digest
	selection digest.Digest
	abi       uint32
	policy    *compiler.Policy
}

func (g *Generation) Digest() digest.Digest          { return g.digest }
func (g *Generation) SelectionDigest() digest.Digest { return g.selection }
func (g *Generation) ABI() uint32                    { return g.abi }

// Policy returns a deep copy suitable for compiler.GenerateRust/Build. Mutating
// it cannot change the immutable generation or its content hash.
func (g *Generation) Policy() *compiler.Policy {
	data, _ := json.Marshal(g.policy)
	var p compiler.Policy
	_ = json.Unmarshal(data, &p)
	return &p
}

// Build compiles a private typed copy into ONE first-match program. Publication
// must additionally content-address the returned WASM bytes, verify the actual
// module ABI with the daemon loader, and bind it to this generation's digest.
// This helper does not publish, install, or claim Applied status.
func (g *Generation) Build(opts compiler.BuildOptions) (*compiler.BuildResult, error) {
	if g == nil || g.policy == nil {
		return nil, errors.New("compiled generation required")
	}
	return compiler.Build(g.Policy(), opts)
}

func (b *Bundle) Compose(s Selection) (*Generation, error) {
	if b == nil || !b.manifest.valid() || s.manifest == "" || s.manifest != b.manifest.digest || s.digest == "" || len(s.sources) == 0 || s.auditOnly {
		return nil, errors.New("selection cannot produce an enforcing generation")
	}
	p := &compiler.Policy{Name: "workload-composition", Version: 1}
	for i, source := range s.sources {
		entry, ok := b.policies[sourceKey(source)]
		if !ok {
			return nil, errors.New("selection source unavailable")
		}
		if i == 0 {
			p.DefaultAction = entry.policy.DefaultAction
		}
		p.Rules = append(p.Rules, entry.policy.Rules...)
	}
	// Stable within each class: baseline first, additions namespace+UID sorted,
	// then original rule order. Enforcing denies ALWAYS precede audit/log/allow.
	sort.SliceStable(p.Rules, func(i, j int) bool { return rank(p.Rules[i]) < rank(p.Rules[j]) })
	if err := p.Validate(); err != nil {
		return nil, errors.New("invalid effective composition")
	}
	data, err := json.Marshal(p)
	if err != nil || len(data) > MaxBundleBytes {
		return nil, errors.New("effective composition budget exceeded")
	}
	abi := exactABI(p)
	key, _ := json.Marshal(struct {
		Selection   digest.Digest `json:"selection"`
		Compiler    string        `json:"compiler"`
		ABI         uint32        `json:"abi"`
		Composition string        `json:"composition"`
		Posture     string        `json:"posture"`
		Policy      digest.Digest `json:"policy"`
	}{s.digest, compiler.Version, abi, CompositionVersion, Posture, digest.FromBytes(data)})
	return &Generation{digest: digest.FromBytes(key), selection: s.digest, abi: abi, policy: p}, nil
}

func rank(r compiler.Rule) int {
	if r.Action == "deny" {
		if r.Mode != "audit" {
			return 0
		}
		return 1
	}
	if r.Action == "log" {
		return 2
	}
	return 3
}
