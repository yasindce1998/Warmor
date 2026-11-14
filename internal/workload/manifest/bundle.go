package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/opencontainers/go-digest"
	"github.com/yasindce1998/warmor/internal/compiler"
	"gopkg.in/yaml.v3"
)

type prepared struct {
	policy *compiler.Policy
}

// Bundle owns resolved, validated typed policies, not raw YAML. Construction
// consumes only explicitly supplied local bytes; no network or disk access.
// Callers must authenticate publication BEFORE constructing/trusting a bundle.
type Bundle struct {
	manifest *Manifest
	policies map[string]prepared
}

// NewBundle validates a complete immutable publication. The caller retains the
// byte inputs, but must not mutate them concurrently during construction.
func NewBundle(m *Manifest, artifacts map[digest.Digest][]byte) (*Bundle, error) {
	if !m.valid() {
		return nil, errors.New("manifest required")
	}
	all := []Source{*m.doc.Baseline}
	for _, s := range []ScopeHandling{m.doc.Unknown, m.doc.KnownHost} {
		if s.Baseline != nil {
			all = append(all, *s.Baseline)
		}
	}
	for _, a := range m.doc.Additions {
		all = append(all, a.Source)
	}
	want := map[digest.Digest]bool{}
	for _, s := range all {
		want[s.Artifact.Digest] = true
	}
	if len(artifacts) != len(want) {
		return nil, errors.New("bundle must contain exactly referenced artifacts")
	}
	b := &Bundle{manifest: m, policies: map[string]prepared{}}
	budget := expansionBudget{values: 65536, bytes: MaxBundleBytes}
	// Preflight EVERY source against one bundle-wide expansion budget before
	// compiler.Parse can allocate any resolved operands. Post-parse JSON sizes
	// remain defense in depth, never the first expansion/resource boundary.
	for _, s := range all {
		raw, ok := artifacts[s.Artifact.Digest]
		if !ok || len(raw) != s.Artifact.Size || len(raw) > MaxArtifactBytes || digest.FromBytes(raw) != s.Artifact.Digest {
			return nil, errors.New("missing source artifact or size/digest mismatch")
		}
		if err := preflightSource(raw, &budget); err != nil {
			return nil, fmt.Errorf("source %s: %w", s, err)
		}
	}
	rules, expanded := 0, 0
	for _, s := range all {
		raw := artifacts[s.Artifact.Digest]
		p, err := parseSource(raw, s)
		if err != nil {
			return nil, fmt.Errorf("source %s: %w", s, err)
		}
		rules += len(p.Rules)
		encoded, err := json.Marshal(p)
		if err != nil {
			return nil, errors.New("invalid typed policy encoding")
		}
		expanded += len(encoded)
		if rules > MaxRules || expanded > MaxBundleBytes {
			return nil, errors.New("expanded policy budget exceeded")
		}
		b.policies[sourceKey(s)] = prepared{policy: p}
	}
	baseline := b.policies[sourceKey(*m.doc.Baseline)].policy
	for _, a := range m.doc.Additions {
		p := b.policies[sourceKey(a.Source)].policy
		if p.DefaultAction != "allow" {
			return nil, errors.New("addition default must explicitly be neutral allow")
		}
		if baseline.DefaultAction == "deny" {
			for _, r := range p.Rules {
				if r.Action != "deny" || r.Mode == "audit" {
					return nil, errors.New("default-deny baseline supports only enforcing-deny additions in v1")
				}
			}
		}
	}
	return b, nil
}

func preflightSource(raw []byte, budget *expansionBudget) error {
	// compiler.Parse intentionally supplies an allow default for legacy sources;
	// this contract requires it to be explicit instead. Do not expose YAML values
	// or parser diagnostics, which may contain sensitive operands, to callers.
	if len(raw) == 0 || len(raw) > MaxArtifactBytes {
		return errors.New("accepted policy source byte budget invalid")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var node yaml.Node
	if decoder.Decode(&node) != nil || len(node.Content) != 1 || node.Content[0].Kind != yaml.MappingNode {
		return errors.New("invalid accepted policy YAML")
	}
	// yaml.Unmarshal(Node) accepts only the first document. Check the COMPLETE
	// stream before charging expansion or calling compiler.Parse, whose trailing
	// Decode(new(any)) would otherwise materialize unchecked aliases. Node-only
	// decoding does not resolve aliases, merges or binary values in the tail.
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errYAMLDocuments
	}
	explicit := false
	for i := 0; i < len(node.Content[0].Content); i += 2 {
		if node.Content[0].Content[i].Value == "default_action" {
			v := node.Content[0].Content[i+1]
			explicit = v.Kind == yaml.ScalarNode && (v.Value == "allow" || v.Value == "deny")
		}
	}
	if !explicit {
		return errors.New("explicit allow or deny default_action required")
	}
	return sourceBudget(node.Content[0], budget)
}

// Only called after the complete bundle has passed preflightSource.
func parseSource(raw []byte, s Source) (*compiler.Policy, error) {
	p, err := compiler.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid accepted policy (details withheld)")
	}
	if len(p.Rules) > MaxRules {
		return nil, errors.New("rule budget exceeded")
	}
	remaining := len(s.RuleModes)
	for i := range p.Rules {
		if mode, ok := s.RuleModes[p.Rules[i].Name]; ok {
			p.Rules[i].Mode = mode
			remaining--
		}
		// Preserve the compiler's original implicit reason before qualifying names.
		if p.Rules[i].Reason == "" {
			p.Rules[i].Reason = "Rule: " + p.Rules[i].Name
		}
		p.Rules[i].Name = sourceKey(s) + "/" + p.Rules[i].Name
	}
	if remaining != 0 {
		return nil, errors.New("source-local override references unknown rule")
	}
	p.Variables = nil // fully resolved per-source by Parse; never merge variable maps
	if exactABI(p) != s.ABI {
		return nil, errors.New("declared exact ABI does not match typed source")
	}
	return p, nil
}

var (
	errYAMLDocuments   = errors.New("accepted policy requires exactly one YAML document")
	errYAMLMerge       = errors.New("YAML merge keys unsupported")
	errExpansionBudget = errors.New("source expansion budget exceeded or YAML aliases unsupported")
)

type expansionBudget struct{ values, bytes int }

// Check BEFORE compiler.Parse expands variables. Reject YAML aliases/merges and budget
// the conservatively expanded syntax tree, including repeated variable uses.
// Post-parse byte checks alone would allow enormous intermediate allocations.
func sourceBudget(root *yaml.Node, budget *expansionBudget) error {
	variables := map[string]*yaml.Node{}
	for i := 0; i < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		if key.Value == "rules" && len(value.Content) > MaxRules {
			return errors.New("rule budget exceeded")
		}
		if key.Value == "variables" && value.Kind == yaml.MappingNode {
			for j := 0; j < len(value.Content); j += 2 {
				variables[value.Content[j].Value] = value.Content[j+1]
			}
		}
	}
	var visit func(*yaml.Node, int) error
	visit = func(n *yaml.Node, depth int) error {
		budget.values--
		budget.bytes -= len(n.Value)
		if budget.values < 0 || budget.bytes < 0 || depth > 32 || n.Kind == yaml.AliasNode {
			return errExpansionBudget
		}
		// Only tags whose scalar spelling matches what the compiler resolves.
		// In particular !!binary can decode opaque text into a hidden "$list"
		// reference, and custom tags need not share this preflight's semantics.
		switch n.ShortTag() {
		case "!!map", "!!seq", "!!str", "!!int", "!!float", "!!bool", "!!null":
		default:
			return errors.New("unsupported YAML tag in accepted policy")
		}
		if n.Kind == yaml.MappingNode {
			for i := 0; i < len(n.Content); i += 2 {
				// Reject even quoted << keys, at EVERY nesting level. Otherwise
				// yaml.Decode may materialize variables absent from this map.
				if n.Content[i].Value == "<<" || n.Content[i].Tag == "!!merge" {
					return errYAMLMerge
				}
			}
		}
		if n.Kind == yaml.ScalarNode && strings.HasPrefix(n.Value, "$") && !strings.HasPrefix(n.Value, "$$") {
			if v := variables[strings.TrimPrefix(n.Value, "$")]; v != nil {
				return visit(v, depth+1)
			}
		}
		for _, child := range n.Content {
			if err := visit(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(root, 0)
}

// exactABI mirrors compiler v7 code generation. Version 7 tightens static
// kernel identities without changing the ABI 3/5 selection or deny-first order.
// Future compiler changes remain rejected until explicitly reviewed.
func exactABI(p *compiler.Policy) uint32 {
	f := compiler.FieldsRead(p)
	if f[0]&compiler.FieldBitArgs != 0 || f[2]&compiler.FieldBitOperation != 0 {
		return 5
	}
	return 3
}
