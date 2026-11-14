package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
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
	rules, expanded := 0, 0
	for _, s := range all {
		raw, ok := artifacts[s.Artifact.Digest]
		if !ok || len(raw) != s.Artifact.Size || len(raw) > MaxArtifactBytes || digest.FromBytes(raw) != s.Artifact.Digest {
			return nil, errors.New("missing source artifact or size/digest mismatch")
		}
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

func parseSource(raw []byte, s Source) (*compiler.Policy, error) {
	// compiler.Parse intentionally supplies an allow default for legacy sources;
	// this contract requires it to be explicit instead. Do not expose YAML values
	// or parser diagnostics, which may contain sensitive operands, to callers.
	var node yaml.Node
	if yaml.Unmarshal(raw, &node) != nil || len(node.Content) != 1 || node.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("invalid accepted policy YAML")
	}
	explicit := false
	for i := 0; i < len(node.Content[0].Content); i += 2 {
		if node.Content[0].Content[i].Value == "default_action" {
			v := node.Content[0].Content[i+1]
			explicit = v.Kind == yaml.ScalarNode && (v.Value == "allow" || v.Value == "deny")
		}
	}
	if !explicit {
		return nil, errors.New("explicit allow or deny default_action required")
	}
	if err := sourceBudget(node.Content[0]); err != nil {
		return nil, err
	}
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

// Check BEFORE compiler.Parse expands variables. Reject YAML aliases and budget
// the conservatively expanded syntax tree, including repeated variable uses.
// Post-parse byte checks alone would allow enormous intermediate allocations.
func sourceBudget(root *yaml.Node) error {
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
	values, remaining := 65536, MaxBundleBytes
	var visit func(*yaml.Node, int) error
	visit = func(n *yaml.Node, depth int) error {
		values--
		remaining -= len(n.Value)
		if values < 0 || remaining < 0 || depth > 32 || n.Kind == yaml.AliasNode {
			return errors.New("source expansion budget exceeded or YAML aliases unsupported")
		}
		if n.Kind == yaml.ScalarNode && n.Tag == "!!str" && strings.HasPrefix(n.Value, "$") && !strings.HasPrefix(n.Value, "$$") {
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

// exactABI mirrors compiler v6 code generation. A compiler version change is
// rejected by New until this composition contract is reviewed for compatibility.
func exactABI(p *compiler.Policy) uint32 {
	f := compiler.FieldsRead(p)
	if f[0]&compiler.FieldBitArgs != 0 || f[2]&compiler.FieldBitOperation != 0 {
		return 5
	}
	return 3
}
