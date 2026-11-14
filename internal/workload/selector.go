package workload

import (
	_ "crypto/sha256" // register required artifact digest algorithm
	"fmt"
	"sort"

	"github.com/opencontainers/go-digest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Selector uses Kubernetes semantics. A namespace is mandatory: empty selectors
// match all verified Pods in that namespace, never unknown identities or hosts.
type Selector struct {
	namespace string
	selector  labels.Selector
}

func CompileSelector(namespace string, spec metav1.LabelSelector) (Selector, error) {
	if errs := validation.IsDNS1123Label(namespace); len(errs) != 0 {
		return Selector{}, fmt.Errorf("selector namespace %q: %v", namespace, errs)
	}
	compiled, err := metav1.LabelSelectorAsSelector(spec.DeepCopy())
	if err != nil {
		return Selector{}, fmt.Errorf("pod selector: %w", err)
	}
	return Selector{namespace: namespace, selector: compiled}, nil
}

func (s Selector) Matches(identity Identity) bool {
	return identity.podUID != "" && s.selector != nil && identity.namespace == s.namespace && s.selector.Matches(labels.Set(identity.podLabels))
}

// PolicyGeneration identifies accepted content, not a display name, desired CR
// generation, or acknowledgement of node activation.
type PolicyGeneration struct {
	Namespace  string
	UID        types.UID
	Generation int64
	Digest     digest.Digest
}

// Candidate is one namespace-local workload addition. Baseline and verdict
// composition are intentionally outside this package's pure selection.
type Candidate struct {
	Policy   PolicyGeneration
	Selector metav1.LabelSelector
}

type compiledCandidate struct {
	policy   PolicyGeneration
	selector Selector
}

// Catalog is immutable. Its result is a deterministic set, not a priority order
// or execution plan. Duplicate source identities are rejected.
type Catalog struct{ entries []compiledCandidate }

func NewCatalog(candidates []Candidate) (*Catalog, error) {
	catalog := &Catalog{entries: make([]compiledCandidate, 0, len(candidates))}
	type source struct {
		namespace string
		uid       types.UID
	}
	seen := make(map[source]bool, len(candidates))
	for _, candidate := range candidates {
		p := candidate.Policy
		if p.UID == "" || p.Generation <= 0 || p.Digest.Validate() != nil || p.Digest.Algorithm() != digest.SHA256 {
			return nil, fmt.Errorf("invalid accepted policy generation for %s/%s", p.Namespace, p.UID)
		}
		key := source{p.Namespace, p.UID}
		if seen[key] {
			return nil, fmt.Errorf("duplicate policy source %s/%s", p.Namespace, p.UID)
		}
		seen[key] = true
		s, err := CompileSelector(p.Namespace, candidate.Selector)
		if err != nil {
			return nil, err
		}
		catalog.entries = append(catalog.entries, compiledCandidate{policy: p, selector: s})
	}
	sort.Slice(catalog.entries, func(i, j int) bool {
		a, b := catalog.entries[i].policy, catalog.entries[j].policy
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.UID < b.UID
	})
	return catalog, nil
}

// Select returns all matching accepted generations. The caller MUST distinguish
// unknown identity from verified no-match. This neither combines verdicts nor
// enables WarmorPolicy selector enforcement.
func (c *Catalog) Select(identity Identity) []PolicyGeneration {
	if c == nil {
		return nil
	}
	var selected []PolicyGeneration
	for _, candidate := range c.entries {
		if candidate.selector.Matches(identity) {
			selected = append(selected, candidate.policy)
		}
	}
	return selected
}
