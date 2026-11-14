// Package manifest prepares immutable workload selection and typed composition.
// It does not authenticate publishers, activate selectors, or install policy.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/opencontainers/go-digest"
	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/workload"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	Version            = "warmor-selection/v1"
	CompositionVersion = "deny-first/v1"
	Posture            = "per-rule/v1"
	// Pin, rather than follow compiler.Version automatically: changed compiler
	// semantics require an explicit review of exactABI and deny-first behavior.
	SupportedCompilerVersion = "6"
	SourceMediaType          = "application/vnd.warmor.accepted-policy.v1+yaml"
	MaxManifestBytes         = 256 << 10
	MaxSources               = 128
	MaxArtifactBytes         = 1 << 20
	MaxBundleBytes           = 8 << 20
	MaxRules                 = 4096
)

// Artifact is a bundle-local reference, never a filesystem path or remote URL.
type Artifact struct {
	Digest    digest.Digest `json:"digest"`
	Size      int           `json:"size"`
	MediaType string        `json:"mediaType"`
}

// Source identifies accepted effective source, not the latest desired CR spec.
// Variables (including overrides) must be materialized in its private artifact.
// RuleModes are exact rule-name overrides LOCAL to this namespace+UID only.
type Source struct {
	Namespace          string            `json:"namespace"`
	UID                types.UID         `json:"uid"`
	AcceptedGeneration int64             `json:"acceptedGeneration"`
	Artifact           Artifact          `json:"artifact"`
	ABI                uint32            `json:"abi"`
	RuleModes          map[string]string `json:"ruleModes,omitempty"`
}

type Addition struct {
	Source   Source               `json:"source"`
	Selector metav1.LabelSelector `json:"selector"`
}

// ScopeHandling is mandatory and independent for unknown and positively known
// host identities. audit-only has no policy; baseline requires a dedicated
// source. Neither mode ever runs workload selectors.
type ScopeHandling struct {
	Mode     string  `json:"mode"`
	Baseline *Source `json:"baseline,omitempty"`
}

type Document struct {
	Version     string        `json:"version"`
	Generation  uint64        `json:"generation"`
	Compiler    string        `json:"compiler"`
	Composition string        `json:"composition"`
	Posture     string        `json:"posture"`
	Baseline    *Source       `json:"baseline"`
	Unknown     ScopeHandling `json:"unknown"`
	KnownHost   ScopeHandling `json:"knownHost"`
	Additions   []Addition    `json:"additions"`
}

// Manifest owns canonical bytes and deep copies of all inputs. Digest is an
// integrity/cache identity, NOT a signature, activation epoch or anti-rollback.
type Manifest struct {
	doc       Document
	canonical []byte
	digest    digest.Digest
	catalog   *workload.Catalog
}

// New validates and owns a copy. Callers must not concurrently mutate inputs
// during construction; returned manifests and their copies support concurrent
// readers. It does not authorize any declared source or publisher.
func New(doc Document) (*Manifest, error) {
	encoded, err := json.Marshal(doc)
	if err != nil || len(encoded) > MaxManifestBytes {
		return nil, errors.New("manifest encoding/budget invalid")
	}
	// Own every selector, map and pointer, without mutating caller inputs.
	var owned Document
	if err := json.Unmarshal(encoded, &owned); err != nil {
		return nil, err
	}
	doc = owned
	if doc.Version != Version || doc.Generation == 0 || doc.Compiler != SupportedCompilerVersion || compiler.Version != SupportedCompilerVersion ||
		doc.Composition != CompositionVersion || doc.Posture != Posture {
		return nil, errors.New("unsupported manifest version, generation, compiler, composition or posture")
	}
	if doc.Baseline == nil {
		return nil, errors.New("explicit workload baseline required")
	}
	if len(doc.Additions) > MaxSources-1 {
		return nil, errors.New("source budget exceeded")
	}
	all := []*Source{doc.Baseline}
	for _, scope := range []ScopeHandling{doc.Unknown, doc.KnownHost} {
		switch scope.Mode {
		case "audit-only":
			if scope.Baseline != nil {
				return nil, errors.New("audit-only scope cannot have a baseline")
			}
		case "baseline":
			if scope.Baseline == nil {
				return nil, errors.New("scope baseline required")
			}
			all = append(all, scope.Baseline)
		default:
			return nil, errors.New("explicit unknown and known-host handling required")
		}
	}
	var candidates []workload.Candidate
	for i := range doc.Additions {
		a := &doc.Additions[i]
		all = append(all, &a.Source)
		if len(a.Selector.MatchLabels)+len(a.Selector.MatchExpressions) > 128 {
			return nil, errors.New("selector budget exceeded")
		}
		// Canonicalize set-valued selector parts without changing K8s semantics.
		for j := range a.Selector.MatchExpressions {
			sort.Strings(a.Selector.MatchExpressions[j].Values)
		}
		sort.Slice(a.Selector.MatchExpressions, func(i, j int) bool {
			x, _ := json.Marshal(a.Selector.MatchExpressions[i])
			y, _ := json.Marshal(a.Selector.MatchExpressions[j])
			return string(x) < string(y)
		})
		candidates = append(candidates, workload.Candidate{Policy: reference(a.Source), Selector: a.Selector})
	}
	if len(all) > MaxSources {
		return nil, errors.New("source budget exceeded")
	}
	seen := map[string]bool{}
	total := 0
	for _, s := range all {
		if err := validateSource(*s); err != nil {
			return nil, err
		}
		key := sourceKey(*s)
		if seen[key] {
			return nil, errors.New("duplicate namespace+UID source identity")
		}
		seen[key] = true
		total += s.Artifact.Size
	}
	if total > MaxBundleBytes {
		return nil, errors.New("bundle byte budget exceeded")
	}
	catalog, err := workload.NewCatalog(candidates)
	if err != nil {
		return nil, errors.New("invalid namespace-local selector")
	}
	sort.Slice(doc.Additions, func(i, j int) bool { return sourceKey(doc.Additions[i].Source) < sourceKey(doc.Additions[j].Source) })
	encoded, _ = json.Marshal(doc)
	return &Manifest{doc: doc, canonical: encoded, digest: digest.FromBytes(encoded), catalog: catalog}, nil
}

func validateSource(s Source) error {
	if len(validation.IsDNS1123Label(s.Namespace)) != 0 || len(s.UID) == 0 || len(s.UID) > 128 ||
		strings.ContainsAny(string(s.UID), "/\\\x00\r\n") || s.AcceptedGeneration <= 0 {
		return errors.New("invalid accepted namespace+UID generation")
	}
	// UIDs are opaque but must be printable ASCII; keep provenance unambiguous.
	for _, c := range s.UID {
		if c < 33 || c > 126 {
			return errors.New("invalid source UID")
		}
	}
	if s.ABI != 3 && s.ABI != 5 {
		return errors.New("unsupported exact source ABI")
	}
	a := s.Artifact
	if a.Digest.Validate() != nil || a.Digest.Algorithm() != digest.SHA256 || a.Size < 1 || a.Size > MaxArtifactBytes || a.MediaType != SourceMediaType {
		return errors.New("invalid bounded SHA-256 source artifact reference")
	}
	if len(s.RuleModes) > MaxRules {
		return errors.New("rule override budget exceeded")
	}
	for name, mode := range s.RuleModes {
		if name == "" || len(name) > 1024 || (mode != "enforce" && mode != "audit") {
			return errors.New("invalid source-local rule mode override")
		}
	}
	return nil
}

// Decode rejects non-exact schema fields, duplicate keys, trailing documents and excess
// bytes before construction. It accepts noncanonical JSON; Bytes is canonical.
func Decode(data []byte) (*Manifest, error) {
	if len(data) > MaxManifestBytes {
		return nil, errors.New("manifest byte budget exceeded")
	}
	if !utf8.Valid(data) {
		return nil, errors.New("manifest requires valid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if err := strictJSON(d, reflect.TypeFor[Document](), 0); err != nil {
		return nil, errors.New("invalid, duplicate or non-exact manifest JSON fields")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing manifest JSON")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var doc Document
	if err := d.Decode(&doc); err != nil {
		return nil, errors.New("invalid manifest fields")
	}
	return New(doc)
}

// Validate the decoded key spelling against exact JSON struct tags before Go's
// case-insensitive struct decoder runs. Map keys (labels and rule names) are
// deliberately NOT schema names and retain their case-sensitive semantics.
func strictJSON(d *json.Decoder, schema reflect.Type, depth int) error {
	if depth > 32 {
		return errors.New("JSON depth budget exceeded")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	for schema.Kind() == reflect.Pointer {
		schema = schema.Elem()
	}
	if delim == '{' && schema.Kind() != reflect.Struct && schema.Kind() != reflect.Map ||
		delim == '[' && schema.Kind() != reflect.Slice && schema.Kind() != reflect.Array {
		return errors.New("invalid JSON schema shape")
	}
	seen := map[string]bool{}
	for d.More() {
		var child reflect.Type
		if delim == '{' {
			k, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := k.(string)
			if !ok || seen[key] {
				return errors.New("duplicate JSON key")
			}
			seen[key] = true
			if schema.Kind() == reflect.Map {
				child = schema.Elem()
			} else {
				for i := 0; i < schema.NumField(); i++ {
					field := schema.Field(i)
					name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
					if name == key {
						child = field.Type
						break
					}
				}
				if child == nil {
					return errors.New("non-exact JSON schema field")
				}
			}
		} else {
			child = schema.Elem()
		}
		if err := strictJSON(d, child, depth+1); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}

func (m *Manifest) Digest() digest.Digest {
	if m == nil {
		return ""
	}
	return m.digest
}

func (m *Manifest) valid() bool {
	return m != nil && m.doc.Baseline != nil && m.catalog != nil && m.digest != ""
}
func (m *Manifest) Bytes() []byte {
	if m == nil {
		return nil
	}
	return bytes.Clone(m.canonical)
}
func (m *Manifest) Document() Document {
	var doc Document
	if m != nil {
		_ = json.Unmarshal(m.canonical, &doc)
	}
	return doc
}
func sourceKey(s Source) string { return s.Namespace + "/" + string(s.UID) }
func reference(s Source) workload.PolicyGeneration {
	return workload.PolicyGeneration{Namespace: s.Namespace, UID: s.UID, Generation: s.AcceptedGeneration, Digest: s.Artifact.Digest}
}

func (s Source) String() string { return fmt.Sprintf("%s@%d", sourceKey(s), s.AcceptedGeneration) }
