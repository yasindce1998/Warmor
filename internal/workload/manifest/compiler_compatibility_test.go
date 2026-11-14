package manifest

import (
	"encoding/json"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/yasindce1998/warmor/internal/compiler"
)

func TestReviewedCompilerCompatibilityPin(t *testing.T) {
	// Deliberately literal: following compiler.Version here would hide the next
	// unreviewed compiler bump rather than catch this cross-package regression.
	if SupportedCompilerVersion != "7" || compiler.Version != "7" || compiler.Identity != "warmor-yaml/7" {
		t.Fatal("compiler compatibility requires explicit manifest review")
	}
	doc, _ := fixture()
	doc.Compiler = "7"
	m := mustManifest(t, doc)
	if _, err := Decode(m.Bytes()); err != nil {
		t.Fatal("reviewed compiler manifest rejected", err)
	}
	for _, version := range []string{"6", "8", "999", "future"} {
		t.Run(version, func(t *testing.T) {
			doc.Compiler = version
			if _, err := New(doc); err == nil {
				t.Fatal("accepted an old or unreviewed compiler version")
			}
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Decode(data); err == nil {
				t.Fatal("decoded an old or unreviewed compiler version")
			}
		})
	}
}

func TestCompilerVersionSeparatesManifestSelectionAndGenerationHashes(t *testing.T) {
	doc, artifacts := fixture()
	m := mustManifest(t, doc)
	s := selectPod(t, m, "alpha")
	g, err := mustBundle(t, m, artifacts).Compose(s)
	if err != nil {
		t.Fatal(err)
	}
	// Hash-only reconstruction of the prior contract, NEVER an accepted v6
	// manifest or executable generation. Everything except compiler is equal.
	oldDoc := m.Document()
	oldDoc.Compiler = "6"
	oldBytes, err := json.Marshal(oldDoc)
	if err != nil {
		t.Fatal(err)
	}
	oldManifestDigest := digest.FromBytes(oldBytes)
	if oldManifestDigest == m.Digest() {
		t.Fatal("compiler omitted from manifest content identity")
	}
	oldSelectionBytes, err := json.Marshal(struct {
		Manifest digest.Digest `json:"manifest"`
		Scope    Scope         `json:"scope"`
		Sources  []Source      `json:"sources"`
	}{oldManifestDigest, s.Scope(), s.Sources()})
	if err != nil {
		t.Fatal(err)
	}
	oldSelectionDigest := digest.FromBytes(oldSelectionBytes)
	if oldSelectionDigest == s.Digest() {
		t.Fatal("selection reused compiler-6 cache identity")
	}
	policyBytes, err := json.Marshal(g.Policy())
	if err != nil {
		t.Fatal(err)
	}
	key := struct {
		Selection   digest.Digest `json:"selection"`
		Compiler    string        `json:"compiler"`
		ABI         uint32        `json:"abi"`
		Composition string        `json:"composition"`
		Posture     string        `json:"posture"`
		Policy      digest.Digest `json:"policy"`
	}{s.Digest(), "7", g.ABI(), CompositionVersion, Posture, digest.FromBytes(policyBytes)}
	hashKey := func() digest.Digest {
		t.Helper()
		data, err := json.Marshal(key)
		if err != nil {
			t.Fatal(err)
		}
		return digest.FromBytes(data)
	}
	if hashKey() != g.Digest() {
		t.Fatal("generation hash does not bind reviewed compiler-7 contract")
	}
	// Compiler must independently participate even if a caller retained the same
	// selected-set key; also check the entire legacy chain cannot share a key.
	key.Compiler = "6"
	if hashKey() == g.Digest() {
		t.Fatal("generation hash omitted compiler identity")
	}
	key.Selection = oldSelectionDigest
	if hashKey() == g.Digest() {
		t.Fatal("generation reused compiler-6 cache identity")
	}
}
