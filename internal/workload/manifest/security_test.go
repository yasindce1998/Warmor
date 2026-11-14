package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/yasindce1998/warmor/internal/compiler"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func repeatedListPolicy(merge bool, uses, items int) []byte {
	var b strings.Builder
	b.WriteString("name: bounded-expansion\nversion: 1\ndefault_action: allow\nvariables:\n")
	if merge {
		b.WriteString("  <<:\n  ")
	}
	b.WriteString("  list: [")
	for i := 0; i < items; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("item")
	}
	b.WriteString("]\nrules:\n  - name: r\n    event: process\n    action: deny\n    conditions:\n      any:\n")
	for i := 0; i < uses; i++ {
		b.WriteString("        - comm: {any_of: $list}\n")
	}
	return []byte(b.String())
}

func TestRejectMergedVariablesBeforeCompilerExpansion(t *testing.T) {
	// Tiny bounded witness: compiler YAML decoding materializes variables from
	// an inline merge, although the old immediate-key preflight missed them.
	tiny := repeatedListPolicy(true, 2, 4)
	if _, err := compiler.Parse(tiny); err != nil {
		t.Fatalf("invalid merged-variable witness: %v", err)
	}
	budget := expansionBudget{values: 65536, bytes: MaxBundleBytes}
	if err := preflightSource(tiny, &budget); !errors.Is(err, errYAMLMerge) {
		t.Fatalf("merged variables did not fail preflight: %v", err)
	}

	// More than the GLOBAL value budget, but only a few KiB of source. Never
	// call compiler.Parse on this amplification specimen: preflight must reject.
	for _, merge := range []bool{false, true} {
		raw := repeatedListPolicy(merge, 128, 1024)
		if len(raw) > 16<<10 {
			t.Fatal("regression specimen exceeded its input budget")
		}
		budget := expansionBudget{values: 65536, bytes: MaxBundleBytes}
		err := preflightSource(raw, &budget)
		want := errExpansionBudget
		if merge {
			want = errYAMLMerge
		}
		if !errors.Is(err, want) {
			t.Fatalf("merge=%v: expected pre-compiler rejection, got %v", merge, err)
		}
	}
}

func TestRejectYAMLMergeKeysEverywhere(t *testing.T) {
	raw := yamlPolicy("deny", "x", "allow")
	cases := []string{
		"<<: {description: merged}\n" + raw,
		strings.Replace(raw, "variables:", "variables:\n  <<: {hidden: x}\n  unused:", 1),
		strings.Replace(raw, "  - name: same-rule", "  - <<: {mode: audit}\n    name: same-rule", 1),
		strings.Replace(raw, `{comm: "$target"}`, `{<<: {comm: "$target"}}`, 1),
		strings.Replace(raw, `{comm: "$target"}`, `{comm: {<<: {eq: "$target"}}}`, 1),
		strings.Replace(raw, "variables:", "variables:\n  unused: {'<<': {hidden: x}}\n  other:", 1),
		strings.Replace(raw, "variables:", "variables:\n  unused: {!!merge different: {hidden: x}}\n  other:", 1),
	}
	for i, input := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			budget := expansionBudget{values: 65536, bytes: MaxBundleBytes}
			if err := preflightSource([]byte(input), &budget); !errors.Is(err, errYAMLMerge) {
				t.Fatalf("nested/tagged/quoted merge not rejected: %v", err)
			}
		})
	}
}

func TestExpansionBudgetSharedAcrossAllBundleSources(t *testing.T) {
	raw := repeatedListPolicy(false, 80, 512)
	budget := expansionBudget{values: 65536, bytes: MaxBundleBytes}
	if err := preflightSource(raw, &budget); err != nil {
		t.Fatal("bounded single source rejected", err)
	}
	if err := preflightSource(raw, &budget); !errors.Is(err, errExpansionBudget) {
		t.Fatal("bundle expansion budget reset per source", err)
	}
	doc, _ := fixture()
	doc.Additions = doc.Additions[:1]
	// An invalid first-source compiler event proves that the later budget
	// failure is detected before ANY source reaches compiler.Parse.
	first := bytes.Replace(raw, []byte("event: process"), []byte("event: invalid"), 1)
	*doc.Baseline = source("system", "baseline", string(first))
	doc.Additions[0].Source = source("alpha", "addition", string(raw))
	if _, err := NewBundle(mustManifest(t, doc), map[digest.Digest][]byte{digest.FromBytes(first): first, digest.FromBytes(raw): raw}); !errors.Is(err, errExpansionBudget) {
		t.Fatal("complete bundle did not fail preflight budget", err)
	}
}

func TestPreflightRepeatedVariableByteBudget(t *testing.T) {
	// Bounded syntax and 128 uses: scalar-byte amplification must be rejected
	// even when the global node count would fit. Never compile this specimen.
	raw := []byte(strings.Replace(yamlPolicy("deny", "x", "allow"), `variables: {target: "x"}`, "variables: {target: "+strings.Repeat("x", 2048)+"}", 1))
	raw = bytes.Replace(raw, []byte(`{comm: "$target"}`), []byte(strings.Repeat(`{comm: "$target"},`, 127)+`{comm: "$target"}`), 1)
	budget := expansionBudget{values: 65536, bytes: 64 << 10}
	if err := preflightSource(raw, &budget); !errors.Is(err, errExpansionBudget) {
		t.Fatal("repeated variable bytes escaped preflight", err)
	}
}

func TestRejectYAMLTagsThatHideVariableReferences(t *testing.T) {
	// yaml.v3 decodes this binary operand to "$target" before compiler variable
	// resolution. Preflight must not mistake its encoded spelling for a literal.
	raw := []byte(strings.Replace(yamlPolicy("deny", "x", "allow"), `comm: "$target"`, `comm: !!binary JHRhcmdldA==`, 1))
	if _, err := compiler.Parse(raw); err != nil {
		t.Fatal("invalid bounded binary-variable witness", err)
	}
	budget := expansionBudget{values: 65536, bytes: MaxBundleBytes}
	if err := preflightSource(raw, &budget); err == nil {
		t.Fatal("encoded variable reference escaped preflight")
	}
	for _, tag := range []string{"!custom", "!!timestamp"} {
		raw := []byte(strings.Replace(yamlPolicy("deny", "x", "allow"), `comm: "$target"`, `comm: `+tag+` "$target"`, 1))
		budget := expansionBudget{values: 65536, bytes: MaxBundleBytes}
		if err := preflightSource(raw, &budget); err == nil {
			t.Fatal("unsupported operand tag escaped preflight")
		}
	}
}

func TestPreflightRejectsTrailingYAMLBeforeExpansion(t *testing.T) {
	first := yamlPolicy("deny", "x", "allow")
	// Small syntax-only witness: never pass this trailing alias document to
	// compiler.Parse or any YAML decoder targeting interface/map values.
	aliases := "values: &values [" + strings.Repeat("x,", 15) + "x]\nrepeated: [" + strings.Repeat("*values,", 31) + "*values]\n"
	for name, tail := range map[string]string{
		"mapping":            "ignored: true\n",
		"aliases":            aliases,
		"merge":              "<<: {hidden: [x, y]}\n",
		"binary":             "!!binary JHRhcmdldA==\n",
		"depth":              strings.Repeat("[", 40) + "x" + strings.Repeat("]", 40) + "\n",
		"empty":              "",
		"comment-only":       "# empty second document\n",
		"null":               "null\n",
		"third-document":     "---\nignored: true\n",
		"malformed":          "[\n",
		"trailing-after-end": "...\n[\n",
	} {
		t.Run(name, func(t *testing.T) {
			raw := []byte(first + "---\n" + tail)
			if len(raw) > 4096 {
				t.Fatal("trailing-document witness exceeded bounded input size")
			}
			// A zero budget would reject even the first ordinary node if visited.
			// Requiring the document error proves rejection occurs BEFORE budget
			// traversal, and NewBundle must return that same pre-compiler error.
			budget := expansionBudget{}
			if err := preflightSource(raw, &budget); !errors.Is(err, errYAMLDocuments) {
				t.Fatal("trailing YAML did not fail before expansion", err)
			}
			if budget != (expansionBudget{}) {
				t.Fatal("trailing YAML charged expansion budget")
			}
			doc, _ := fixture()
			doc.Additions = nil
			*doc.Baseline = source("system", "baseline", string(raw))
			if _, err := NewBundle(mustManifest(t, doc), map[digest.Digest][]byte{digest.FromBytes(raw): raw}); !errors.Is(err, errYAMLDocuments) {
				t.Fatal("trailing YAML reached compiler parsing", err)
			}
		})
	}
	for _, raw := range []string{first, "---\n" + first, first + "# trailing comment\n", first + "...\n# trailing comment\n"} {
		budget := expansionBudget{values: 65536, bytes: MaxBundleBytes}
		if err := preflightSource([]byte(raw), &budget); err != nil {
			t.Fatal("valid single YAML document rejected", err)
		}
	}
	budget := expansionBudget{}
	if err := preflightSource(bytes.Repeat([]byte(" "), MaxArtifactBytes+1), &budget); err == nil {
		t.Fatal("oversized YAML stream accepted")
	}
}

func TestDecodeExactSchemaNames(t *testing.T) {
	doc, _ := fixture()
	doc.Additions[0].Source.RuleModes = map[string]string{"rule": "audit", "Rule": "enforce"}
	doc.Additions[0].Selector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "a", "App": "b"}, MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"api"}}}}
	raw := mustManifest(t, doc).Bytes()
	// Every schema layer, with and without an exact-spelling predecessor.
	for _, key := range []string{"version", "generation", "compiler", "composition", "posture", "baseline", "unknown", "knownHost", "additions", "namespace", "uid", "acceptedGeneration", "artifact", "abi", "ruleModes", "digest", "size", "mediaType", "source", "selector", "matchLabels", "matchExpressions", "key", "operator", "values", "mode"} {
		t.Run(key, func(t *testing.T) {
			exact := []byte(fmt.Sprintf("%q:", key))
			variant := []byte(fmt.Sprintf("%q:", strings.ToUpper(key)))
			if !bytes.Contains(raw, exact) {
				t.Fatal("missing schema field in regression fixture")
			}
			bad := bytes.Replace(raw, exact, variant, 1)
			if _, err := Decode(bad); err == nil {
				t.Fatal("accepted non-exact schema field")
			}
		})
	}
	decoded, err := Decode(raw)
	if err != nil {
		t.Fatal("case-sensitive user map keys rejected", err)
	}
	got := decoded.Document().Additions[0]
	if got.Selector.MatchLabels["app"] != "a" || got.Selector.MatchLabels["App"] != "b" || got.Source.RuleModes["rule"] != "audit" || got.Source.RuleModes["Rule"] != "enforce" {
		t.Fatal("user map key cases collapsed")
	}

	// The review witness: a case variant must not replace an enforcing unknown
	// baseline with audit-only scope handling (in either order).
	s := source("system", "unknown", yamlPolicy("deny", "x", "deny"))
	doc.Unknown = ScopeHandling{Mode: "baseline", Baseline: &s}
	raw = mustManifest(t, doc).Bytes()
	for _, extra := range []string{`"Unknown":{"mode":"audit-only","baseline":null},`, `"UNKNOWN":{"mode":"audit-only","baseline":null},`, `"unKnown":{"mode":"audit-only","baseline":null},`, `"\u0055nknown":{"mode":"audit-only","baseline":null},`, `"unknown":{"Mode":"audit-only","baseline":null},`} {
		for _, input := range [][]byte{append([]byte("{"+extra), raw[1:]...), append(append(bytes.Clone(raw[:len(raw)-1]), ','), []byte(strings.TrimSuffix(extra, ",")+"}")...)} {
			if _, err := Decode(input); err == nil {
				t.Fatal("accepted scope override via case variant/duplicate")
			}
		}
	}
}

func FuzzDecodeStrictJSON(f *testing.F) {
	doc, _ := fixture()
	raw, err := json.Marshal(doc)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"unknown":{},"Unknown":{}}`))
	f.Add([]byte(`{"baseline":{"Artifact":{"digest":"x"}}}`))
	f.Add([]byte(`{"generation":1,"\u0067eneration":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxManifestBytes {
			t.Skip()
		}
		m, err := Decode(data)
		if err != nil {
			return
		}
		copy, err := Decode(m.Bytes())
		if err != nil || copy.Digest() != m.Digest() {
			t.Fatal("accepted manifest failed canonical round trip", err)
		}
	})
}

func FuzzRejectSchemaCaseVariants(f *testing.F) {
	for _, key := range []string{"Unknown", "UNKNOWN", "unKnown", "unKnown", "unknown"} {
		f.Add(key)
	}
	doc, _ := fixture()
	raw, err := json.Marshal(doc)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, key string) {
		if len(key) > 128 || !strings.EqualFold(key, "unknown") {
			return
		}
		encoded, err := json.Marshal(key)
		if err != nil {
			t.Fatal(err)
		}
		input := append([]byte("{"+string(encoded)+`:{"mode":"audit-only"},`), raw[1:]...)
		if _, err := Decode(input); err == nil {
			t.Fatal("accepted duplicate or non-exact schema key")
		}
	})
}

func FuzzRejectYAMLMergeKeys(f *testing.F) {
	f.Add(uint8(0), uint8(1))
	f.Add(uint8(4), uint8(8))
	f.Add(uint8(5), uint8(32))
	f.Fuzz(func(t *testing.T, location, items uint8) {
		// Generate only bounded YAML; NEVER compile an amplification specimen.
		value := "[" + strings.Repeat("x,", int(items%32)) + "x]"
		key := []string{"<<", "'<<'", "!!merge hidden"}[int(location)%3]
		fragments := []string{
			key + ": {description: x}\n",
			"variables: {" + key + ": {list: " + value + "}}\n",
			"variables: {unused: {" + key + ": {list: " + value + "}}}\n",
			"variables: {unused: [{" + key + ": {list: " + value + "}}]}\n",
		}
		raw := []byte(fragments[int(location)%len(fragments)] + strings.Replace(yamlPolicy("deny", "x", "allow"), `variables: {target: "x"}`, "", 1))
		budget := expansionBudget{values: 65536, bytes: MaxBundleBytes}
		if err := preflightSource(raw, &budget); !errors.Is(err, errYAMLMerge) {
			t.Fatal("merge escaped preflight", err)
		}
	})
}

func FuzzPreflightRepeatedVariables(f *testing.F) {
	f.Add(uint8(127), uint8(63))
	f.Add(uint8(1), uint8(1))
	f.Fuzz(func(t *testing.T, uses, items uint8) {
		u, n := int(uses%128)+1, int(items%64)+1
		raw := repeatedListPolicy(false, u, n)
		budget := expansionBudget{values: 1024, bytes: MaxBundleBytes}
		err := preflightSource(raw, &budget)
		if u*n > 1024 && !errors.Is(err, errExpansionBudget) {
			t.Fatal("repeated variable expansion escaped global node budget", err)
		}
	})
}

func FuzzPreflightRejectsTrailingYAML(f *testing.F) {
	for _, tail := range []string{"", "# comment\n", "x: &x [a,b]\ny: [*x,*x]\n", "<<: {x: y}\n", "!!binary JHRhcmdldA==\n", "[", "---\n"} {
		f.Add([]byte(tail))
	}
	first := []byte(yamlPolicy("deny", "x", "allow") + "---\n")
	f.Fuzz(func(t *testing.T, tail []byte) {
		if len(tail) > 4096 {
			t.Skip()
		}
		raw := append(bytes.Clone(first), tail...)
		budget := expansionBudget{}
		if err := preflightSource(raw, &budget); err == nil {
			t.Fatal("accepted trailing YAML document or syntax")
		}
		if budget != (expansionBudget{}) {
			t.Fatal("trailing YAML reached expansion traversal")
		}
	})
}
