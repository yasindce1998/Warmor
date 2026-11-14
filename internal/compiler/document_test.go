package compiler

import (
	"fmt"
	"strings"
	"testing"
)

const documentPolicy = "name: framing\nversion: 1\ndefault_action: allow\nrules:\n- name: rule\n  event: process\n  action: allow\n  conditions: {all: [{path: /bin/tool}]}\n"

func TestDocumentFramingRejectsTrailingContentBeforeTypedDecoding(t *testing.T) {
	for _, trailing := range []string{
		"---\n",
		"---\n{}\n",
		"---\n!!binary not-valid-base64!\n",
		"---\na: &a [one, two]\nb: [*a, *a]\n",
		"---\nbase: &base {key: value}\nmerged: {<<: *base}\n",
		"---\n[unterminated\n",
	} {
		t.Run(trailing, func(t *testing.T) {
			// The first document deliberately fails typed operand decoding.
			// Framing must reject the second document before either document
			// is materialized into interface-valued variables or operands.
			data := "name: framing\nversion: 1\nvariables: {bad: !!binary not-base64!}\nrules: []\n" + trailing
			_, err := Parse([]byte(data))
			if err == nil || err.Error() != "parse YAML: expected exactly one YAML document" {
				t.Fatalf("error = %v, want framing rejection before typed decoding", err)
			}
		})
	}
}

func TestDocumentFramingDoesNotExpandTrailingAliases(t *testing.T) {
	var trailing strings.Builder
	trailing.WriteString("---\nv0: &v0 [one, two]\n")
	// Syntactically small, but expanding the reference graph would produce
	// over a million scalar occurrences. Test framing only: no typed decode
	// or JSON serialization of this rejected graph is performed.
	for i := 1; i <= 20; i++ {
		fmt.Fprintf(&trailing, "v%d: &v%d [*v%d, *v%d]\n", i, i, i-1, i-1)
	}
	data := []byte(documentPolicy + trailing.String())
	if len(data) > 1024 {
		t.Fatalf("unexpectedly large framing fixture: %d bytes", len(data))
	}
	if err := validateDocumentFraming(data); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("framing error = %v", err)
	}
}

func TestSingleDocumentFramingPreservesStrictFieldsAndAliases(t *testing.T) {
	for _, suffix := range []string{"", "...\n", "# trailing comment\n"} {
		if _, err := Parse([]byte(documentPolicy + suffix)); err != nil {
			t.Fatalf("single document suffix %q: %v", suffix, err)
		}
	}
	if _, err := Parse([]byte(strings.Replace(documentPolicy, "default_action", "default_actoin", 1))); err == nil || !strings.Contains(err.Error(), "default_actoin") {
		t.Fatalf("strict field validation lost: %v", err)
	}
	data := "name: alias\nversion: 1\nvariables:\n  first: &path /bin/tool\n  second: *path\nrules:\n- name: r\n  event: process\n  action: deny\n  conditions: {all: [{path: $second}]}\n"
	p, err := Parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Rules[0].Conditions.All[0].Value; got != "/bin/tool" {
		t.Fatalf("single-document alias = %v", got)
	}
}
