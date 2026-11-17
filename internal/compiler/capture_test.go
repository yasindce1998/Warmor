package compiler

import (
	"fmt"
	"strings"
	"testing"
)

func TestCaptureFieldVocabulary(t *testing.T) {
	for name, want := range map[string]uint32{
		"ppid":        FieldBitPPID,
		"parent_comm": FieldBitParentComm,
		"cgroup_id":   FieldBitCgroupID,
	} {
		if got := FieldBit(name); got != want {
			t.Errorf("FieldBit(%q) = %#x, want %#x", name, got, want)
		}
		if got := FieldNames(want); len(got) != 1 || got[0] != name {
			t.Errorf("FieldNames(%#x) = %v, want [%s]", want, got, name)
		}
	}
}

func TestRequireCompleteCaptureDeclarationRoundTrip(t *testing.T) {
	policy := &Policy{
		Name: "gate", Version: 1, DefaultAction: "deny",
		RequireCompleteCapture: true,
		Rules: []Rule{{
			Name: "exec", Event: "process", Action: "deny",
			Conditions: Conditions{All: []Condition{{Field: "path", Operator: "glob", Value: "/tmp/**"}}},
		}},
	}
	fr := FieldsRead(policy)
	if fr[0]&FieldBitRequireCompleteCapture == 0 {
		t.Fatalf("process declaration %#x missing require-complete bit", fr[0])
	}
	if want := FieldBitPath | FieldBitRequireCompleteCapture; fr[0] != want {
		t.Fatalf("process declaration = %#x, want %#x", fr[0], want)
	}

	src, err := GenerateRust(policy)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(src, fmt.Sprintf("0 => 0x%08X,", fr[0])) {
		t.Fatalf("generated warmor_fields_read does not carry the declaration %#x", fr[0])
	}

	// The same declaration is observable at parse time via the typed policy's
	// variables hook (the strict YAML decoder uses a separate rawPolicy).
	parsed, err := Parse([]byte(`name: gate
version: 1
variables:
  require_complete_capture: true
rules:
  - name: exec
    event: process
    conditions:
      all:
        - path: { glob: "/tmp/**" }
    action: deny
default_action: deny
`))
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.RequireCompleteCapture {
		t.Fatal("YAML declaration lost at parse time")
	}
	if got := FieldsRead(parsed)[0]; got&FieldBitRequireCompleteCapture == 0 {
		t.Fatalf("parsed declaration %#x missing require-complete bit", got)
	}

	// A policy without the declaration keeps its exact old mask.
	policy.RequireCompleteCapture = false
	if got := FieldsRead(policy)[0]; got != FieldBitPath {
		t.Fatalf("undeclared policy mask = %#x, want only path", got)
	}
}
