package compiler

import (
	"fmt"
	"strings"
	"testing"
)

func TestFieldsRead(t *testing.T) {
	p, err := Parse([]byte(`name: f
version: 1
rules:
  - name: exec
    event: process
    conditions:
      all:
        - path: { glob: "/tmp/**" }
      not:
        - uid: { eq: 0 }
    action: deny
  - name: net
    event: network
    conditions:
      any:
        - remote_port: { eq: 22 }
        - remote_addr: { eq: "10.0.0.1" }
    action: deny
default_action: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	fr := FieldsRead(p)
	if want := FieldBitPath | FieldBitUID; fr[0] != want {
		t.Errorf("process fields = %v, want %v", FieldNames(fr[0]), FieldNames(want))
	}
	if fr[1] != 0 {
		t.Errorf("file fields = %v, want none (no file rules)", FieldNames(fr[1]))
	}
	if want := FieldBitRemotePort | FieldBitRemoteAddr; fr[2] != want {
		t.Errorf("network fields = %v, want %v", FieldNames(fr[2]), FieldNames(want))
	}

	src, err := GenerateRust(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"pub extern \"C\" fn warmor_fields_read(event_type: u32) -> u32",
		"0 => 0x00000012,", // path|uid
		"1 => 0x00000000,",
		"2 => 0x00000600,", // remote_addr|remote_port
		"_ => 0xFFFFFFFF,",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("generated Rust missing %q", want)
		}
	}
}

func TestFieldBit_EveryConditionFieldHasABit(t *testing.T) {
	// A field the schema accepts but FieldsRead cannot represent would make
	// the declaration claim independence from it.
	for _, ev := range []string{"process", "file", "network"} {
		for _, f := range fieldsForEvent(ev) {
			if b := FieldBit(f); b == FieldsUnknown || b == 0 {
				t.Errorf("field %q (%s) has no fields-read bit", f, ev)
			}
		}
	}
	if FieldBit("cgroup") != FieldsUnknown {
		t.Error("unknown fields must map to FieldsUnknown")
	}
}

func TestGeneratedABIRequiresCallbackSupportOnlyWhenUsed(t *testing.T) {
	for _, tc := range []struct{ event, field, value, version string }{
		{"process", "path", "/bin/tool", "3"},
		{"process", "args", "--flag", "5"},
		{"network", "operation", "connect", "5"},
	} {
		p := &Policy{Name: "abi", Version: 1, Rules: []Rule{{Name: "r", Event: tc.event, Action: "deny", Conditions: Conditions{All: []Condition{{Field: tc.field, Operator: "eq", Value: tc.value}}}}}}
		src, err := GenerateRust(p)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(src, "fn abi_version() -> u32 {\n    "+tc.version) {
			t.Fatalf("%s policy has wrong ABI declaration", tc.field)
		}
		if fmt.Sprint(PolicyABIVersion(p)) != tc.version || strings.Count(src, "fn abi_version()") != 1 {
			t.Fatal("controller ABI prediction diverged or duplicated export")
		}
	}
}
