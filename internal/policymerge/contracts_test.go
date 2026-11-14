package policymerge

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCompilerValidationContracts(t *testing.T) {
	for _, cond := range []map[string]any{
		{"uid": -1}, {"remote_port": 65536}, {"path": "$missing"},
		{"path": map[string]any{"gt": 1}}, {"path": map[string]any{"any_of": "not-a-list"}},
		{"comm": "sh", "path": "/bin/sh"},
	} {
		p := &PolicyYAML{Name: "test", Version: 1, Rules: []RuleYAML{{Name: "r", Event: "process", Action: "allow", Conditions: ConditionsYAML{All: []map[string]any{cond}}}}}
		if err := Validate(p); err == nil {
			t.Errorf("accepted invalid condition: %#v", cond)
		}
	}
	p := &PolicyYAML{Name: "test", Version: 1, Rules: []RuleYAML{{Name: "r", Event: "process", Action: "deny", Conditions: ConditionsYAML{All: []map[string]any{{"comm": "sh"}}}, Temporal: map[string]any{"unknown_window": true}}}}
	if err := Validate(p); err == nil {
		t.Fatal("accepted invalid temporal semantics")
	}
	p.Rules[0].Temporal = nil
	p.Rules = append(p.Rules, p.Rules[0])
	if err := Validate(p); err == nil {
		t.Fatal("accepted duplicate rule names")
	}
}

func TestLoadFileRejectsUnknownOriginalFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	data := "name: test\nversion: 1\ndefault_actoin: deny\nrules:\n- name: r\n  event: process\n  action: allow\n  conditions:\n    all:\n    - comm: sh\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("accepted misspelled default action")
	}
}
