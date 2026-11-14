package policymerge

import (
	"strings"
	"testing"
)

func TestValidateValid(t *testing.T) {
	p := &PolicyYAML{
		Name:          "test",
		Version:       1,
		DefaultAction: "deny",
		Rules: []RuleYAML{{
			Name:  "allow-nginx",
			Event: "process",
			Conditions: ConditionsYAML{
				All: []map[string]any{{"path": map[string]any{"eq": "/usr/sbin/nginx"}}},
			},
			Action: "allow",
		}},
	}
	if err := Validate(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateMissingName(t *testing.T) {
	p := &PolicyYAML{Version: 1, DefaultAction: "deny", Rules: []RuleYAML{{
		Name: "r", Event: "process", Action: "allow",
		Conditions: ConditionsYAML{All: []map[string]any{{"path": map[string]any{"eq": "/x"}}}},
	}}}
	err := Validate(p)
	if err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Errorf("expected name required error, got: %v", err)
	}
}

func TestValidateVersionZero(t *testing.T) {
	p := &PolicyYAML{Name: "x", Version: 0, DefaultAction: "deny", Rules: []RuleYAML{{
		Name: "r", Event: "process", Action: "allow",
		Conditions: ConditionsYAML{All: []map[string]any{{"path": map[string]any{"eq": "/x"}}}},
	}}}
	err := Validate(p)
	if err == nil || !strings.Contains(err.Error(), "version must be >= 1") {
		t.Errorf("expected version error, got: %v", err)
	}
}

func TestValidateNoRules(t *testing.T) {
	p := &PolicyYAML{Name: "x", Version: 1, DefaultAction: "deny"}
	err := Validate(p)
	if err == nil || !strings.Contains(err.Error(), "at least one rule") {
		t.Errorf("expected no-rules error, got: %v", err)
	}
}

func TestValidateInvalidEvent(t *testing.T) {
	p := &PolicyYAML{Name: "x", Version: 1, DefaultAction: "deny", Rules: []RuleYAML{{
		Name: "r", Event: "disk", Action: "allow",
		Conditions: ConditionsYAML{All: []map[string]any{{"path": map[string]any{"eq": "/x"}}}},
	}}}
	err := Validate(p)
	if err == nil || !strings.Contains(err.Error(), "invalid event") {
		t.Errorf("expected invalid event error, got: %v", err)
	}
}

func TestValidateInvalidAction(t *testing.T) {
	p := &PolicyYAML{Name: "x", Version: 1, DefaultAction: "deny", Rules: []RuleYAML{{
		Name: "r", Event: "process", Action: "block",
		Conditions: ConditionsYAML{All: []map[string]any{{"path": map[string]any{"eq": "/x"}}}},
	}}}
	err := Validate(p)
	if err == nil || !strings.Contains(err.Error(), "invalid action") {
		t.Errorf("expected invalid action error, got: %v", err)
	}
}

func TestValidateInvalidField(t *testing.T) {
	p := &PolicyYAML{Name: "x", Version: 1, DefaultAction: "deny", Rules: []RuleYAML{{
		Name: "r", Event: "process", Action: "allow",
		Conditions: ConditionsYAML{All: []map[string]any{{"bogus_field": map[string]any{"eq": "x"}}}},
	}}}
	err := Validate(p)
	if err == nil || !strings.Contains(err.Error(), "not valid for event type") {
		t.Errorf("expected invalid field error, got: %v", err)
	}
}

func TestValidateNoConditions(t *testing.T) {
	p := &PolicyYAML{Name: "x", Version: 1, DefaultAction: "deny", Rules: []RuleYAML{{
		Name: "r", Event: "process", Action: "allow",
		Conditions: ConditionsYAML{},
	}}}
	err := Validate(p)
	if err == nil || !strings.Contains(err.Error(), "at least one condition") {
		t.Errorf("expected no-condition error, got: %v", err)
	}
}

func TestValidateInvalidDefaultAction(t *testing.T) {
	p := &PolicyYAML{Name: "x", Version: 1, DefaultAction: "reject", Rules: []RuleYAML{{
		Name: "r", Event: "process", Action: "allow",
		Conditions: ConditionsYAML{All: []map[string]any{{"path": map[string]any{"eq": "/x"}}}},
	}}}
	err := Validate(p)
	if err == nil || !strings.Contains(err.Error(), "invalid default_action") {
		t.Errorf("expected invalid default_action error, got: %v", err)
	}
}

func TestValidateNetworkFields(t *testing.T) {
	p := &PolicyYAML{Name: "x", Version: 1, DefaultAction: "deny", Rules: []RuleYAML{{
		Name: "r", Event: "network", Action: "deny",
		Conditions: ConditionsYAML{All: []map[string]any{{"remote_addr": map[string]any{"eq": "10.0.0.1"}}}},
	}}}
	if err := Validate(p); err != nil {
		t.Fatalf("valid network rule rejected: %v", err)
	}
}

func TestValidateFileFields(t *testing.T) {
	p := &PolicyYAML{Name: "x", Version: 1, DefaultAction: "deny", Rules: []RuleYAML{{
		Name: "r", Event: "file", Action: "allow",
		Conditions: ConditionsYAML{All: []map[string]any{{"operation": map[string]any{"eq": "read"}}}},
	}}}
	if err := Validate(p); err != nil {
		t.Fatalf("valid file rule rejected: %v", err)
	}
}
