package compiler

import (
	"fmt"

	"github.com/yasindce1998/warmor/internal/temporal"
)

type Policy struct {
	Name          string                 `yaml:"name"`
	Version       int                    `yaml:"version"`
	Description   string                 `yaml:"description,omitempty"`
	Variables     map[string]interface{} `yaml:"variables,omitempty"`
	Rules         []Rule                 `yaml:"rules"`
	DefaultAction string                 `yaml:"default_action"`
}

type Rule struct {
	Name       string     `yaml:"name"`
	Event      string     `yaml:"event"`
	Conditions Conditions `yaml:"conditions"`
	Action     string     `yaml:"action"`
	Mode       string     `yaml:"mode,omitempty"`
	Reason     string     `yaml:"reason,omitempty"`
	// Temporal is the rule's temporal: block (nil: none). The action only
	// applies outside this window; see temporal.go.
	Temporal *temporal.Constraint `yaml:"-"`
}

type Conditions struct {
	All []Condition `yaml:"all,omitempty"`
	Any []Condition `yaml:"any,omitempty"`
	Not []Condition `yaml:"not,omitempty"`
}

type Condition struct {
	Field    string
	Operator string
	Value    interface{}
}

type ConditionOperator struct {
	Eq         interface{} `yaml:"eq,omitempty"`
	Not        interface{} `yaml:"not,omitempty"`
	AnyOf      interface{} `yaml:"any_of,omitempty"`
	NoneOf     interface{} `yaml:"none_of,omitempty"`
	Glob       string      `yaml:"glob,omitempty"`
	Gt         *float64    `yaml:"gt,omitempty"`
	Lt         *float64    `yaml:"lt,omitempty"`
	Gte        *float64    `yaml:"gte,omitempty"`
	Lte        *float64    `yaml:"lte,omitempty"`
	StartsWith string      `yaml:"starts_with,omitempty"`
	Contains   string      `yaml:"contains,omitempty"`
}

func (p *Policy) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	if p.Version < 1 {
		return fmt.Errorf("policy version must be >= 1")
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("policy must have at least one rule")
	}
	if p.DefaultAction == "" {
		p.DefaultAction = "allow"
	}
	if !isValidAction(p.DefaultAction) {
		return fmt.Errorf("invalid default_action %q (must be allow, deny, or log)", p.DefaultAction)
	}
	for i, rule := range p.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("rule[%d] %q: %w", i, rule.Name, err)
		}
	}
	return nil
}

func (r *Rule) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if !isValidEvent(r.Event) {
		return fmt.Errorf("invalid event type %q (must be process, file, or network)", r.Event)
	}
	if !isValidAction(r.Action) {
		return fmt.Errorf("invalid action %q (must be allow, deny, or log)", r.Action)
	}
	if r.Mode != "" && r.Mode != "enforce" && r.Mode != "audit" {
		return fmt.Errorf("invalid mode %q (must be enforce or audit)", r.Mode)
	}
	if len(r.Conditions.All) == 0 && len(r.Conditions.Any) == 0 && len(r.Conditions.Not) == 0 {
		return fmt.Errorf("rule must have at least one condition")
	}
	for i, cond := range r.Conditions.All {
		if err := cond.Validate(r.Event); err != nil {
			return fmt.Errorf("conditions.all[%d]: %w", i, err)
		}
	}
	for i, cond := range r.Conditions.Any {
		if err := cond.Validate(r.Event); err != nil {
			return fmt.Errorf("conditions.any[%d]: %w", i, err)
		}
	}
	for i, cond := range r.Conditions.Not {
		if err := cond.Validate(r.Event); err != nil {
			return fmt.Errorf("conditions.not[%d]: %w", i, err)
		}
	}
	return validateTemporal(r)
}

func (c *Condition) Validate(eventType string) error {
	if c.Field == "" {
		return fmt.Errorf("condition field is required")
	}
	if c.Operator == "" {
		return fmt.Errorf("condition operator is required")
	}
	validFields := fieldsForEvent(eventType)
	found := false
	for _, f := range validFields {
		if f == c.Field {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("field %q is not valid for event type %q", c.Field, eventType)
	}
	return nil
}

func fieldsForEvent(eventType string) []string {
	switch eventType {
	case "process":
		return []string{"pid", "uid", "gid", "comm", "path", "args"}
	case "file":
		return []string{"pid", "uid", "gid", "comm", "path", "operation", "flags"}
	case "network":
		return []string{"pid", "uid", "gid", "comm", "operation", "protocol", "remote_addr", "remote_port", "local_port"}
	default:
		return nil
	}
}

func isValidAction(action string) bool {
	return action == "allow" || action == "deny" || action == "log"
}

func isValidEvent(event string) bool {
	return event == "process" || event == "file" || event == "network"
}

// Version identifies the YAML-to-WASM compiler. Bump it whenever the output
// for an unchanged YAML policy changes (codegen, ABI or build settings), so
// cached compiled policies are rebuilt.
const Version = "3"
