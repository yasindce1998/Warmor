package compiler

import (
	"fmt"
	"math"
	"unicode/utf8"

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
	if !utf8.ValidString(p.Name) {
		return fmt.Errorf("policy name must be valid UTF-8")
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
	names := make(map[string]bool, len(p.Rules))
	for i, rule := range p.Rules {
		if names[rule.Name] {
			return fmt.Errorf("rule[%d]: duplicate rule name %q", i, rule.Name)
		}
		names[rule.Name] = true
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
	if !utf8.ValidString(r.Name) || !utf8.ValidString(r.Reason) {
		return fmt.Errorf("rule name and reason must be valid UTF-8")
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
	switch c.Operator {
	case "eq", "not", "any_of", "none_of":
	case "gt", "lt", "gte", "lte":
		if !isNumericField(c.Field) {
			return fmt.Errorf("operator %q is not supported for string field %q", c.Operator, c.Field)
		}
	case "glob", "starts_with", "contains":
		if isNumericField(c.Field) {
			return fmt.Errorf("operator %q is not supported for numeric field %q", c.Operator, c.Field)
		}
	default:
		return fmt.Errorf("unknown operator %q", c.Operator)
	}
	if c.Operator == "any_of" || c.Operator == "none_of" {
		var items []interface{}
		switch v := c.Value.(type) {
		case []interface{}:
			items = v
		case []string:
			for _, s := range v {
				items = append(items, s)
			}
		}
		if len(items) == 0 {
			return fmt.Errorf("field %q: %s requires a non-empty list", c.Field, c.Operator)
		}
		for i, item := range items {
			if err := validateConditionValue(c.Field, item); err != nil {
				return fmt.Errorf("%s[%d]: %w", c.Operator, i, err)
			}
		}
		return nil
	}
	return validateConditionValue(c.Field, c.Value)
}

func validateConditionValue(field string, value interface{}) error {
	if !isNumericField(field) {
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("field %q requires a string, got %T", field, value)
		}
		if !utf8.ValidString(s) {
			return fmt.Errorf("field %q requires valid UTF-8", field)
		}
		return nil
	}
	maxValue := uint64(math.MaxUint32)
	if field == "remote_port" || field == "local_port" {
		maxValue = math.MaxUint16
	}
	valid := false
	switch n := value.(type) {
	case int:
		valid = n >= 0 && uint64(n) <= maxValue
	case int64:
		valid = n >= 0 && uint64(n) <= maxValue
	case uint64:
		valid = n <= maxValue
	case float64:
		valid = n >= 0 && n <= float64(maxValue) && math.Trunc(n) == n
	}
	if !valid {
		return fmt.Errorf("field %q requires an unsigned integer in [0, %d], got %T", field, maxValue, value)
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
const Version = "6"
