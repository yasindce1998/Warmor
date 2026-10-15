package compiler

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

func ParseFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (*Policy, error) {
	var raw rawPolicy
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	policy := &Policy{
		Name:          raw.Name,
		Version:       raw.Version,
		Description:   raw.Description,
		Variables:     raw.Variables,
		DefaultAction: raw.DefaultAction,
	}

	for i, rr := range raw.Rules {
		rule, err := parseRule(rr, policy.Variables)
		if err != nil {
			return nil, fmt.Errorf("rule[%d]: %w", i, err)
		}
		policy.Rules = append(policy.Rules, *rule)
	}

	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	return policy, nil
}

type rawPolicy struct {
	Name          string                 `yaml:"name"`
	Version       int                    `yaml:"version"`
	Description   string                 `yaml:"description,omitempty"`
	Variables     map[string]interface{} `yaml:"variables,omitempty"`
	Rules         []rawRule              `yaml:"rules"`
	DefaultAction string                 `yaml:"default_action"`
}

type rawRule struct {
	Name       string        `yaml:"name"`
	Event      string        `yaml:"event"`
	Conditions rawConditions `yaml:"conditions"`
	Action     string        `yaml:"action"`
	Mode       string        `yaml:"mode,omitempty"`
	Reason     string        `yaml:"reason,omitempty"`
	Temporal   yaml.Node     `yaml:"temporal,omitempty"`
}

type rawConditions struct {
	All []map[string]interface{} `yaml:"all,omitempty"`
	Any []map[string]interface{} `yaml:"any,omitempty"`
	Not []map[string]interface{} `yaml:"not,omitempty"`
}

func parseRule(rr rawRule, variables map[string]interface{}) (*Rule, error) {
	rule := &Rule{
		Name:   rr.Name,
		Event:  rr.Event,
		Action: rr.Action,
		Mode:   rr.Mode,
		Reason: rr.Reason,
	}

	var err error
	rule.Conditions.All, err = parseConditionList(rr.Conditions.All, variables)
	if err != nil {
		return nil, fmt.Errorf("conditions.all: %w", err)
	}
	rule.Conditions.Any, err = parseConditionList(rr.Conditions.Any, variables)
	if err != nil {
		return nil, fmt.Errorf("conditions.any: %w", err)
	}
	rule.Conditions.Not, err = parseConditionList(rr.Conditions.Not, variables)
	if err != nil {
		return nil, fmt.Errorf("conditions.not: %w", err)
	}

	if rr.Temporal.Kind != 0 { // the key is present
		var raw map[string]interface{}
		if rr.Temporal.Kind != yaml.MappingNode || rr.Temporal.Decode(&raw) != nil {
			return nil, fmt.Errorf("temporal: must be a map of constraints (line %d)", rr.Temporal.Line)
		}
		rule.Temporal, err = parseTemporal(raw)
		if err != nil {
			return nil, fmt.Errorf("temporal: %w", err)
		}
	}

	return rule, nil
}

func parseConditionList(raw []map[string]interface{}, variables map[string]interface{}) ([]Condition, error) {
	var conditions []Condition
	for i, entry := range raw {
		cond, err := parseCondition(entry, variables)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		conditions = append(conditions, *cond)
	}
	return conditions, nil
}

func parseCondition(entry map[string]interface{}, variables map[string]interface{}) (*Condition, error) {
	if len(entry) != 1 {
		return nil, fmt.Errorf("condition must have exactly one field, got %d", len(entry))
	}

	var field string
	var value interface{}
	for k, v := range entry {
		field = k
		value = v
	}

	value = resolveVariables(value, variables)

	cond := &Condition{Field: field}

	switch v := value.(type) {
	case map[string]interface{}:
		op, val, err := extractOperator(v, variables)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", field, err)
		}
		cond.Operator = op
		cond.Value = val
	default:
		cond.Operator = "eq"
		cond.Value = value
	}

	return cond, nil
}

func extractOperator(m map[string]interface{}, variables map[string]interface{}) (string, interface{}, error) {
	if len(m) != 1 {
		return "", nil, fmt.Errorf("operator map must have exactly one key, got %d", len(m))
	}

	for op, val := range m {
		val = resolveVariables(val, variables)
		switch op {
		case "eq", "not", "any_of", "none_of", "glob", "gt", "lt", "gte", "lte", "starts_with", "contains":
			return op, val, nil
		default:
			return "", nil, fmt.Errorf("unknown operator %q", op)
		}
	}
	return "", nil, fmt.Errorf("empty operator")
}

func resolveVariables(value interface{}, variables map[string]interface{}) interface{} {
	switch v := value.(type) {
	case string:
		if strings.HasPrefix(v, "$") {
			varName := v[1:]
			if resolved, ok := variables[varName]; ok {
				return resolved
			}
		}
		return v
	case []interface{}:
		resolved := make([]interface{}, len(v))
		for i, item := range v {
			resolved[i] = resolveVariables(item, variables)
		}
		return resolved
	default:
		return value
	}
}
