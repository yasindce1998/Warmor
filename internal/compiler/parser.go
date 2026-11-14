package compiler

import (
	"bytes"
	"fmt"
	"io"
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
	// Establish framing before decoding interface-valued operands. Decoding a
	// rejected trailing document into any expands its aliases first, allowing
	// invalid input to allocate well beyond its syntactic size. yaml.Node keeps
	// aliases as references; KnownFields still applies to the typed decode below.
	if err := validateDocumentFraming(data); err != nil {
		return nil, err
	}
	var raw rawPolicy
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil {
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

func validateDocumentFraming(data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("parse YAML: %w", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("parse YAML: expected exactly one YAML document")
	}
	return nil
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
		var err error
		cond.Value, err = resolveVariables(value, variables)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", field, err)
		}
	}

	return cond, nil
}

func extractOperator(m map[string]interface{}, variables map[string]interface{}) (string, interface{}, error) {
	if len(m) != 1 {
		return "", nil, fmt.Errorf("operator map must have exactly one key, got %d", len(m))
	}

	for op, val := range m {
		var err error
		val, err = resolveVariables(val, variables)
		if err != nil {
			return "", nil, err
		}
		switch op {
		case "eq", "not", "any_of", "none_of", "glob", "gt", "lt", "gte", "lte", "starts_with", "contains":
			return op, val, nil
		default:
			return "", nil, fmt.Errorf("unknown operator %q", op)
		}
	}
	return "", nil, fmt.Errorf("empty operator")
}

func resolveVariables(value interface{}, variables map[string]interface{}) (interface{}, error) {
	r := variableResolver{variables: variables, visiting: make(map[string]bool), remaining: 4096, bytes: 1 << 20}
	return r.resolve(value, 0, false)
}

// Limits apply before allocating expanded values. Operands are scalar or
// flat lists, so nested lists are invalid even when reached through aliases.
// Reject them immediately rather than traversing an exponentially expanding
// reference graph only to reject its type afterwards.
type variableResolver struct {
	variables map[string]interface{}
	visiting  map[string]bool
	remaining int
	bytes     int
}

func (r *variableResolver) resolve(value interface{}, depth int, inList bool) (interface{}, error) {
	if depth > 32 || r.remaining <= 0 {
		return nil, fmt.Errorf("variable expansion limit exceeded (maximum depth 32, 4096 values)")
	}
	r.remaining--
	switch v := value.(type) {
	case string:
		r.bytes -= len(v)
		if r.bytes < 0 {
			return nil, fmt.Errorf("variable expansion exceeds 1 MiB")
		}
		if strings.HasPrefix(v, "$$") {
			return v[1:], nil // Explicit escape for a literal leading dollar.
		}
		if strings.HasPrefix(v, "$") {
			varName := v[1:]
			resolved, ok := r.variables[varName]
			if !ok {
				return nil, fmt.Errorf("undefined variable %q (use $$ for a literal leading dollar)", varName)
			}
			if r.visiting[varName] {
				return nil, fmt.Errorf("cyclic variable reference %q", varName)
			}
			r.visiting[varName] = true
			result, err := r.resolve(resolved, depth+1, inList)
			delete(r.visiting, varName)
			return result, err
		}
		return v, nil
	case []interface{}:
		if inList {
			return nil, fmt.Errorf("nested operand lists are not supported; expected a scalar list item")
		}
		if len(v) > r.remaining {
			return nil, fmt.Errorf("variable expansion limit exceeded (maximum 4096 values)")
		}
		resolved := make([]interface{}, len(v))
		for i, item := range v {
			var err error
			resolved[i], err = r.resolve(item, depth+1, true)
			if err != nil {
				return nil, fmt.Errorf("[%d]: %w", i, err)
			}
		}
		return resolved, nil
	default:
		return value, nil
	}
}
