package compiler

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseStrictPolicy(t *testing.T) {
	base := "name: strict\nversion: 1\ndefault_action: deny\nrules:\n  - name: r\n    event: process\n    conditions:\n      all:\n        - path: {eq: /bin/tool}\n    action: allow\n"
	for _, tc := range []struct {
		name, yaml, want string
	}{
		{"policy typo", strings.Replace(base, "default_action", "default_actoin", 1), "default_actoin"},
		{"rule typo", strings.Replace(base, "    action:", "    actoin:", 1), "actoin"},
		{"condition group typo", strings.Replace(base, "      all:", "      alll:", 1), "alll"},
		{"temporal typo", base + "    tempral: {max_container_age: 5m}\n", "tempral"},
		{"second document", base + "---\nname: ignored\n", "one YAML document"},
		{"unknown variable", strings.Replace(base, "/bin/tool", "$missing", 1), "undefined variable"},
		{"unknown nested variable", strings.Replace(base, "{eq: /bin/tool}", "{any_of: [/bin/tool, $missing]}", 1), "undefined variable"},
		{"duplicate rule name", base + "  - name: r\n    event: process\n    conditions: {all: [{comm: tool}]}\n    action: deny\n", "duplicate rule name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.yaml)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestConditionValueValidation(t *testing.T) {
	for _, tc := range []struct{ field, expr, want string }{
		{"uid", "{eq: -1}", "unsigned integer"},
		{"uid", "{eq: 4294967296}", "unsigned integer"},
		{"uid", "{eq: 1.5}", "unsigned integer"},
		{"uid", "{eq: root}", "unsigned integer"},
		{"uid", "{contains: root}", "not supported"},
		{"path", "{gt: 3}", "not supported"},
		{"path", "{eq: 12}", "string"},
		{"path", "{glob: 12}", "string"},
		{"path", "{eq: null}", "string"},
		{"path", "{any_of: /bin/tool}", "non-empty list"},
		{"path", "{none_of: []}", "non-empty list"},
		{"path", "{any_of: [/bin/tool, 12]}", "string"},
		{"remote_port", "{eq: 65536}", "unsigned integer"},
		{"remote_port", "{eq: .inf}", "unsigned integer"},
		{"remote_port", "{any_of: [443, -1]}", "unsigned integer"},
	} {
		t.Run(tc.field+tc.expr, func(t *testing.T) {
			event := "process"
			if tc.field == "remote_port" {
				event = "network"
			}
			data := fmt.Sprintf("name: v\nversion: 1\nrules:\n- name: r\n  event: %s\n  action: deny\n  conditions: {all: [{%s: %s}]}\n", event, tc.field, tc.expr)
			if _, err := Parse([]byte(data)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVariablesResolveRecursivelyAndEscapeLiterals(t *testing.T) {
	p, err := Parse([]byte(`name: variables
version: 1
variables:
  first: $second
  second: /bin/tool
rules:
- name: r
  event: process
  action: deny
  conditions: {all: [{path: {any_of: [$first, "$$literal"]}}]}
`))
	if err != nil {
		t.Fatal(err)
	}
	items := p.Rules[0].Conditions.All[0].Value.([]interface{})
	if fmt.Sprint(items) != "[/bin/tool $literal]" {
		t.Fatalf("resolved values = %v", items)
	}
	_, err = Parse([]byte(`name: cycle
version: 1
variables: {a: $b, b: $a}
rules:
- name: r
  event: process
  action: deny
  conditions: {all: [{path: $a}]}
`))
	if err == nil || !strings.Contains(err.Error(), "cyclic variable") {
		t.Fatalf("cycle error = %v", err)
	}
}

func TestGenerateRustValidatesProgrammaticPolicies(t *testing.T) {
	p := &Policy{Name: "p", Version: 1, Rules: []Rule{{Name: "r", Event: "process", Action: "deny", Conditions: Conditions{All: []Condition{{Field: "path", Operator: "typo", Value: "/bin/tool"}}}}}}
	if _, err := GenerateRust(p); err == nil {
		t.Fatal("invalid operator generated code")
	}
}

func TestCompilerExamplesValidateStrictly(t *testing.T) {
	// This example previously used ignored time_constraints: blocks. Keep
	// it tied to the real parser so advertised temporal rules cannot vanish.
	p, err := ParseFile("../../policies/yaml-example/workload/temporal-workload-control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range p.Rules {
		if rule.Temporal == nil || rule.Action == "allow" {
			t.Fatalf("rule lost its temporal constraint: %+v", rule)
		}
	}
}
