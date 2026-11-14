package compiler

import (
	"math"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func safetyPolicy() *Policy {
	return &Policy{Name: "safe", Version: 1, DefaultAction: "allow", Rules: []Rule{{
		Name: "r", Event: "process", Action: "deny",
		Conditions: Conditions{All: []Condition{{Field: "comm", Operator: "eq", Value: "x"}}},
	}}}
}

func TestCodegenUntrustedNamesAndStrings(t *testing.T) {
	p := safetyPolicy()
	p.Name = "policy\ncompile_error!(\"policy injection\");\r\n\"\n[dependencies.attacker]\npath = \"/tmp/evil\""
	p.Rules[0].Name = "rule\r\ncompile_error!(\"rule injection\");\u2028line"
	p.Rules[0].Reason = "reason\a\b\f\v\x00\x1b\x7f\u0085\u2028\u2029\U0001f512\"\\"
	for _, op := range []string{"eq", "not", "any_of", "none_of", "glob", "starts_with", "contains"} {
		c := Condition{Field: "comm", Operator: op, Value: p.Rules[0].Reason}
		if op == "any_of" || op == "none_of" {
			c.Value = []string{p.Rules[0].Reason}
		}
		p.Rules[0].Conditions.Any = append(p.Rules[0].Conditions.Any, c)
	}
	src, err := GenerateRust(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(src, "\n") {
		if strings.Contains(line, "compile_error!") && !strings.HasPrefix(strings.TrimSpace(line), "//") && !strings.Contains(line, `"Rule: `) {
			t.Fatalf("name escaped its comment/string: %s", line)
		}
	}
	if !strings.Contains(src, `\u{7}`) || !strings.Contains(src, `\u{85}`) || strings.Contains(src, `\a`) {
		t.Fatal("Go-only string escapes in Rust source")
	}
	toml := GenerateCargoToml(p.Name)
	if strings.Contains(toml, "attacker") || strings.Contains(toml, "/tmp/evil") || !strings.Contains(toml, "warmor-policy-id_") {
		t.Fatalf("unsafe TOML: %s", toml)
	}
	if testing.Short() || !CargoAvailable() {
		return
	}
	result, err := Build(p, BuildOptions{OutputPath: filepath.Join(t.TempDir(), "safe.wasm")})
	defer Cleanup(result)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCrateIdentifierBoundedAndSafe(t *testing.T) {
	valid := regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	for _, name := range []string{"test-policy", "with spaces", "../escape", "\"\n[dependencies]", "💣", strings.Repeat("a", 4096), ""} {
		id := crateIdentifier(name)
		if len(id) > 67 || !valid.MatchString(id) || id != crateIdentifier(name) {
			t.Errorf("unsafe/non-deterministic identifier %q", id)
		}
	}
	if crateIdentifier("test-policy") != "test_policy" {
		t.Fatal("legacy safe crate identifier changed")
	}
}

type injectedNumber struct{}

func (injectedNumber) String() string { return "0; compile_error!(\"injected\"); 0" }

func TestNumericCodegenUsesOnlyValidatedIntegers(t *testing.T) {
	for _, value := range []any{int(0), int64(42), uint64(math.MaxUint32), float64(math.MaxUint32)} {
		p := safetyPolicy()
		p.Rules[0].Conditions.All[0] = Condition{Field: "uid", Operator: "eq", Value: value}
		src, err := GenerateRust(p)
		if err != nil || !strings.Contains(src, "uid == "+formatNumeric(value)) {
			t.Errorf("integer %v: %v", value, err)
		}
	}
	for _, value := range []any{injectedNumber{}, "0; panic!()", math.NaN(), math.Inf(1), 1.5, int64(-1), uint64(math.MaxUint32) + 1} {
		p := safetyPolicy()
		p.Rules[0].Conditions.All[0] = Condition{Field: "uid", Operator: "eq", Value: value}
		if _, err := GenerateRust(p); err == nil {
			t.Errorf("invalid numeric value accepted: %v", value)
		}
	}
}

func TestCodegenRejectsInvalidUTF8RatherThanReplacingBytes(t *testing.T) {
	for _, field := range []string{"policy", "rule", "reason", "condition"} {
		p := safetyPolicy()
		switch field {
		case "policy":
			p.Name = "\xff"
		case "rule":
			p.Rules[0].Name = "\xff"
		case "reason":
			p.Rules[0].Reason = "\xff"
		case "condition":
			p.Rules[0].Conditions.All[0].Value = "\xff"
		}
		if _, err := GenerateRust(p); err == nil {
			t.Errorf("invalid UTF-8 %s accepted", field)
		}
	}
}
