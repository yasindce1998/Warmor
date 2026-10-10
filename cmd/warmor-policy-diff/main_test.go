package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// policyA and policyB share one rule (allow-nginx) and each has one unique rule.
const policyA = `name: policy-a
version: 1
description: first
default_action: allow
rules:
  - name: allow-nginx
    event: process
    conditions:
      all:
        - path:
            eq: /usr/sbin/nginx
    action: allow
  - name: deny-tmp
    event: process
    conditions:
      all:
        - path:
            glob: "/tmp/**"
    action: deny
    reason: no tmp exec
`

const policyB = `name: policy-b
version: 1
description: second
default_action: deny
rules:
  - name: allow-nginx
    event: process
    conditions:
      all:
        - path:
            eq: /usr/sbin/nginx
    action: allow
  - name: log-etc
    event: file
    conditions:
      all:
        - path:
            glob: "/etc/**"
    action: log
`

func writePolicies(t *testing.T) (dir, a, b string) {
	t.Helper()
	dir = t.TempDir()
	a = writeFile(t, filepath.Join(dir, "a.yaml"), policyA)
	b = writeFile(t, filepath.Join(dir, "b.yaml"), policyB)
	return dir, a, b
}

func TestDiff_Detailed(t *testing.T) {
	_, a, b := writePolicies(t)
	out, _ := runMain(t, "", a, b)
	assertContains(t, "detailed diff", out,
		"Only in a.yaml (1 rules)", "deny-tmp",
		"Only in b.yaml (1 rules)", "log-etc")
	if strings.Contains(out, "Only in a.yaml (2") {
		t.Errorf("shared rule counted as unique:\n%s", out)
	}
}

func TestDiff_Summary(t *testing.T) {
	_, a, b := writePolicies(t)
	out, _ := runMain(t, "", "--summary", a, b)
	assertContains(t, "summary", out,
		"Only in a.yaml: 1 rules", "Only in b.yaml: 1 rules", "In both:    1 rules")
	if strings.Contains(out, "deny-tmp") {
		t.Errorf("summary should not list rule names:\n%s", out)
	}
}

func TestDiff_IdenticalPolicies(t *testing.T) {
	_, a, _ := writePolicies(t)
	out, _ := runMain(t, "", "-summary", a, a)
	assertContains(t, "identical", out, "Only in a.yaml: 0 rules", "In both:    2 rules")
}

func TestDiff_OutputFlagBeforeArgs(t *testing.T) {
	dir, a, b := writePolicies(t)
	outPath := filepath.Join(dir, "out.txt")
	stdout, _ := runMain(t, "", "-o", outPath, "-summary", a, b)
	if stdout != "" {
		t.Errorf("stdout should be empty when -o is used, got %q", stdout)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	assertContains(t, "output file", string(data), "In both:    1 rules")
}

// Flags after the positional args are parsed as flags.
func TestDiff_OutputFlagAfterArgs(t *testing.T) {
	dir, a, b := writePolicies(t)
	outPath := filepath.Join(dir, "trailing.txt")
	stdout, _ := runMain(t, "", a, b, "-o", outPath)
	if stdout != "" {
		t.Errorf("stdout should be empty, got %q", stdout)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	assertContains(t, "output file", string(data), "deny-tmp", "log-etc")
}

// Every flag works in any position; previously only a bare "-o <file>" was
// recognised after the files and e.g. "--summary" became a third file.
func TestDiff_FlagsInAnyPosition(t *testing.T) {
	dir, a, b := writePolicies(t)
	outPath := filepath.Join(dir, "o.txt")
	cases := [][]string{
		{a, b, "--summary", "-o=" + outPath},
		{a, "-summary", b, "--o", outPath},
		{"-o", outPath, a, b, "-summary=true"},
	}
	for _, args := range cases {
		os.Remove(outPath)
		stdout, _ := runMain(t, "", args...)
		if stdout != "" {
			t.Errorf("%v: stdout should be empty, got %q", args, stdout)
		}
		data, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		assertContains(t, "output file", string(data), "In both:    1 rules")
		if strings.Contains(string(data), "deny-tmp") {
			t.Errorf("%v: --summary ignored:\n%s", args, data)
		}
	}
}

func TestDiff_DoubleDashEndsFlags(t *testing.T) {
	_, a, _ := writePolicies(t)
	r := runChild(t, nil, a, "--", "-summary")
	if r.code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", r.code, r.stderr)
	}
	assertContains(t, "stderr", r.stderr, "error loading -summary")
}

func TestDiff_UnknownTrailingFlagRejected(t *testing.T) {
	_, a, b := writePolicies(t)
	r := runChild(t, nil, a, b, "--bogus")
	if r.code != 2 {
		t.Errorf("exit = %d, want 2 (stderr: %s)", r.code, r.stderr)
	}
	assertContains(t, "stderr", r.stderr, "flag provided but not defined: -bogus")
}

func TestDiff_ChangedDecision(t *testing.T) {
	dir, a, _ := writePolicies(t)
	// Same rule as policyA's deny-tmp but allowed instead.
	c := writeFile(t, filepath.Join(dir, "c.yaml"), strings.Replace(policyA, "action: deny", "action: allow", 1))
	out, _ := runMain(t, "", a, c)
	assertContains(t, "detailed diff", out, "=== Changed (1 rules) ===", "[process] deny-tmp: action deny -> allow")
	out, _ = runMain(t, "", "--summary", a, c)
	assertContains(t, "summary", out, "Changed:    1 rules", "In both:    1 rules")
}

func TestDiff_Errors(t *testing.T) {
	dir, a, _ := writePolicies(t)
	bad := writeFile(t, filepath.Join(dir, "bad.yaml"), "name: [unclosed")

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no args", nil, "exactly 2 policy files required"},
		{"one arg", []string{a}, "exactly 2 policy files required"},
		{"three args", []string{a, a, a}, "exactly 2 policy files required"},
		{"missing first", []string{filepath.Join(dir, "nope.yaml"), a}, "error loading"},
		{"bad second", []string{a, bad}, "error loading " + bad},
		{"unwritable output", []string{"-o", filepath.Join(dir, "no", "such", "dir"), a, a}, "error writing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runChild(t, nil, tt.args...)
			if r.code != 1 {
				t.Errorf("exit code = %d, want 1 (stderr: %s)", r.code, r.stderr)
			}
			assertContains(t, "stderr", r.stderr, tt.want)
		})
	}
}

func TestDiff_UsageMentionsTool(t *testing.T) {
	r := runChild(t, nil)
	assertContains(t, "usage", r.stderr, "Usage: warmor-policy-diff", "-summary")
}

func TestDiff_Version(t *testing.T) {
	r := runChild(t, nil, "-version")
	if r.code != 0 {
		t.Fatalf("exit = %d", r.code)
	}
	assertContains(t, "stdout", r.stdout, "warmor-policy-diff dev")
}
