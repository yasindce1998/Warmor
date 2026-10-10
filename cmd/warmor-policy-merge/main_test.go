package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yasindce1998/warmor/internal/policymerge"
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

// invalidForValidate parses fine but fails policymerge.Validate (bad event).
const invalidForValidate = `name: policy-c
version: 1
rules:
  - name: weird
    event: telepathy
    conditions:
      all:
        - path:
            eq: /x
    action: allow
`

func writePolicies(t *testing.T) (dir, a, b string) {
	t.Helper()
	dir = t.TempDir()
	a = writeFile(t, filepath.Join(dir, "a.yaml"), policyA)
	b = writeFile(t, filepath.Join(dir, "b.yaml"), policyB)
	return dir, a, b
}

func loadMerged(t *testing.T, path string) *policymerge.PolicyYAML {
	t.Helper()
	p, err := policymerge.LoadFile(path)
	if err != nil {
		t.Fatalf("merged output not loadable: %v", err)
	}
	return p
}

func ruleNames(p *policymerge.PolicyYAML) map[string]bool {
	m := map[string]bool{}
	for _, r := range p.Rules {
		m[r.Name] = true
	}
	return m
}

func TestMerge_UnionToStdout(t *testing.T) {
	dir, a, b := writePolicies(t)
	stdout, stderr := runMain(t, "", "-name", "combined", a, b)
	assertContains(t, "stderr", stderr, "Merged 2 policies (3 rules, 1 deduplicated)")

	out := writeFile(t, filepath.Join(dir, "stdout.yaml"), stdout)
	p := loadMerged(t, out)
	if p.Name != "combined" {
		t.Errorf("name = %q, want combined", p.Name)
	}
	names := ruleNames(p)
	for _, n := range []string{"allow-nginx", "deny-tmp", "log-etc"} {
		if !names[n] {
			t.Errorf("merged policy missing rule %q: %v", n, names)
		}
	}
	// The strictest default action wins.
	if p.DefaultAction != "deny" {
		t.Errorf("default_action = %q, want deny", p.DefaultAction)
	}
}

func TestMerge_IntersectionToFile(t *testing.T) {
	dir, a, b := writePolicies(t)
	outPath := filepath.Join(dir, "merged.yaml")
	stdout, stderr := runMain(t, "", "-strategy", "intersection", "-o", outPath, a, b)
	if stdout != "" {
		t.Errorf("stdout should be empty, got %q", stdout)
	}
	assertContains(t, "stderr", stderr, "→ "+outPath)
	p := loadMerged(t, outPath)
	names := ruleNames(p)
	if len(p.Rules) != 1 || !names["allow-nginx"] {
		t.Errorf("intersection rules = %v, want only allow-nginx", names)
	}
}

func TestMerge_DirValidateDenyWins(t *testing.T) {
	dir, _, _ := writePolicies(t)
	// Non-YAML files and subdirectories are ignored by --dir.
	writeFile(t, filepath.Join(dir, "README.txt"), "ignore me")
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(t.TempDir(), "merged.yaml")

	_, stderr := runMain(t, "", "-dir", dir, "-validate", "-strategy", "deny-wins", "-o", outPath)
	assertContains(t, "stderr", stderr, "Loaded 2 policies from "+dir, "Validation passed", "Merged 2 policies")
	p := loadMerged(t, outPath)
	if err := policymerge.Validate(p); err != nil {
		t.Errorf("merged output does not validate: %v", err)
	}
}

// Flags given after positional args, including a trailing "-o <file>", are
// still parsed as flags.
func TestMerge_DirPlusFilesAndTrailingOutput(t *testing.T) {
	dir, _, _ := writePolicies(t)
	extraDir := t.TempDir()
	c := writeFile(t, filepath.Join(extraDir, "c.yaml"), `name: policy-c
version: 1
default_action: log
rules:
  - name: log-net
    event: network
    conditions:
      all:
        - remote_port:
            eq: 22
    action: log
`)
	outPath := filepath.Join(t.TempDir(), "merged.yaml")
	_, stderr := runMain(t, "", "-dir", dir, "-annotate=false", "-dedup=false", c, "-o", outPath)
	assertContains(t, "stderr", stderr, "Merged 3 policies", "0 deduplicated")
	p := loadMerged(t, outPath)
	if !ruleNames(p)["log-net"] {
		t.Errorf("rule from positional file missing: %v", ruleNames(p))
	}
}

// Every flag form works in any position; previously only a bare trailing
// "-o <file>" was recognised and anything else became a file name.
func TestMerge_FlagsAfterFiles(t *testing.T) {
	_, a, b := writePolicies(t)
	outPath := filepath.Join(t.TempDir(), "merged.yaml")
	for _, args := range [][]string{
		{a, b, "-o=" + outPath, "-strategy", "intersection", "-name=late"},
		{a, "--strategy=intersection", b, "--o", outPath, "--name", "late"},
	} {
		os.Remove(outPath)
		stdout, _ := runMain(t, "", args...)
		if stdout != "" {
			t.Errorf("%v: stdout should be empty, got %q", args, stdout)
		}
		p := loadMerged(t, outPath)
		if p.Name != "late" || len(p.Rules) != 1 {
			t.Errorf("%v: name=%q rules=%d, want late/1 (trailing flags ignored)", args, p.Name, len(p.Rules))
		}
	}
}

func TestMerge_DoubleDashEndsFlags(t *testing.T) {
	// After "--" a dash-prefixed argument is a file name, not a flag.
	_, a, _ := writePolicies(t)
	r := runChild(t, nil, a, "--", "-validate")
	if r.code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", r.code, r.stderr)
	}
	assertContains(t, "stderr", r.stderr, "-validate")
}

func TestMerge_UnknownTrailingFlagRejected(t *testing.T) {
	_, a, b := writePolicies(t)
	r := runChild(t, nil, a, b, "--bogus")
	if r.code != 2 {
		t.Errorf("exit = %d, want 2 (stderr: %s)", r.code, r.stderr)
	}
	assertContains(t, "stderr", r.stderr, "flag provided but not defined: -bogus")
}

func TestMerge_Errors(t *testing.T) {
	dir, a, b := writePolicies(t)
	invalid := writeFile(t, filepath.Join(t.TempDir(), "c.yaml"), invalidForValidate)
	noName := writeFile(t, filepath.Join(t.TempDir(), "n.yaml"), "version: 1\n")
	emptyDir := t.TempDir()

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no inputs", nil, "at least 2 policies required"},
		{"one input", []string{a}, "at least 2 policies required"},
		{"missing file", []string{a, filepath.Join(dir, "nope.yaml")}, "error: read"},
		{"no name", []string{a, noName}, "policy name is required"},
		{"bad dir", []string{"-dir", filepath.Join(dir, "missing")}, "read directory"},
		{"empty dir", []string{"-dir", emptyDir}, "no .yaml/.yml policy files"},
		{"bad strategy", []string{"-strategy", "chaos", a, b}, "unknown strategy"},
		{"validate fails", []string{"-validate", a, invalid}, "validation error"},
		{"unwritable output", []string{"-o", filepath.Join(dir, "no", "dir", "x.yaml"), a, b}, "error: write"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runChild(t, nil, tt.args...)
			if r.code != 1 {
				t.Errorf("exit = %d, want 1 (stderr: %s)", r.code, r.stderr)
			}
			assertContains(t, "stderr", r.stderr, tt.want)
		})
	}
}

func TestMerge_Version(t *testing.T) {
	r := runChild(t, nil, "-version")
	if r.code != 0 {
		t.Fatalf("exit = %d", r.code)
	}
	assertContains(t, "stdout", r.stdout, "warmor-policy-merge dev")
}
