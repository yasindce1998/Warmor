package main

import (
	"path/filepath"
	"testing"

	"github.com/yasindce1998/warmor/internal/policymerge"
)

func TestLearn_ShortSessionToFile(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "learned.yaml")
	stdout, stderr := runMain(t, "", "-duration", "10ms", "-cgroup", "123, 456,,", "-name", "learned-app", "-o", outPath)
	if stdout != "" {
		t.Errorf("stdout should be empty with -o, got %q", stdout)
	}
	assertContains(t, "stderr", stderr,
		"Starting learning session (duration: 10ms, cgroups: [123 456])",
		"Recorder sink name:",
		"Learning complete: learned 0 containers",
		"Policy written to "+outPath)

	p, err := policymerge.LoadFile(outPath)
	if err != nil {
		t.Fatalf("learned policy not loadable: %v", err)
	}
	if p.Name != "learned-app" {
		t.Errorf("name = %q, want learned-app", p.Name)
	}
	// NOTE: the recorder is never attached to an event source in main(), so a
	// real session always learns nothing. See report.
	if len(p.Rules) != 0 {
		t.Logf("learned %d rules (recorder now wired?)", len(p.Rules))
	}
}

func TestLearn_StdoutAllCgroups(t *testing.T) {
	stdout, stderr := runMain(t, "", "-duration", "5ms")
	assertContains(t, "stderr", stderr, "cgroups: []")
	if stdout == "" {
		t.Error("policy YAML should be written to stdout")
	}
}

func TestLearn_Errors(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"bad cgroup", []string{"-cgroup", "12,abc"}, `invalid cgroup ID "abc"`},
		{"negative cgroup", []string{"-cgroup", "-5"}, `invalid cgroup ID "-5"`},
		{"unwritable output", []string{"-duration", "1ms", "-o", filepath.Join(dir, "x", "y", "p.yaml")}, "error writing"},
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

func TestLearn_Version(t *testing.T) {
	r := runChild(t, nil, "-version")
	if r.code != 0 {
		t.Fatalf("exit = %d", r.code)
	}
	assertContains(t, "stdout", r.stdout, "warmor-learn dev")
}
