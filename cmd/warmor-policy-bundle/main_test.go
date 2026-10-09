package main

import (
	"path/filepath"
	"testing"
)

// Push/Pull success paths need a TLS OCI registry trusted by the system
// (policybundle has no plain-HTTP option), so only argument validation and
// failure handling are exercised here. All targets are local or malformed;
// nothing reaches the external network.
func TestBundle_ArgumentValidation(t *testing.T) {
	wasm := writeFile(t, filepath.Join(t.TempDir(), "p.wasm"), "\x00asm")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"neither push nor pull", nil, "specify --push or --pull"},
		{"both", []string{"-push", "-pull", "-ref", "r", "-wasm", wasm}, "specify only one of --push or --pull"},
		{"push without ref", []string{"-push", "-wasm", wasm}, "--ref is required"},
		{"pull without wasm", []string{"-pull", "-ref", "localhost/x:v1"}, "--wasm is required"},
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

func TestBundle_UsageShown(t *testing.T) {
	r := runChild(t, nil)
	assertContains(t, "usage", r.stderr, "Usage: warmor-policy-bundle", "-policy-version")
}

func TestBundle_PushFailures(t *testing.T) {
	dir := t.TempDir()
	wasm := writeFile(t, filepath.Join(dir, "p.wasm"), "\x00asm\x01\x00\x00\x00")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing wasm file", []string{"-push", "-ref", "127.0.0.1:1/x:v1", "-wasm", filepath.Join(dir, "nope.wasm")}, "error: push: read wasm"},
		{"malformed ref", []string{"-push", "-ref", "NOT A REF", "-wasm", wasm}, "error: push:"},
		{"unreachable registry", []string{"-push", "-ref", "127.0.0.1:1/x:v1", "-wasm", wasm, "-name", "n", "-description", "d"}, "error: push:"},
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

func TestBundle_PullFailures(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.wasm")
	for _, ref := range []string{"NOT A REF", "127.0.0.1:1/x:v1"} {
		r := runChild(t, nil, "-pull", "-ref", ref, "-wasm", out)
		if r.code != 1 {
			t.Errorf("%s: exit = %d, want 1", ref, r.code)
		}
		assertContains(t, "stderr", r.stderr, "error: pull:")
	}
}

func TestBundle_Version(t *testing.T) {
	r := runChild(t, nil, "-version")
	if r.code != 0 {
		t.Fatalf("exit = %d", r.code)
	}
	assertContains(t, "stdout", r.stdout, "warmor-policy-bundle dev")
}
