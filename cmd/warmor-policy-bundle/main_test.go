package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/yasindce1998/warmor/internal/crypto"
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

// genKeys runs --keygen in-process and returns the key paths.
func genKeys(t *testing.T) (priv, pub string) {
	t.Helper()
	dir := t.TempDir()
	priv, pub = filepath.Join(dir, "signing.key"), filepath.Join(dir, "signing.pub")
	_, stderr := runMain(t, "", "-keygen", "-sign-key", priv, "-verify-key", pub)
	assertContains(t, "stderr", stderr, "Wrote private key")
	return priv, pub
}

func TestBundle_Keygen(t *testing.T) {
	priv, pub := genKeys(t)
	sk, err := crypto.LoadSigningKey(priv)
	if err != nil {
		t.Fatalf("load generated private key: %v", err)
	}
	pk, err := crypto.LoadPublicKey(pub)
	if err != nil {
		t.Fatalf("load generated public key: %v", err)
	}
	if !sk.Public.Equal(pk) {
		t.Error("generated public key does not match private key")
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(priv); fi.Mode().Perm() != 0o600 {
			t.Errorf("private key mode = %v, want 0600", fi.Mode().Perm())
		}
	}

	// Refuses to overwrite existing keys or run without output paths.
	for _, args := range [][]string{
		{"-keygen", "-sign-key", priv, "-verify-key", pub + ".new"},
		{"-keygen", "-sign-key", priv + ".new"},
		{"-keygen", "-push", "-sign-key", priv + ".x", "-verify-key", pub + ".x"},
	} {
		r := runChild(t, nil, args...)
		if r.code != 1 {
			t.Errorf("%v: exit = %d, want 1 (stderr: %s)", args, r.code, r.stderr)
		}
	}
	if _, err := os.Stat(pub + ".new"); !os.IsNotExist(err) {
		t.Error("public key written although private key already existed")
	}
}

func TestBundle_KeyFlagsRequired(t *testing.T) {
	wasm := writeFile(t, filepath.Join(t.TempDir(), "p.wasm"), "\x00asm")
	bad := writeFile(t, filepath.Join(t.TempDir(), "bad.pem"), "not a pem")
	out := filepath.Join(t.TempDir(), "out.wasm")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"push without key", []string{"-push", "-ref", "127.0.0.1:1/x:v1", "-wasm", wasm}, "--sign-key is required"},
		{"pull without key", []string{"-pull", "-ref", "127.0.0.1:1/x:v1", "-wasm", out}, "--verify-key is required"},
		{"bad sign key", []string{"-push", "-ref", "127.0.0.1:1/x:v1", "-wasm", wasm, "-sign-key", bad}, "error: load signing key"},
		{"bad verify key", []string{"-pull", "-ref", "127.0.0.1:1/x:v1", "-wasm", out, "-verify-key", bad}, "error: load verify key"},
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
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("output written on failed pull")
	}
}

func TestBundle_PushFailures(t *testing.T) {
	dir := t.TempDir()
	wasm := writeFile(t, filepath.Join(dir, "p.wasm"), "\x00asm\x01\x00\x00\x00")
	priv, _ := genKeys(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing wasm file", []string{"-push", "-ref", "127.0.0.1:1/x:v1", "-wasm", filepath.Join(dir, "nope.wasm"), "-sign-key", priv}, "error: push: read wasm"},
		{"malformed ref", []string{"-push", "-ref", "NOT A REF", "-wasm", wasm, "-sign-key", priv}, "error: push:"},
		{"unreachable registry", []string{"-push", "-ref", "127.0.0.1:1/x:v1", "-wasm", wasm, "-name", "n", "-description", "d", "-sign-key", priv}, "error: push:"},
		{"unreachable registry unsigned", []string{"-push", "-ref", "127.0.0.1:1/x:v1", "-wasm", wasm, "-allow-unsigned"}, "error: push:"},
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
	_, pub := genKeys(t)
	for _, ref := range []string{"NOT A REF", "127.0.0.1:1/x:v1"} {
		for _, keyArgs := range [][]string{{"-verify-key", pub}, {"-insecure-skip-verify"}} {
			r := runChild(t, nil, append([]string{"-pull", "-ref", ref, "-wasm", out}, keyArgs...)...)
			if r.code != 1 {
				t.Errorf("%s %v: exit = %d, want 1", ref, keyArgs, r.code)
			}
			assertContains(t, "stderr", r.stderr, "error: pull:")
		}
	}
}

func TestBundle_Version(t *testing.T) {
	r := runChild(t, nil, "-version")
	if r.code != 0 {
		t.Fatalf("exit = %d", r.code)
	}
	assertContains(t, "stdout", r.stdout, "warmor-policy-bundle dev")
}
