package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/crypto"
)

// wasmFixture is a real policy module shared with internal/wasm.
var wasmFixture = filepath.Join("..", "..", "internal", "wasm", "testdata", "allow_policy.wasm")

func readFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(wasmFixture)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// writeKeyPair generates an ed25519 key pair and writes the PEM files the
// same way warmor-policy-bundle --keygen does.
func writeKeyPair(t *testing.T, dir string) (*crypto.SigningKey, string) {
	t.Helper()
	sk, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := sk.MarshalPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pubFile := filepath.Join(dir, "signing.pub")
	writeFile(t, pubFile, string(pubPEM))
	return sk, pubFile
}

func TestMain_ValidatePolicy(t *testing.T) {
	dir := t.TempDir()
	sk, pubFile := writeKeyPair(t, dir)
	wasmData := readFixture(t)

	signed := filepath.Join(dir, "signed.wasm")
	writeFile(t, signed, string(wasmData))
	writeFile(t, crypto.PolicySignaturePath(signed), string(sk.SignPolicyFile(wasmData)))
	unsigned := filepath.Join(dir, "unsigned.wasm")
	writeFile(t, unsigned, string(wasmData))
	tampered := filepath.Join(dir, "tampered.wasm")
	writeFile(t, tampered, string(append(append([]byte(nil), wasmData...), 0)))
	writeFile(t, crypto.PolicySignaturePath(tampered), string(sk.SignPolicyFile(wasmData)))
	garbage := writeFile(t, filepath.Join(dir, "garbage.wasm"), "not wasm")
	yamlPolicy := filepath.Join("..", "..", "policies", "yaml-example", "policy.yaml")
	badYAML := writeFile(t, filepath.Join(dir, "bad.yaml"), "name: x\nrules:\n  - event: bogus\n")

	tests := []struct {
		name     string
		args     []string
		code     int
		inStdout string
		inStderr string
	}{
		// Exactly the Helm chart's initContainer invocation shape.
		{"chart yaml", []string{"--validate-policy", yamlPolicy}, 0, "policy OK: " + yamlPolicy + " (yaml", ""},
		{"wasm", []string{"--validate-policy", unsigned}, 0, "loaded in WASM runtime", ""},
		{"equals form", []string{"--validate-policy=" + unsigned}, 0, "policy OK", ""},
		{"signed", []string{"--verify-key", pubFile, "--validate-policy", signed}, 0, "signature verified", ""},
		{"unsigned with key", []string{"--verify-key", pubFile, "--validate-policy", unsigned}, 1, "", "policy is not signed"},
		{"tampered with key", []string{"--verify-key", pubFile, "--validate-policy", tampered}, 1, "", "signature verification failed"},
		{"yaml with key", []string{"--verify-key", pubFile, "--validate-policy", yamlPolicy}, 1, "", "requires a compiled .wasm"},
		{"garbage", []string{"--validate-policy", garbage}, 1, "", "policy INVALID"},
		{"bad yaml", []string{"--validate-policy", badYAML}, 1, "", "policy INVALID"},
		{"missing", []string{"--validate-policy", filepath.Join(dir, "nope.wasm")}, 1, "", "policy INVALID"},
		{"bad key", []string{"--verify-key", garbage, "--validate-policy", signed}, 1, "", "--verify-key"},
		{"host validator forbidden", []string{"--experimental-supervised-policy-host", "--validate-policy", unsigned}, 1, "", "do not combine with supervised backend flags"},
		{"host path validator forbidden", []string{"--policy-host", "/not-executed", "--validate-policy", unsigned}, 1, "", "do not combine with supervised backend flags"},
		{"host pin validator forbidden", []string{"--policy-host-sha256", strings.Repeat("a", 64), "--validate-policy", unsigned}, 1, "", "do not combine with supervised backend flags"},
		{"host declaration validator forbidden", []string{"--policy-declaration-digests", strings.Repeat("b", 64), "--validate-policy", unsigned}, 1, "", "do not combine with supervised backend flags"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := runChild(t, nil, tc.args...)
			if r.code != tc.code {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", r.code, tc.code, r.stdout, r.stderr)
			}
			if tc.inStdout != "" {
				assertContains(t, "stdout", r.stdout, tc.inStdout)
			}
			if tc.inStderr != "" {
				assertContains(t, "stderr", r.stderr, tc.inStderr)
			}
			// Validation must not reach the banner, the privilege check or
			// the enforcer (which would need root and BPF).
			if strings.Contains(r.stderr, "elevated") || strings.Contains(r.stderr, "WASM-Powered") {
				t.Errorf("--validate-policy ran the daemon:\n%s", r.stderr)
			}
		})
	}
}

func TestMain_VerifyKeyUnreadable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("daemon start-up past the privilege check needs root")
	}
	r := runChild(t, nil, "--verify-key", filepath.Join(t.TempDir(), "missing.pub"))
	if r.code != 1 {
		t.Fatalf("exit = %d, want 1", r.code)
	}
	assertContains(t, "stderr", r.stderr, "--verify-key")
}

func TestVerifyDownloadWithoutKey(t *testing.T) {
	if verifyDownload(nil) != nil {
		t.Fatal("no key must mean no verification hook")
	}
}
