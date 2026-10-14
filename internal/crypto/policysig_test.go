package crypto

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicySignatureRoundTrip(t *testing.T) {
	sk, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	wasm := []byte("\x00asm policy bytes")
	sigFile := sk.SignPolicyFile(wasm)

	if !strings.HasSuffix(string(sigFile), "\n") || len(strings.TrimSpace(string(sigFile))) != 88 {
		t.Fatalf("unexpected signature file encoding %q", sigFile)
	}
	if err := VerifyPolicySignature(sk.Public, wasm, sigFile); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// Raw 64-byte binary signatures are accepted too.
	if err := VerifyPolicySignature(sk.Public, wasm, sk.Sign(wasm)); err != nil {
		t.Fatalf("raw signature rejected: %v", err)
	}
	if err := VerifyPolicySignature(other.Public, wasm, sigFile); !errors.Is(err, ErrPolicySignatureInvalid) {
		t.Errorf("wrong key: got %v", err)
	}
	if err := VerifyPolicySignature(sk.Public, append(wasm, 'x'), sigFile); !errors.Is(err, ErrPolicySignatureInvalid) {
		t.Errorf("tampered data: got %v", err)
	}
	if err := VerifyPolicySignature(sk.Public, wasm, nil); !errors.Is(err, ErrPolicyUnsigned) {
		t.Errorf("empty signature: got %v", err)
	}
	if err := VerifyPolicySignature(sk.Public, wasm, []byte("not base64!")); !errors.Is(err, ErrPolicySignatureInvalid) {
		t.Errorf("malformed signature: got %v", err)
	}
	if err := VerifyPolicySignature(sk.Public, wasm, []byte("c2hvcnQ=")); !errors.Is(err, ErrPolicySignatureInvalid) {
		t.Errorf("short signature: got %v", err)
	}
	if err := VerifyPolicySignature(nil, wasm, sigFile); err == nil {
		t.Error("nil public key accepted")
	}
}

func TestReadVerifiedPolicy(t *testing.T) {
	sk, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.wasm")
	wasm := []byte("\x00asm module")
	write := func(p string, data []byte) {
		t.Helper()
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(path, wasm)

	if _, err := ReadVerifiedPolicy(sk.Public, path, 1<<20); !errors.Is(err, ErrPolicyUnsigned) {
		t.Fatalf("missing .sig: got %v", err)
	}

	write(PolicySignaturePath(path), sk.SignPolicyFile(wasm))
	got, err := ReadVerifiedPolicy(sk.Public, path, 1<<20)
	if err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	if string(got) != string(wasm) {
		t.Errorf("returned %q, want %q", got, wasm)
	}

	if _, err := ReadVerifiedPolicy(sk.Public, path, 4); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("size limit not enforced: %v", err)
	}

	write(path, []byte("\x00asm tampered"))
	if _, err := ReadVerifiedPolicy(sk.Public, path, 1<<20); !errors.Is(err, ErrPolicySignatureInvalid) {
		t.Errorf("tampered policy: got %v", err)
	}

	if _, err := ReadVerifiedPolicy(sk.Public, filepath.Join(dir, "missing.wasm"), 1<<20); err == nil {
		t.Error("missing policy accepted")
	}
	if _, err := ReadVerifiedPolicy(sk.Public, dir, 1<<20); err == nil {
		t.Error("directory accepted as policy")
	}
}
