package main

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/policyserver"
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

func serverSignatureFailures(t *testing.T) float64 {
	t.Helper()
	var m dto.Metric
	if err := metrics.PolicySignatureFailures.WithLabelValues(metrics.PolicySourceServer).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
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

// TestSignedPolicyDistributionEndToEnd runs a real policy server (httptest)
// and the daemon's policy client wired exactly as runDaemon wires it, with
// --verify-key semantics, and checks that only correctly signed policies
// reach disk and trigger a reload.
func TestSignedPolicyDistributionEndToEnd(t *testing.T) {
	dir := t.TempDir()
	sk, pubFile := writeKeyPair(t, dir)
	pub, err := loadVerifyKey(pubFile)
	if err != nil {
		t.Fatal(err)
	}
	good := readFixture(t)

	// Server side: the module is signed offline; the server only stores and
	// serves the signature (it has no private key).
	srv := policyserver.NewServer(policyserver.ServerConfig{Insecure: true})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	uploads := t.TempDir()
	upload := func(name string, data, sigFile []byte, create bool) {
		t.Helper()
		p := writeFile(t, filepath.Join(uploads, name), string(data))
		var err error
		if create {
			err = srv.Store().CreateSignedPolicy(&policyserver.Policy{ID: "p", Selector: map[string]string{"env": "prod"}}, p, sigFile)
		} else {
			err = srv.Store().AddVersion("p", p, sigFile, true)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	upload("v1.wasm", good, sk.SignPolicyFile(good), true)

	// Daemon side.
	policyPath := filepath.Join(dir, "policy.wasm")
	reloadCh := make(chan struct{}, 1)
	// Record which versions the daemon's hook rejected, and why.
	hook := verifyDownload(pub)
	var mu sync.Mutex
	rejected := map[int64]error{}
	c, err := newPolicyClient(policyClientConfig{
		ServerURL: ts.URL, AgentID: "node-1", Labels: map[string]string{"env": "prod"},
		Verify: func(a *policyserver.PolicyAssignment, data []byte) error {
			err := hook(a, data)
			if err != nil {
				mu.Lock()
				rejected[a.Version] = err
				mu.Unlock()
			}
			return err
		},
	}, policyUpdateHandler(policyPath, reloadCh))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runPolicyClient(ctx, c, 10*time.Millisecond)

	// 1. Valid signature: written to disk (with its .sig) and reload signalled.
	select {
	case <-reloadCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the signed policy to be applied")
	}
	onDisk, err := os.ReadFile(policyPath)
	if err != nil || !bytes.Equal(onDisk, good) {
		t.Fatalf("policy on disk = %d bytes (err %v), want the signed module", len(onDisk), err)
	}
	// The reload path (enforcer.ReadVerifiedPolicy) accepts what was written.
	if _, err := crypto.ReadVerifiedPolicy(pub, policyPath, 64<<20); err != nil {
		t.Fatalf("written policy does not verify from disk: %v", err)
	}
	sigOnDisk, _ := os.ReadFile(crypto.PolicySignaturePath(policyPath))

	expectRejected := func(what string, version int64, want error, before float64) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			mu.Lock()
			err := rejected[version]
			mu.Unlock()
			if err != nil {
				if !errors.Is(err, want) {
					t.Fatalf("%s: rejected with %v, want %v", what, err, want)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: v%d was not rejected", what, version)
			}
			time.Sleep(5 * time.Millisecond)
		}
		if serverSignatureFailures(t) <= before {
			t.Errorf("%s: warmor_policy_signature_failures_total{source=\"server\"} not incremented", what)
		}
		select {
		case <-reloadCh:
			t.Fatalf("%s: reload signalled for a rejected policy", what)
		default:
		}
		got, err := os.ReadFile(policyPath)
		if err != nil || !bytes.Equal(got, good) {
			t.Fatalf("%s: policy file changed (err %v)", what, err)
		}
		gotSig, _ := os.ReadFile(crypto.PolicySignaturePath(policyPath))
		if !bytes.Equal(gotSig, sigOnDisk) {
			t.Fatalf("%s: signature file changed", what)
		}
	}

	// 2. Tampered: the module served no longer matches its signature (the
	// signature is for the original bytes).
	tampered := append(append([]byte(nil), good...), 0)
	before := serverSignatureFailures(t)
	upload("v2.wasm", tampered, sk.SignPolicyFile(good), false)
	expectRejected("tampered module", 2, crypto.ErrPolicySignatureInvalid, before)

	// 3. Signed by a different key.
	other, _ := crypto.GenerateSigningKey()
	before = serverSignatureFailures(t)
	upload("v3.wasm", tampered, other.SignPolicyFile(tampered), false)
	expectRejected("wrong key", 3, crypto.ErrPolicySignatureInvalid, before)

	// 4. No signature at all.
	before = serverSignatureFailures(t)
	upload("v4.wasm", tampered, nil, false)
	expectRejected("unsigned module", 4, crypto.ErrPolicyUnsigned, before)

	// The client never adopted a rejected version.
	if a, _ := srv.Store().GetAgent("node-1"); a != nil && a.PolicyVersion > 1 {
		t.Errorf("agent reports version %d, want <= 1", a.PolicyVersion)
	}

	// 5. A correctly signed new version is applied again.
	upload("v5.wasm", tampered, sk.SignPolicyFile(tampered), false)
	select {
	case <-reloadCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the re-signed policy")
	}
	if got, _ := os.ReadFile(policyPath); !bytes.Equal(got, tampered) {
		t.Fatal("re-signed policy not written")
	}
}

func TestVerifyDownloadWithoutKey(t *testing.T) {
	if verifyDownload(nil) != nil {
		t.Fatal("no key must mean no verification hook")
	}
}

func TestWriteDownloadedPolicySignatureFile(t *testing.T) {
	sk, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.wasm")
	data := []byte("module")
	sig := sk.Sign(data)
	if err := writeDownloadedPolicy(path, &policyserver.PolicyAssignment{Signature: sig}, data); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.ReadVerifiedPolicy(sk.Public, path, 1<<20); err != nil {
		t.Fatalf("written policy does not verify: %v", err)
	}
	// An unsigned download (only possible without --verify-key) removes the
	// stale signature rather than leaving one that no longer matches.
	if err := writeDownloadedPolicy(path, &policyserver.PolicyAssignment{}, []byte("other")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(crypto.PolicySignaturePath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale signature kept: %v", err)
	}
}
