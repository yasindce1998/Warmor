package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/crypto/assignment"
	"github.com/yasindce1998/warmor/internal/policybuild"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
)

func TestOfflineAssignmentSignerDistinctKeysActualMetadataAndNoOverwrite(t *testing.T) {
	artifact, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	modulePath := filepath.Join(root, "policy.wasm")
	intentPath := filepath.Join(root, "intent.json")
	artifactPath := filepath.Join(root, "artifact.pub")
	signerPath := filepath.Join(root, "deployment.pk8")
	outputPath := filepath.Join(root, "bundle.json")
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	module, err := policybuild.Append(wasmtest.VersionedConstPolicy(1, 1), policybuild.Metadata{Compiler: "test-build", DefaultAction: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	write(modulePath, module)
	write(modulePath+".sig", artifact.SignPolicyFile(module))
	pub, err := artifact.MarshalPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	write(artifactPath, pub)
	priv, err := signer.MarshalPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	write(signerPath, priv)
	now := time.Now().Unix()
	d := assignment.Deployment{Format: 1, KeyID: "deployment", Target: assignment.Target{Scope: "scope", Audience: "node"}, Policy: assignment.Policy{ID: "policy", Version: 1, SHA256: assignment.Digest(module), ABI: 1, Compiler: "test-build", Posture: assignment.Posture{Mode: "enforce", DefaultAction: "deny"}}, Sequence: 1, IssuedAt: now, ExpiresAt: now + 60}
	intent, _ := json.Marshal(d)
	write(intentPath, intent)
	args := []string{"--intent", intentPath, "--wasm", modulePath, "--artifact-public-key", artifactPath, "--assignment-private-key", signerPath, "--out", outputPath}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := assignment.DecodeBundle(wire)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := assignment.Decode(bundle.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assignment.Verify(envelope, module, assignment.Trust{"deployment": assignment.Key{Public: signer.Public, Target: d.Target}}, assignment.VerifyOptions{Target: d.Target, Clock: assignment.Clock{Now: time.Unix(now, 0), Trusted: true}, SupportedABIs: []uint32{1}, AllowedCompilers: []string{"test-build"}, MaxLifetime: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if err := run(args); err == nil {
		t.Fatal("signed output overwritten")
	}
	if err := os.Remove(outputPath); err != nil {
		t.Fatal(err)
	}
	d.Policy.ABI = 2
	intent, _ = json.Marshal(d)
	write(intentPath, intent)
	if err := run(args); err == nil {
		t.Fatal("wrong declared ABI signed")
	}
	d.Policy.ABI = 1
	intent, _ = json.Marshal(d)
	write(intentPath, intent)
	priv, err = artifact.MarshalPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	write(signerPath, priv)
	if err := run(args); err == nil {
		t.Fatal("artifact key reused as deployment signer")
	}
}
