//go:build !windows

package main

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/enforcer"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/policyserver"
)

func serverSignatureFailures(t *testing.T) float64 {
	t.Helper()
	var m dto.Metric
	if err := metrics.PolicySignatureFailures.WithLabelValues(metrics.PolicySourceServer).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// Successful durable publication requires the POSIX link/directory-sync backend.
// Windows runs explicit failure/no-ack tests instead; portable signature and
// client/heartbeat tests continue to run on both platforms.
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
	}, policyUpdateHandler(policyPath, sk.Public, func(path string, commit func() error) error {
		if _, err := enforcer.ValidatePolicy(context.Background(), path, pub); err != nil {
			return err
		}
		if err := commit(); err != nil {
			return err
		}
		reloadCh <- struct{}{}
		return nil
	}))
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
	upload("v5.wasm", good, sk.SignPolicyFile(good), false)
	select {
	case <-reloadCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the re-signed policy")
	}
	if got, _ := os.ReadFile(policyPath); !bytes.Equal(got, good) {
		t.Fatal("re-signed policy not written")
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
