package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/enforcer"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/policyserver"
)

// loadVerifyKey loads the --verify-key public key (PKIX PEM, as written by
// warmor-policy-bundle --keygen). An empty path means no verification.
func loadVerifyKey(path string) (ed25519.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	pub, err := crypto.LoadPublicKey(path)
	if err != nil {
		return nil, fmt.Errorf("--verify-key: %w", err)
	}
	return pub, nil
}

// runValidatePolicy implements --validate-policy: it loads the policy in a
// throwaway WASM runtime (verifying its signature first when verifyKeyPath
// is set), reports the result and returns the process exit code. It needs
// neither root nor BPF, so it can run in an unprivileged init container.
func runValidatePolicy(path, verifyKeyPath string, stdout, stderr io.Writer) int {
	pub, err := loadVerifyKey(verifyKeyPath)
	if err != nil {
		fmt.Fprintf(stderr, "policy INVALID: %v\n", err)
		return 1
	}
	res, err := enforcer.ValidatePolicy(context.Background(), path, pub)
	if err != nil {
		fmt.Fprintf(stderr, "policy INVALID: %s: %v\n", path, err)
		return 1
	}
	detail := "loaded in WASM runtime"
	if !res.Loaded {
		detail = "YAML schema valid; not compiled (no precompiled .wasm next to it)"
	} else if res.WASMPath != path {
		detail = "YAML schema valid; " + res.WASMPath + " loaded in WASM runtime"
	}
	sig := "signature not checked (no --verify-key)"
	if res.SignatureVerified {
		sig = "signature verified"
	}
	fmt.Fprintf(stdout, "policy OK: %s (%s, %s, %s)\n", path, res.Kind, sig, detail)
	return 0
}

// verifyDownload returns the policy client's Verify hook: with a key, a
// downloaded policy is rejected unless the signature served with it
// verifies over the downloaded bytes. Verification happens in memory,
// before anything is written to disk.
func verifyDownload(pub ed25519.PublicKey) func(*policyserver.PolicyAssignment, []byte) error {
	if pub == nil {
		return nil
	}
	return func(a *policyserver.PolicyAssignment, data []byte) error {
		var err error
		if len(a.Signature) == 0 {
			err = crypto.ErrPolicyUnsigned
		} else {
			err = crypto.VerifyPolicySignature(pub, data, a.Signature)
		}
		if err != nil {
			metrics.RecordPolicySignatureFailure(metrics.PolicySourceServer)
			log.Printf("❌ Rejected policy %s v%d from server: %v; keeping the current policy", a.PolicyID, a.Version, err)
			return err
		}
		return nil
	}
}

// writeDownloadedPolicy stores a verified (or, without --verify-key,
// accepted) download at path, with its signature at path+".sig" so later
// reloads from disk can verify it again. The signature is written first:
// if the process stops in between, the old module fails verification
// against the new signature and is refused rather than a new module
// running unverified. Without a signature any stale .sig is removed.
func writeDownloadedPolicy(path string, a *policyserver.PolicyAssignment, data []byte) error {
	sigPath := crypto.PolicySignaturePath(path)
	if len(a.Signature) > 0 {
		if err := writePolicyFile(sigPath, crypto.EncodePolicySignature(a.Signature)); err != nil {
			return fmt.Errorf("write signature: %w", err)
		}
	} else if err := os.Remove(sigPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove stale signature: %w", err)
	}
	return writePolicyFile(path, data)
}

// policyUpdateHandler returns the policy client's OnUpdate callback: it
// stores the download (already vetted by verifyDownload) at policyPath and
// signals a reload. The reload reads the file back and, with --verify-key,
// verifies it again before loading.
func policyUpdateHandler(policyPath string, reloadCh chan<- struct{}) func(*policyserver.PolicyAssignment, []byte) {
	return func(a *policyserver.PolicyAssignment, data []byte) {
		if err := writeDownloadedPolicy(policyPath, a, data); err != nil {
			log.Printf("❌ Failed to write policy %s v%d: %v", a.PolicyID, a.Version, err)
			return
		}
		log.Printf("📥 Received policy %s v%d from server", a.PolicyID, a.Version)
		select {
		case reloadCh <- struct{}{}:
		default:
		}
	}
}
