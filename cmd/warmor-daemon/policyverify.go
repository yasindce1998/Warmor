package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log"

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
		fmt.Fprintf(stderr, "policy INVALID: %v\n", err)
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

// writeDownloadedPolicy publishes an immutable revision. Production activation
// uses policyUpdateHandler to prepare the runtime before publication.
func writeDownloadedPolicy(path string, a *policyserver.PolicyAssignment, data []byte) error {
	r, err := stagePolicyRevision(path, a, data)
	if err != nil {
		return err
	}
	defer r.discard()
	return r.commit()
}

// policyUpdateHandler waits for actual activation and durable publication.
func policyUpdateHandler(policyPath string, pub ed25519.PublicKey, activate func(string, func() error) error) func(*policyserver.PolicyAssignment, []byte) error {
	return (policyRevisionStager{verifyKey: pub}).updateHandler(policyPath, activate)
}

func (s policyRevisionStager) updateHandler(policyPath string, activate func(string, func() error) error) func(*policyserver.PolicyAssignment, []byte) error {
	// Keep an uncertain live commit's immutable pair and callback. Retrying a
	// fresh revision would lose the disk recovery owner after the kernel commit.
	var pending *stagedPolicyRevision
	var pendingID string
	return func(a *policyserver.PolicyAssignment, data []byte) error {
		id := fmt.Sprintf("%s/%d/%s", a.PolicyID, a.Version, a.WASMHash)
		if pending != nil && id != pendingID {
			return fmt.Errorf("%w: resolve previous revision before accepting a new assignment", enforcer.ErrActivationPending)
		}
		r := pending
		var err error
		if r == nil {
			r, err = s.stage(policyPath, a, data)
		}
		if err == nil {
			err = activate(r.modulePath, r.commit)
			if errors.Is(err, enforcer.ErrActivationPending) {
				pending, pendingID = r, id
			} else {
				pending = nil
				r.discard()
			}
		}
		if err != nil {
			log.Printf("❌ Failed to activate policy %s v%d: %v", a.PolicyID, a.Version, err)
			return err
		}
		log.Printf("✓ Activated policy %s v%d (%s)", a.PolicyID, a.Version, a.WASMHash)
		return nil
	}
}
