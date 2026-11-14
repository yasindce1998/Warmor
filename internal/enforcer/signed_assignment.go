package enforcer

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/yasindce1998/warmor/internal/crypto/assignment"
	"github.com/yasindce1998/warmor/internal/policymeta"
)

func (e *Enforcer) checkAssignment(src policymeta.Source, want assignment.Policy) error {
	// This is child-observed actual identity/ABI/build metadata in host mode.
	// Do not inspect custom sections or WASM imports in the parent.
	if err := src.Metadata().MatchArtifact(want.SHA256, want.ABI, want.Compiler, want.Posture.DefaultAction); err != nil {
		return fmt.Errorf("%w: actual artifact metadata differs", assignment.ErrCompatibility)
	}
	mode := "enforce"
	if e.auditMode || e.learningMode {
		mode = "audit"
	}
	if mode != want.Posture.Mode {
		return fmt.Errorf("%w: effective audit/enforce mode differs", assignment.ErrCompatibility)
	}
	if want.Posture.RequireDefaultDeny {
		if _, ok := e.policyMap.(defaultDenySyncer); !ok || !e.defaultDeny || !e.kernelEnforce || !e.requireLSM || e.auditMode || e.learningMode || !src.StaticRulesProcess().Eligible || !src.StaticRulesNetwork().Eligible {
			return fmt.Errorf("%w: required kernel default-deny unavailable/ineligible", assignment.ErrCompatibility)
		}
	}
	return nil
}

// ActivateAssignment requires a previously verified assignment and the sole
// durable store commit callback. It cannot share atomic-generation publication
// until that combined recovery model is tested. Generic reloads stay disabled
// when ExpectedAssignment was supplied at startup.
func (e *Enforcer) ActivateAssignment(path string, policy assignment.Policy, commit func() error) error {
	if len(e.verifyKey) != ed25519.PublicKeySize {
		return errors.New("signed assignment requires an artifact verification key")
	}
	if commit == nil {
		return errors.New("signed assignment requires durable commit")
	}
	return e.activatePolicy(path, &policy, commit, nil)
}
