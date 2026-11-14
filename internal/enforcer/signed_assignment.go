package enforcer

import (
	"errors"
	"fmt"

	"github.com/yasindce1998/warmor/internal/crypto/assignment"
	"github.com/yasindce1998/warmor/internal/wasm"
)

func checkAssignment(pool *wasm.Pool, want assignment.Policy, audit, learning, defaultDeny, kernelEnforce bool, pm PolicyMapSyncer) error {
	if err := pool.CheckAssignment(want); err != nil {
		return err
	}
	mode := "enforce"
	if audit || learning {
		mode = "audit"
	}
	if mode != want.Posture.Mode {
		return fmt.Errorf("%w: effective audit/enforce mode differs", assignment.ErrCompatibility)
	}
	if want.Posture.RequireDefaultDeny {
		if _, ok := pm.(defaultDenySyncer); !ok || !defaultDeny || !kernelEnforce || audit || learning || !pool.StaticRulesProcess().Eligible || !pool.StaticRulesNetwork().Eligible {
			return fmt.Errorf("%w: required kernel default-deny unavailable/ineligible", assignment.ErrCompatibility)
		}
	}
	return nil
}

// ActivateAssignment uses the same real drain/kernel prepare/durable commit/
// swap boundary as legacy activation, with strict actual artifact checks.
func (e *Enforcer) ActivateAssignment(path string, policy assignment.Policy, commit func() error) error {
	if commit == nil {
		return errors.New("signed assignment requires durable commit")
	}
	return e.activatePolicy(path, &policy, commit, nil)
}
