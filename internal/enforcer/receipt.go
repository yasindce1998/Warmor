package enforcer

import (
	"fmt"
	"time"

	"github.com/yasindce1998/warmor/internal/nodereceipt"
)

// captureActivation is called only after kernel preparation and evaluator
// commit, under activationMu (or before the new enforcer is published).
// A supervised backend has no parent pool; in that case the child's trusted
// metadata observations provide the committed identity.
func (e *Enforcer) captureActivation() nodereceipt.Activation {
	var digest, compiler, defaultAction string
	var abi uint32
	if e.pool != nil {
		id := e.pool.Identity()
		digest, abi, compiler, defaultAction = id.Digest, id.ABI, id.Compiler, id.DefaultAction
	} else if e.evaluator != nil {
		m := e.evaluator.Metadata()
		digest, abi = m.ModuleSHA256, m.ABIVersion
		if m.Build != nil {
			compiler, defaultAction = m.Build.Compiler, m.Build.DefaultAction
		}
	}
	return nodereceipt.Activation{
		Digest: digest, ABI: abi, ArtifactCompiler: compiler, DefaultAction: defaultAction, ActivatedAt: time.Now().UTC(),
		Posture: nodereceipt.Posture{Audit: e.auditMode, Learning: e.learningMode,
			LSMEnforcement:       e.lsmEnforce && e.platform.Capabilities().LSMEnforcement && !e.auditMode && !e.learningMode,
			DefaultDenyRequested: e.defaultDeny},
	}
}

// ActiveReceipt returns an identity of the actual active runtime, not current
// file contents. Preparation/download/failed commit never advances it.
func (e *Enforcer) ActiveReceipt() (nodereceipt.Activation, error) {
	e.activationMu.Lock()
	defer e.activationMu.Unlock()
	if e.signedAssignment {
		return nodereceipt.Activation{}, fmt.Errorf("controller receipts are unsupported in signed fleet assignment mode")
	}
	if e.closed || e.activation.Digest == "" {
		return nodereceipt.Activation{}, fmt.Errorf("no acknowledged activation")
	}
	if err := e.Ready(); err != nil {
		return nodereceipt.Activation{}, err
	}
	return e.activation, nil
}
