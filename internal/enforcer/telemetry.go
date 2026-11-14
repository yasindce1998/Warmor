package enforcer

import (
	"fmt"

	"github.com/yasindce1998/warmor/internal/telemetry"
	"github.com/yasindce1998/warmor/pkg/api"
)

// ActivatePolicyTelemetry preserves ActivatePolicy's durable commit semantics.
// All fallible telemetry preparation precedes the commit. Replacement happens
// while old events are drained and before new events can observe the evaluator.
// The caller passes the server-issued assignment and already verified artifact
// identity; this method does not relax artifact/signature verification.
func (e *Enforcer) ActivatePolicyTelemetry(path string, commit func() error, assignment telemetry.Assignment, revision telemetry.Revision) error {
	if e.signedAssignment {
		return fmt.Errorf("signed assignment mode refuses legacy telemetry activation")
	}
	if e.telemetry == nil {
		return fmt.Errorf("enforcer telemetry is not configured")
	}
	snapshot, err := e.telemetry.Prepare(assignment, revision)
	if err != nil {
		return err
	}
	return e.activatePolicy(path, nil, commit, &snapshot)
}

func (e *Enforcer) recordTelemetryDecision(result *api.ActionResult, evaluationError error) {
	if e.telemetry == nil || e.signedAssignment {
		return
	}
	excluded := result == nil || e.auditMode || e.learningMode
	denied := false
	if result != nil {
		excluded = excluded || result.Audit || (result.Action != api.ActionAllow && result.Action != api.ActionDeny)
		denied = result.Action == api.ActionDeny
	}
	e.telemetry.Record(denied, evaluationError != nil, excluded)
}
