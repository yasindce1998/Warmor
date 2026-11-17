package enforcer

import (
	"errors"
	"fmt"

	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/telemetry"
	"github.com/yasindce1998/warmor/pkg/api"
)

var errGenerationTelemetryUnsupported = errors.New("atomic generations with legacy telemetry require separately reviewed per-generation attribution")

// ActivatePolicyTelemetry preserves ActivatePolicy's durable commit semantics.
// All fallible telemetry preparation precedes the commit. Replacement happens
// while old events are drained and before new events can observe the evaluator.
// The caller passes the server-issued assignment and already verified artifact
// identity; this method does not relax artifact/signature verification.
func (e *Enforcer) ActivatePolicyTelemetry(path string, commit func() error, assignment telemetry.Assignment, revision telemetry.Revision) error {
	if e.generations != nil {
		if e.telemetry != nil {
			e.telemetry.Seal()
		}
		return errGenerationTelemetryUnsupported
	}
	if e.signedAssignment {
		return fmt.Errorf("signed assignment mode refuses legacy telemetry activation")
	}
	if e.generations != nil {
		return fmt.Errorf("legacy telemetry attribution with atomic generations is unsupported")
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

// reportOutcome performs the same denial log, audit metric and telemetry
// reporting as the main WASM evaluation path for decisions made by a cache hit
// or an early deny (netfilter, sandbox, escape). It must be called after
// ActionHandler.Enforce, which may set result.Audit in global audit mode.
func (e *Enforcer) reportOutcome(event *api.Event, result *api.ActionResult, evaluationError error) {
	if result != nil {
		if result.Action == api.ActionDeny && !result.Audit && e.logger != nil {
			e.logger.LogDenial(event, result)
		}
		if result.Audit {
			metrics.RecordAuditDenied()
		}
	}
	e.recordTelemetryDecision(result, evaluationError)
}

func (e *Enforcer) recordTelemetryDecision(result *api.ActionResult, evaluationError error) {
	if e.telemetry == nil || e.signedAssignment || e.generations != nil {
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
