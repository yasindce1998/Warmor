package enforcer

import (
	"log"
	"sync/atomic"
	"time"

	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/pkg/api"
)

// RecordKernelDenied counts an operation the kernel already refused. Nothing
// is terminated: the syscall failed with EPERM, so the process never ran the
// denied operation and killing it would turn a refused exec into a crash.
func (h *ActionHandler) RecordKernelDenied(event *api.Event, result *api.ActionResult) {
	atomic.AddUint64(&h.denied, 1)
	log.Printf("DENY (kernel) pid=%d type=%s reason=%q", event.PID, event.Type, result.Reason)
}

// handleKernelVerdict handles events that carry a verdict the kernel already
// reached: an integrity violation (enforce or audit) or a policy-map deny.
// They are recorded and streamed but never re-evaluated by the WASM policy,
// whose decision could not change what the kernel did. It reports whether
// the event was consumed.
func (e *Enforcer) handleKernelVerdict(event *api.Event) bool {
	if !event.KernelDenied && !event.IntegrityViolation {
		return false
	}

	result := &api.ActionResult{
		Action:    api.ActionDeny,
		Timestamp: time.Now(),
	}
	switch {
	case event.IntegrityViolation:
		result.Reason = "exec integrity: SHA-256 not in allowlist"
	default:
		result.Reason = "kernel policy map deny"
	}

	if event.IntegrityViolation {
		metrics.RecordIntegrityViolation(event.KernelDenied)
	}
	if event.KernelDenied {
		e.actionHandler.RecordKernelDenied(event, result)
	} else {
		// Integrity in audit mode: the exec went ahead; report a would-deny.
		result.Audit = true
		_ = e.actionHandler.Enforce(e.ctx, event, result)
		metrics.RecordAuditDenied()
	}

	e.logger.LogEvent(event, result)
	metrics.RecordEvent(result.Action.String())
	if e.pipeline != nil {
		e.pipeline.Emit(event, result)
	}
	return true
}
