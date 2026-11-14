package enforcer

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"

	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/pkg/api"
)

// ActionHandler handles policy decisions
type ActionHandler struct {
	allowed              uint64
	denied               uint64
	logged               uint64
	auditDenied          uint64
	enforcementAttempted uint64
	enforcementSucceeded uint64
	enforcementFailed    uint64
	enforcementRefused   uint64
	auditMode            bool
	terminate            func(*api.Event) (bool, error)
}

// NewActionHandler creates a new action handler
func NewActionHandler(auditMode bool) *ActionHandler {
	return &ActionHandler{auditMode: auditMode, terminate: terminateEventProcess}
}

// Enforce executes the policy decision
func (h *ActionHandler) Enforce(ctx context.Context, event *api.Event, result *api.ActionResult) error {
	// Cache hits/caller reuse must never reuse a different event's outcome.
	result.EnforcementAttempted, result.Enforced, result.EnforcementError = false, false, ""
	switch result.Action {
	case api.ActionAllow:
		atomic.AddUint64(&h.allowed, 1)
		return h.handleAllow(event, result)

	case api.ActionDeny:
		if h.auditMode || result.Audit {
			result.Audit = true
			atomic.AddUint64(&h.auditDenied, 1)
			atomic.AddUint64(&h.logged, 1)
			return h.handleLog(event, result)
		}
		atomic.AddUint64(&h.denied, 1)
		return h.handleDeny(ctx, event, result)

	case api.ActionLog:
		atomic.AddUint64(&h.logged, 1)
		return h.handleLog(event, result)

	default:
		return fmt.Errorf("unknown action: %v", result.Action)
	}
}

func (h *ActionHandler) handleAllow(_ *api.Event, _ *api.ActionResult) error {
	return nil
}

func (h *ActionHandler) handleDeny(ctx context.Context, event *api.Event, result *api.ActionResult) error {
	log.Printf("DENY pid=%d type=%s reason=%q", event.PID, event.Type, result.Reason)
	var attempted bool
	err := ctx.Err()
	if err == nil {
		if event.PID == 0 {
			err = fmt.Errorf("termination refused: PID is unknown/zero")
		} else {
			attempted, err = h.terminate(event)
		}
	}
	result.EnforcementAttempted = attempted
	if attempted {
		atomic.AddUint64(&h.enforcementAttempted, 1)
		metrics.TerminationsTotal.WithLabelValues("attempted").Inc()
	}
	if err != nil {
		result.EnforcementError = err.Error()
		if attempted {
			atomic.AddUint64(&h.enforcementFailed, 1)
			metrics.TerminationsTotal.WithLabelValues("failed").Inc()
		} else {
			atomic.AddUint64(&h.enforcementRefused, 1)
			metrics.TerminationsTotal.WithLabelValues("refused").Inc()
		}
		log.Printf("DENY pid=%d: termination unsuccessful attempted=%v: %v", event.PID, attempted, err)
		return err
	}
	result.Enforced = true
	atomic.AddUint64(&h.enforcementSucceeded, 1)
	metrics.TerminationsTotal.WithLabelValues("succeeded").Inc()
	return nil
}

func (h *ActionHandler) handleLog(event *api.Event, result *api.ActionResult) error {
	level := "INFO"
	if result.Action == api.ActionDeny {
		level = "WARN"
	}

	log.Printf("[%s] audit pid=%d type=%s action=%s reason=%q audit=%v",
		level, event.PID, event.Type, result.Action, result.Reason, result.Audit)

	return nil
}

// GetStats returns current enforcement statistics
func (h *ActionHandler) GetStats() api.EnforcementStats {
	return api.EnforcementStats{
		Allowed:              atomic.LoadUint64(&h.allowed),
		Denied:               atomic.LoadUint64(&h.denied),
		Logged:               atomic.LoadUint64(&h.logged),
		AuditDenied:          atomic.LoadUint64(&h.auditDenied),
		EnforcementAttempted: atomic.LoadUint64(&h.enforcementAttempted),
		EnforcementSucceeded: atomic.LoadUint64(&h.enforcementSucceeded),
		EnforcementFailed:    atomic.LoadUint64(&h.enforcementFailed),
		EnforcementRefused:   atomic.LoadUint64(&h.enforcementRefused),
	}
}
