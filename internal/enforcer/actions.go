package enforcer

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"

	"github.com/yasindce1998/warmor/pkg/api"
)

// ActionHandler handles policy decisions
type ActionHandler struct {
	allowed     uint64
	denied      uint64
	logged      uint64
	auditDenied uint64
	auditMode   bool
}

// NewActionHandler creates a new action handler
func NewActionHandler(auditMode bool) *ActionHandler {
	return &ActionHandler{auditMode: auditMode}
}

// Enforce executes the policy decision
func (h *ActionHandler) Enforce(ctx context.Context, event *api.Event, result *api.ActionResult) error {
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
		return h.handleDeny(event, result)

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

func (h *ActionHandler) handleDeny(event *api.Event, result *api.ActionResult) error {
	if event.PID == 0 {
		return nil
	}

	log.Printf("DENY pid=%d type=%s reason=%q", event.PID, event.Type, result.Reason)

	if err := terminateEventProcess(event.PID, event.Timestamp); err != nil {
		log.Printf("DENY pid=%d: terminate failed (process may have exited): %v", event.PID, err)
	}

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
		Allowed:     atomic.LoadUint64(&h.allowed),
		Denied:      atomic.LoadUint64(&h.denied),
		Logged:      atomic.LoadUint64(&h.logged),
		AuditDenied: atomic.LoadUint64(&h.auditDenied),
	}
}
