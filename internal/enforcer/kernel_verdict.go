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

// handleKernelVerdict handles events the kernel already refused (a policy
// map deny). They are recorded and streamed but never re-evaluated by the
// WASM policy: its decision could not change what the kernel did, and a
// re-evaluated allow would otherwise be cached and synced over the kernel's
// deny. It reports whether the event was consumed.
func (e *Enforcer) handleKernelVerdict(event *api.Event) bool {
	if !event.KernelDenied {
		return false
	}

	result := &api.ActionResult{
		Action:    api.ActionDeny,
		Reason:    "kernel policy map deny",
		Timestamp: time.Now(),
	}
	e.actionHandler.RecordKernelDenied(event, result)

	e.logger.LogEvent(event, result)
	metrics.RecordEvent(result.Action.String())
	if e.pipeline != nil {
		e.pipeline.Emit(event, result)
	}
	return true
}
