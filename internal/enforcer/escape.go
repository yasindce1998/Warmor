package enforcer

import (
	"fmt"
	"log"
	"time"

	"github.com/yasindce1998/warmor/internal/escape"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Escape detection modes (--escape-detect).
const (
	EscapeOff   = "off"
	EscapeAlert = "alert"
	EscapeDeny  = "deny"
)

// ValidateEscapeMode checks an --escape-detect value.
func ValidateEscapeMode(mode string) error {
	switch mode {
	case "", EscapeOff, EscapeAlert, EscapeDeny:
		return nil
	}
	return fmt.Errorf("invalid escape detection mode %q (valid: off, alert, deny)", mode)
}

// newEscapeDetector builds the detector for mode, or nil when off.
// isContainer scopes detection to container cgroups.
func newEscapeDetector(mode string, isContainer func(uint64) bool) (*escape.Detector, error) {
	if err := ValidateEscapeMode(mode); err != nil {
		return nil, err
	}
	if mode == "" || mode == EscapeOff {
		return nil, nil
	}
	return escape.NewDetector(escape.DetectorConfig{
		DenyOnDetect: mode == EscapeDeny,
		IsContainer:  isContainer,
		AlertCallback: func(a *escape.Alert) {
			metrics.RecordEscapeAlert(string(a.TechniqueID))
			log.Printf("[WARN] escape attempt: %s (%s) pid=%d comm=%s cgroup=%d: %s",
				a.Name, a.TechniqueID, a.PID, a.Comm, a.CgroupID, a.Details)
		},
	}), nil
}

// checkEscape runs escape detection on an event. Matches are alerted by the
// detector itself. In deny mode a match is enforced like any other deny
// (the process is terminated, since the operation already went through the
// kernel), and the event is consumed. Events the kernel already refused are
// alerted but left to the kernel-verdict path. It reports whether the event
// was consumed.
func (e *Enforcer) checkEscape(event *api.Event) bool {
	if e.escape == nil {
		return false
	}
	deny := e.escape.CheckEvent(e.ctx, streaming.FromAPIEvent(event, nil))
	if deny == nil || event.KernelDenied {
		return false
	}
	if deny.Timestamp.IsZero() {
		deny.Timestamp = time.Now()
	}
	// Learning mode records a would-deny but never kills.
	deny.Audit = e.learningMode
	_ = e.actionHandler.Enforce(e.ctx, event, deny)
	e.logger.LogEvent(event, deny)
	metrics.RecordEvent(deny.Action.String())
	if e.pipeline != nil {
		e.pipeline.Emit(event, deny)
	}
	return true
}
