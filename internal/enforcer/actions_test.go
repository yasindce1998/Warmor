package enforcer

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestActionHandler_AuditMode_DowngradesDeny(t *testing.T) {
	handler := NewActionHandler(true)

	event := &api.Event{
		PID:       1234,
		UID:       1000,
		GID:       1000,
		Comm:      "test",
		Filename:  "/tmp/malicious",
		Timestamp: time.Now(),
	}

	result := &api.ActionResult{
		Action:    api.ActionDeny,
		Reason:    "execution from temp dir",
		Timestamp: time.Now(),
	}

	err := handler.Enforce(context.Background(), event, result)
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}

	if !result.Audit {
		t.Error("expected result.Audit to be true in audit mode")
	}

	stats := handler.GetStats()
	if stats.AuditDenied != 1 {
		t.Errorf("expected AuditDenied=1, got %d", stats.AuditDenied)
	}
	if stats.Denied != 0 {
		t.Errorf("expected Denied=0 in audit mode, got %d", stats.Denied)
	}
}

func TestActionHandler_AuditMode_AllowPassesThrough(t *testing.T) {
	handler := NewActionHandler(true)

	event := &api.Event{
		PID:  1234,
		UID:  0,
		Comm: "systemd",
	}

	result := &api.ActionResult{
		Action:    api.ActionAllow,
		Reason:    "allowed",
		Timestamp: time.Now(),
	}

	err := handler.Enforce(context.Background(), event, result)
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}

	if result.Audit {
		t.Error("expected result.Audit to be false for allow actions")
	}

	stats := handler.GetStats()
	if stats.Allowed != 1 {
		t.Errorf("expected Allowed=1, got %d", stats.Allowed)
	}
}

func TestActionHandler_NoAudit_DenyNotDowngraded(t *testing.T) {
	handler := NewActionHandler(false)

	// Actual termination is tested only with dedicated isolated child processes.
	event := &api.Event{
		PID:      0,
		UID:      1000,
		Comm:     "nc",
		Filename: "/usr/bin/nc",
	}

	result := &api.ActionResult{
		Action:    api.ActionDeny,
		Reason:    "blocked network tool",
		Timestamp: time.Now(),
	}

	err := handler.Enforce(context.Background(), event, result)
	if err == nil || result.EnforcementError == "" || result.Enforced || result.EnforcementAttempted {
		t.Fatalf("PID zero must report refused enforcement: result=%+v err=%v", result, err)
	}

	if result.Audit {
		t.Error("expected result.Audit to be false when audit mode is off")
	}

	stats := handler.GetStats()
	if stats.Denied != 1 {
		t.Errorf("expected Denied=1, got %d", stats.Denied)
	}
	if stats.AuditDenied != 0 {
		t.Errorf("expected AuditDenied=0, got %d", stats.AuditDenied)
	}
}

func TestActionHandler_PerRuleAudit(t *testing.T) {
	handler := NewActionHandler(false)

	event := &api.Event{
		PID:      1234,
		UID:      1000,
		Comm:     "test",
		Filename: "/tmp/script.sh",
	}

	result := &api.ActionResult{
		Action:    api.ActionDeny,
		Reason:    "temp dir execution",
		Timestamp: time.Now(),
		Audit:     true, // per-rule audit set by WASM evaluator
	}

	err := handler.Enforce(context.Background(), event, result)
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}

	if !result.Audit {
		t.Error("expected result.Audit to remain true for per-rule audit")
	}

	stats := handler.GetStats()
	if stats.AuditDenied != 1 {
		t.Errorf("expected AuditDenied=1, got %d", stats.AuditDenied)
	}
	if stats.Denied != 0 {
		t.Errorf("expected Denied=0 for audit deny, got %d", stats.Denied)
	}
}

func TestActionHandler_LogAction(t *testing.T) {
	handler := NewActionHandler(false)

	result := &api.ActionResult{Action: api.ActionLog, Reason: "log it"}
	if err := handler.Enforce(context.Background(), &api.Event{PID: 0, Comm: "python"}, result); err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}

	stats := handler.GetStats()
	if stats.Logged != 1 || stats.Allowed != 0 || stats.Denied != 0 || stats.AuditDenied != 0 {
		t.Errorf("unexpected stats for log action: %+v", stats)
	}
	if result.Audit {
		t.Error("log action must not set Audit")
	}
}

func TestActionHandler_UnknownActionReturnsError(t *testing.T) {
	handler := NewActionHandler(false)

	err := handler.Enforce(context.Background(), &api.Event{PID: 0}, &api.ActionResult{Action: api.Action(42)})
	if err == nil {
		t.Fatal("expected error for unknown action")
	}

	stats := handler.GetStats()
	if stats.Allowed+stats.Denied+stats.Logged+stats.AuditDenied != 0 {
		t.Errorf("unknown action must not be counted, got %+v", stats)
	}
}

func TestActionHandler_DenyPIDZeroIsNoop(t *testing.T) {
	handler := NewActionHandler(false)

	// PID 0 must never be signalled (kill(0, ...) would target our own
	// process group).
	result := &api.ActionResult{Action: api.ActionDeny}
	err := handler.Enforce(context.Background(), &api.Event{PID: 0}, result)
	if err == nil || result.Enforced || result.EnforcementAttempted {
		t.Fatalf("expected refused enforcement for PID 0: %+v, %v", result, err)
	}
	if got := handler.GetStats().Denied; got != 1 {
		t.Errorf("Denied = %d, want 1", got)
	}
}

func TestActionHandler_ConcurrentStats(t *testing.T) {
	handler := NewActionHandler(true)
	ctx := context.Background()

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			_ = handler.Enforce(ctx, &api.Event{PID: 0}, &api.ActionResult{Action: api.ActionAllow})
		}()
		go func() {
			defer wg.Done()
			_ = handler.Enforce(ctx, &api.Event{PID: 99}, &api.ActionResult{Action: api.ActionDeny})
		}()
		go func() {
			defer wg.Done()
			_ = handler.Enforce(ctx, &api.Event{PID: 0}, &api.ActionResult{Action: api.ActionLog})
		}()
	}
	wg.Wait()

	stats := handler.GetStats()
	if stats.Allowed != 50 || stats.AuditDenied != 50 || stats.Logged != 100 || stats.Denied != 0 {
		t.Errorf("unexpected concurrent stats: %+v", stats)
	}
}

func boolUint(v bool) uint64 {
	if v {
		return 1
	}
	return 0
}

func TestActionHandler_TruthfulTerminationOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		attempted bool
		err       error
		outcome   string
	}{
		{"accepted", true, nil, "succeeded"},
		{"signal failed", true, errors.New("permission denied"), "failed"},
		{"identity refused", false, errors.New("identity unavailable"), "refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewActionHandler(false)
			h.terminate = func(*api.Event) (bool, error) { return tc.attempted, tc.err }
			before := testutil.ToFloat64(metrics.TerminationsTotal.WithLabelValues(tc.outcome))
			beforeAttempt := testutil.ToFloat64(metrics.TerminationsTotal.WithLabelValues("attempted"))
			r := &api.ActionResult{Action: api.ActionDeny}
			err := h.Enforce(context.Background(), &api.Event{PID: 42}, r)
			if !errors.Is(err, tc.err) || r.EnforcementAttempted != tc.attempted || r.Enforced != (tc.err == nil) || (r.EnforcementError != "") != (tc.err != nil) {
				t.Fatalf("outcome: %+v, %v", r, err)
			}
			s := h.GetStats()
			if s.EnforcementAttempted != boolUint(tc.attempted) || s.EnforcementSucceeded != boolUint(tc.err == nil) || s.EnforcementFailed != boolUint(tc.attempted && tc.err != nil) || s.EnforcementRefused != boolUint(!tc.attempted) {
				t.Fatalf("stats: %+v", s)
			}
			if got := testutil.ToFloat64(metrics.TerminationsTotal.WithLabelValues(tc.outcome)) - before; got != 1 {
				t.Fatalf("outcome metric delta = %v", got)
			}
			if got := testutil.ToFloat64(metrics.TerminationsTotal.WithLabelValues("attempted")) - beforeAttempt; got != float64(boolUint(tc.attempted)) {
				t.Fatalf("attempt metric delta = %v", got)
			}
		})
	}
}

func TestActionHandler_ResetsOutcomeAndSuppressesTerminationInAudit(t *testing.T) {
	for _, audit := range []bool{false, true} {
		h := NewActionHandler(audit)
		h.terminate = func(*api.Event) (bool, error) { t.Fatal("must not terminate"); return false, nil }
		for _, action := range []api.Action{api.ActionAllow, api.ActionLog, api.ActionDeny} {
			r := &api.ActionResult{Action: action, Audit: true, Enforced: true, EnforcementAttempted: true, EnforcementError: "stale"}
			if err := h.Enforce(context.Background(), &api.Event{PID: 42}, r); err != nil {
				t.Fatal(err)
			}
			if r.Enforced || r.EnforcementAttempted || r.EnforcementError != "" {
				t.Fatalf("stale outcome: %+v", r)
			}
		}
	}
}

func TestActionHandler_CancelledContextRefusesTermination(t *testing.T) {
	h := NewActionHandler(false)
	h.terminate = func(*api.Event) (bool, error) { t.Fatal("must not terminate"); return false, nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &api.ActionResult{Action: api.ActionDeny}
	if err := h.Enforce(ctx, &api.Event{PID: 42}, r); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if r.Enforced || r.EnforcementAttempted || h.GetStats().EnforcementRefused != 1 {
		t.Fatalf("outcome: %+v", r)
	}
}

func TestActionHandler_KernelDeniedIsEnforcedWithoutTermination(t *testing.T) {
	h := NewActionHandler(false)
	h.terminate = func(*api.Event) (bool, error) { t.Fatal("must not terminate"); return false, nil }
	r := &api.ActionResult{Action: api.ActionDeny, EnforcementAttempted: true, EnforcementError: "stale"}
	h.RecordKernelDenied(&api.Event{PID: 42, KernelDenied: true}, r)
	if !r.Enforced || r.EnforcementAttempted || r.EnforcementError != "" {
		t.Fatalf("outcome: %+v", r)
	}
	s := h.GetStats()
	if s.Denied != 1 || s.EnforcementAttempted != 0 || s.EnforcementSucceeded != 0 || s.EnforcementFailed != 0 || s.EnforcementRefused != 0 {
		t.Fatalf("kernel counted as termination: %+v", s)
	}
}
