package enforcer

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
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

// refusalReason is intentionally a closed set: any unrecognized error text
// must fall back to "unknown" instead of creating a new label value.
func TestRefusalReasonIsBounded(t *testing.T) {
	allowed := map[string]bool{
		refusalReasonPIDZero: true, refusalReasonContext: true, refusalReasonUnsafePID: true,
		refusalReasonMissingTS: true, refusalReasonPIDFD: true, refusalReasonStale: true,
		refusalReasonClockDomain: true, refusalReasonNamespace: true,
		refusalReasonClockUnavail: true, refusalReasonIdentity: true, refusalReasonUnknown: true,
	}
	inputs := []string{
		"termination refused: PID is unknown/zero",
		"context canceled",
		"context deadline exceeded",
		"process identity cannot be verified; termination refused: unsafe PID 2147483648",
		"process identity cannot be verified; termination refused: missing trusted kernel monotonic timestamp",
		"process identity cannot be verified; termination refused: initial PID namespace required for host-PID kernel events (use hostPID)",
		"process identity cannot be verified; termination refused: procfs PID namespace does not match daemon",
		"process identity cannot be verified; termination refused: cannot verify initial clock domain: open timens_offsets: no such file",
		"process identity cannot be verified; termination refused: read monotonic clock: input/output error",
		"process identity cannot be verified; termination refused: read USER_HZ: input/output error",
		"process identity cannot be verified; termination refused: future timestamp or wrong clock domain",
		"process identity cannot be verified; termination refused: process start tick does not strictly precede event (stale/reused PID)",
		"read process 42 start identity: open /proc/42/stat: no such file or directory",
		"process identity cannot be verified; termination refused: invalid process start tick or USER_HZ",
		"pidfd_open(42), no numeric-PID fallback: function not implemented",
		"a brand new error string never seen before",
		"",
	}
	for _, in := range inputs {
		if r := refusalReason(in); !allowed[r] {
			t.Errorf("refusalReason(%q) = %q outside the bounded set", in, r)
		}
	}
}

func TestRefusalReasonClassification(t *testing.T) {
	for _, tc := range []struct{ errText, want string }{
		{"termination refused: PID is unknown/zero", refusalReasonPIDZero},
		{"context deadline exceeded", refusalReasonContext},
		{"process identity cannot be verified; termination refused: unsafe PID 1", refusalReasonUnsafePID},
		{"process identity cannot be verified; termination refused: missing trusted kernel monotonic timestamp", refusalReasonMissingTS},
		{"pidfd_open(42), no numeric-PID fallback: no such process", refusalReasonPIDFD},
		{"process identity cannot be verified; termination refused: process start tick does not strictly precede event (stale)", refusalReasonStale},
		{"process identity cannot be verified; termination refused: future timestamp or wrong clock domain", refusalReasonClockDomain},
		{"process identity cannot be verified; termination refused: initial PID namespace required", refusalReasonNamespace},
		{"process identity cannot be verified; termination refused: cannot verify initial clock domain: read: EIO", refusalReasonNamespace},
		{"process identity cannot be verified; termination refused: read monotonic clock: EIO", refusalReasonClockUnavail},
		{"process identity cannot be verified; termination refused: read USER_HZ: EIO", refusalReasonClockUnavail},
		{"read process 42 start identity: stat: ENOENT", refusalReasonIdentity},
		{"process identity cannot be verified; termination refused: invalid process start tick or USER_HZ", refusalReasonIdentity},
		{"identity unavailable", refusalReasonIdentity},
		{"totally unexpected", refusalReasonUnknown},
	} {
		if got := refusalReason(tc.errText); got != tc.want {
			t.Errorf("refusalReason(%q) = %q, want %q", tc.errText, got, tc.want)
		}
	}
}

func TestActionHandler_RefusalReasonMetric(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pid     uint32
		cancel  bool
		termErr error
		reason  string
	}{
		{"pid zero", 0, false, nil, refusalReasonPIDZero},
		{"context canceled", 42, true, nil, refusalReasonContext},
		{"namespace mismatch", 42, false, errors.New("process identity cannot be verified; termination refused: initial PID namespace required"), refusalReasonNamespace},
		{"clock failure", 42, false, errors.New("process identity cannot be verified; termination refused: read monotonic clock: EIO"), refusalReasonClockUnavail},
		{"pidfd unsupported", 42, false, errors.New("pidfd_open(42), no numeric-PID fallback: function not implemented"), refusalReasonPIDFD},
		{"stale event", 42, false, errors.New("process identity cannot be verified; termination refused: process start tick does not strictly precede event"), refusalReasonStale},
		{"unrecognized", 42, false, errors.New("some new refusal"), refusalReasonUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewActionHandler(false)
			h.terminate = func(*api.Event) (bool, error) { return false, tc.termErr }
			ctx := context.Background()
			if tc.cancel {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			before := testutil.ToFloat64(metrics.TerminationRefusals.WithLabelValues(tc.reason))
			r := &api.ActionResult{Action: api.ActionDeny}
			if err := h.Enforce(ctx, &api.Event{PID: tc.pid}, r); err == nil {
				t.Fatal("expected refusal error")
			}
			if r.Enforced || r.EnforcementAttempted || r.EnforcementError == "" {
				t.Fatalf("not a refusal: %+v", r)
			}
			if got := testutil.ToFloat64(metrics.TerminationRefusals.WithLabelValues(tc.reason)) - before; got != 1 {
				t.Fatalf("refusal reason metric delta for %q = %v", tc.reason, got)
			}
			if got := h.GetStats().EnforcementRefused; got != 1 {
				t.Fatalf("EnforcementRefused = %d", got)
			}
		})
	}
}

func histogramState(t *testing.T) (uint64, float64) {
	t.Helper()
	var m dto.Metric
	if err := metrics.TerminationLatency.Write(&m); err != nil {
		t.Fatal(err)
	}
	h := m.GetHistogram()
	return h.GetSampleCount(), h.GetSampleSum()
}

func TestActionHandler_LatencyRecordedOnlyOnSuccess(t *testing.T) {
	countBefore, sumBefore := histogramState(t)
	h := NewActionHandler(false)
	h.terminate = func(*api.Event) (bool, error) { return true, nil }
	r := &api.ActionResult{Action: api.ActionDeny}
	if err := h.Enforce(context.Background(), &api.Event{PID: 42}, r); err != nil {
		t.Fatal(err)
	}
	countAfter, sumAfter := histogramState(t)
	if countAfter-countBefore != 1 || sumAfter <= sumBefore {
		t.Fatalf("latency not recorded on success: count %d->%d sum %v->%v", countBefore, countAfter, sumBefore, sumAfter)
	}

	for _, tc := range []struct {
		name      string
		attempted bool
		err       error
	}{
		{"failed signal", true, errors.New("permission denied")},
		{"refusal", false, errors.New("identity unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h2 := NewActionHandler(false)
			h2.terminate = func(*api.Event) (bool, error) { return tc.attempted, tc.err }
			before, _ := histogramState(t)
			_ = h2.Enforce(context.Background(), &api.Event{PID: 42}, &api.ActionResult{Action: api.ActionDeny})
			after, _ := histogramState(t)
			if after != before {
				t.Fatalf("latency recorded for non-successful outcome (count %d->%d)", before, after)
			}
		})
	}
}

func TestTerminationMetrics_Descriptors(t *testing.T) {
	// The refusal breakdown and latency histogram are separate series that do
	// not change the existing outcome series' label set.
	if got := testutil.CollectAndCount(metrics.TerminationRefusals); got < 0 {
		t.Fatalf("refusal counter not registered: %d", got)
	}
	if n := testutil.CollectAndCount(metrics.TerminationLatency); n != 1 {
		t.Fatalf("latency histogram families = %d, want 1", n)
	}
}
