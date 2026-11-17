package enforcer

import (
	"bytes"
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/yasindce1998/warmor/internal/kernelmap"
	"github.com/yasindce1998/warmor/internal/logging"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestKernelSyncFailureReasonClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"map full", syscall.E2BIG, metrics.SyncReasonMapFull},
		{"wrapped map full", fmt.Errorf("put: %w", syscall.ENOSPC), metrics.SyncReasonMapFull},
		{"verifier reject", fmt.Errorf("put: %w", syscall.EPERM), metrics.SyncReasonVerifierReject},
		{"access denied", syscall.EACCES, metrics.SyncReasonVerifierReject},
		{"unsound key", errNotKeyDetermined, metrics.SyncReasonInvalidKey},
		{"unmatchable key", fmt.Errorf("rule: %w", kernelmap.ErrNotKernelMatchable), metrics.SyncReasonInvalidKey},
		{"stale decision", errStaleDecision, metrics.SyncReasonGenerationStale},
		{"stale generation", kernelmap.ErrStaleGeneration, metrics.SyncReasonGenerationStale},
		{"unknown", errors.New("unexpected error"), metrics.SyncReasonUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := kernelSyncFailureReason(tc.err); got != tc.want {
				t.Fatalf("reason = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestKernelSyncCountersThroughSyncPath(t *testing.T) {
	deny := &api.ActionResult{Action: api.ActionDeny}
	ev := &api.Event{Filename: "/bin/x"}
	successBefore := testutil.ToFloat64(metrics.KernelSyncSuccessesTotal)
	failBefore := testutil.ToFloat64(metrics.KernelSyncFailuresTotal.WithLabelValues(metrics.SyncReasonMapFull))

	ok := &Enforcer{policyMap: &fakePolicyMap{}}
	if err := ok.syncToPolicyMap(ev, deny, 0, 0); err != nil {
		t.Fatalf("successful sync: %v", err)
	}
	if got := testutil.ToFloat64(metrics.KernelSyncSuccessesTotal) - successBefore; got != 1 {
		t.Errorf("success counter +%v, want +1", got)
	}
	if got := testutil.ToFloat64(metrics.KernelSyncFailuresTotal.WithLabelValues(metrics.SyncReasonMapFull)) - failBefore; got != 0 {
		t.Errorf("failure counter +%v on success, want +0", got)
	}
	if !ok.KernelSyncHealthy() {
		t.Error("success must keep the posture healthy")
	}

	failing := &Enforcer{
		policyMap: &fakePolicyMap{setErr: syscall.E2BIG},
		logger:    logging.NewLoggerWithWriter("error", &bytes.Buffer{}),
	}
	successBefore = testutil.ToFloat64(metrics.KernelSyncSuccessesTotal)
	failBefore = testutil.ToFloat64(metrics.KernelSyncFailuresTotal.WithLabelValues(metrics.SyncReasonMapFull))
	if err := failing.syncToPolicyMap(ev, deny, 0, 0); err == nil {
		t.Fatal("map-full failure was not returned")
	}
	if got := testutil.ToFloat64(metrics.KernelSyncFailuresTotal.WithLabelValues(metrics.SyncReasonMapFull)) - failBefore; got != 1 {
		t.Errorf("map_full failure counter +%v, want +1", got)
	}
	if got := testutil.ToFloat64(metrics.KernelSyncSuccessesTotal) - successBefore; got != 0 {
		t.Errorf("success counter +%v on failure, want +0", got)
	}
	// A single failure is below the threshold and must not flap the posture.
	if !failing.KernelSyncHealthy() {
		t.Error("one failure must not degrade the posture")
	}
}

func TestKernelSyncHealthThresholdAndHysteresis(t *testing.T) {
	e := &Enforcer{}
	ev := &api.Event{Filename: "/bin/x"}
	fail := errors.New("sync failed")

	if !e.KernelSyncHealthy() {
		t.Fatal("default posture must be healthy")
	}
	// Degrading requires more than the threshold of failures in the window.
	for i := 0; i < kernelSyncFailureThreshold; i++ {
		e.recordSync(ev, fail)
	}
	if !e.KernelSyncHealthy() {
		t.Fatalf("posture degraded at %d failures (threshold %d)", kernelSyncFailureThreshold, kernelSyncFailureThreshold)
	}
	if n, _ := e.syncHealth.stats(); n != kernelSyncFailureThreshold {
		t.Fatalf("recent failures = %d, want %d", n, kernelSyncFailureThreshold)
	}

	e.recordSync(ev, fail)
	if e.KernelSyncHealthy() {
		t.Fatal("posture must degrade once failures exceed the threshold")
	}

	// A single success, and even a short run, must not recover (hysteresis).
	e.recordSync(ev, nil)
	if e.KernelSyncHealthy() {
		t.Fatal("one success must not recover a degraded posture")
	}
	for i := 0; i < kernelSyncRecoveryStreak-2; i++ {
		e.recordSync(ev, nil)
	}
	if e.KernelSyncHealthy() {
		t.Fatal("a short success run must not recover a degraded posture")
	}

	// The full recovery streak clears the posture and resets the window, so a
	// single later failure does not flap it back to degraded.
	e.recordSync(ev, nil)
	if !e.KernelSyncHealthy() {
		t.Fatal("recovery streak must restore a healthy posture")
	}
	e.recordSync(ev, fail)
	if !e.KernelSyncHealthy() {
		t.Fatal("one failure after recovery must not flap the posture")
	}
	if n, healthy := e.syncHealth.stats(); n != 1 || !healthy {
		t.Fatalf("posture after recovery window = (%d, %v), want (1, true)", n, healthy)
	}
}

// Degraded kernel fast-path coverage must never make the daemon unready:
// readiness and its reporting stay on the original Ready() gate.
func TestKernelSyncHealthDoesNotFlipDefaultReadiness(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{audit: true})
	e.processing.Store(true)
	if err := e.Ready(); err != nil {
		t.Fatalf("baseline readiness: %v", err)
	}

	ev := &api.Event{Filename: "/bin/x"}
	fail := errors.New("sync failed")
	for i := 0; i < kernelSyncFailureThreshold+1; i++ {
		e.recordSync(ev, fail)
	}
	if e.KernelSyncHealthy() {
		t.Fatal("posture should be degraded")
	}
	if err := e.Ready(); err != nil {
		t.Fatalf("degraded kernel sync flipped readiness: %v", err)
	}
	report := e.ReadinessReport()
	if !report.Ready {
		t.Error("readiness report gate must ignore kernel sync health")
	}
	if report.KernelSyncHealthy {
		t.Error("readiness report must expose the degraded kernel sync posture")
	}
}
