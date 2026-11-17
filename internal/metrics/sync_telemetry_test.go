package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The reason label is part of the public metrics contract: alerts key off
// these exact values, and they must stay a bounded set.
func TestKernelSyncReasonSetIsBounded(t *testing.T) {
	want := map[string]bool{
		"map_full":         true,
		"verifier_reject":  true,
		"invalid_key":      true,
		"generation_stale": true,
		"unknown":          true,
	}
	for _, reason := range []string{
		SyncReasonMapFull, SyncReasonVerifierReject, SyncReasonInvalidKey,
		SyncReasonGenerationStale, SyncReasonUnknown,
	} {
		if !want[reason] {
			t.Errorf("unexpected sync reason %q", reason)
		}
		delete(want, reason)
	}
	if len(want) != 0 {
		t.Errorf("missing sync reasons: %v", want)
	}
}

func TestRecordKernelSyncCounters(t *testing.T) {
	failFull := testutil.ToFloat64(KernelSyncFailuresTotal.WithLabelValues(SyncReasonMapFull))
	failStale := testutil.ToFloat64(KernelSyncFailuresTotal.WithLabelValues(SyncReasonGenerationStale))
	successes := testutil.ToFloat64(KernelSyncSuccessesTotal)

	RecordKernelSyncFailure(SyncReasonMapFull)
	RecordKernelSyncFailure(SyncReasonMapFull)
	RecordKernelSyncSuccess()

	if got := testutil.ToFloat64(KernelSyncFailuresTotal.WithLabelValues(SyncReasonMapFull)) - failFull; got != 2 {
		t.Errorf("map_full failures +%v, want +2", got)
	}
	if got := testutil.ToFloat64(KernelSyncFailuresTotal.WithLabelValues(SyncReasonGenerationStale)) - failStale; got != 0 {
		t.Errorf("generation_stale failures +%v, want +0", got)
	}
	if got := testutil.ToFloat64(KernelSyncSuccessesTotal) - successes; got != 1 {
		t.Errorf("successes +%v, want +1", got)
	}
}

func TestSetKernelSyncHealthy(t *testing.T) {
	SetKernelSyncHealthy(false)
	if got := testutil.ToFloat64(KernelSyncHealthy); got != 0 {
		t.Errorf("degraded posture gauge = %v, want 0", got)
	}
	SetKernelSyncHealthy(true)
	if got := testutil.ToFloat64(KernelSyncHealthy); got != 1 {
		t.Errorf("healthy posture gauge = %v, want 1", got)
	}
}
