package enforcer

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/yasindce1998/warmor/internal/kernelmap"
	"github.com/yasindce1998/warmor/internal/logging"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/pkg/api"
)

func syncCount(result string) float64 {
	return testutil.ToFloat64(metrics.PolicyMapSyncs.WithLabelValues(result))
}

func TestSyncToPolicyMap_CountsOutcomes(t *testing.T) {
	results := []string{metrics.SyncSynced, metrics.SyncFailed, metrics.SyncSkippedUnmatchable,
		metrics.SyncSkippedUnsound, metrics.SyncSkippedStale}
	before := map[string]float64{}
	for _, r := range results {
		before[r] = syncCount(r)
	}
	deny := &api.ActionResult{Action: api.ActionDeny}
	exec := &api.Event{Filename: "/bin/x"}

	ok := &Enforcer{policyMap: &fakePolicyMap{}, logger: logging.NewLoggerWithWriter("error", &bytes.Buffer{})}
	if err := ok.syncToPolicyMap(exec, deny, 0, 0); err != nil {
		t.Fatalf("sync: %v", err)
	}
	// Unsound: the decision reads uid, which no kernel key covers.
	if err := ok.syncToPolicyMap(exec, deny, 0, 1<<1); !errors.Is(err, errNotKeyDetermined) {
		t.Fatalf("unsound err = %v", err)
	}
	// Unmatchable: refused by the syncer (here an empty pattern).
	if err := ok.syncToPolicyMap(&api.Event{}, deny, 0, 0); !errors.Is(err, kernelmap.ErrNotKernelMatchable) {
		t.Fatalf("unmatchable err = %v", err)
	}
	refusing := &Enforcer{policyMap: &fakePolicyMap{setErr: fmt.Errorf("x: %w", kernelmap.ErrNotKernelMatchable)}}
	_ = refusing.syncToPolicyMap(exec, deny, 0, 0)
	// Stale generation.
	if err := ok.syncToPolicyMap(exec, deny, 99, 0); !errors.Is(err, errStaleDecision) {
		t.Fatalf("stale err = %v", err)
	}
	// Failure: the map write itself failed.
	failing := &Enforcer{policyMap: &fakePolicyMap{setErr: errors.New("E2BIG")},
		logger: logging.NewLoggerWithWriter("error", &bytes.Buffer{})}
	if err := failing.syncToPolicyMap(exec, deny, 0, 0); err == nil {
		t.Fatal("write failure not returned")
	}

	want := map[string]float64{
		metrics.SyncSynced: 1, metrics.SyncSkippedUnsound: 1, metrics.SyncSkippedUnmatchable: 2,
		metrics.SyncSkippedStale: 1, metrics.SyncFailed: 1,
	}
	for _, r := range results {
		if got := syncCount(r) - before[r]; got != want[r] {
			t.Errorf("%s: +%v, want +%v", r, got, want[r])
		}
	}
}

func TestSyncToPolicyMap_FailureLogsAreRateLimited(t *testing.T) {
	var buf bytes.Buffer
	e := &Enforcer{policyMap: &fakePolicyMap{setErr: errors.New("map full")},
		logger: logging.NewLoggerWithWriter("error", &buf)}
	ev := &api.Event{Filename: "/bin/x"}
	deny := &api.ActionResult{Action: api.ActionDeny}

	for i := 0; i < 50; i++ {
		_ = e.syncToPolicyMap(ev, deny, 0, 0)
	}
	if n := strings.Count(buf.String(), "map full"); n != 1 {
		t.Fatalf("logged %d failures in a burst, want 1:\n%s", n, buf.String())
	}

	// After the interval the next failure is logged with the suppressed count.
	e.syncFailLog.last = time.Now().Add(-2 * syncFailureLogInterval)
	_ = e.syncToPolicyMap(ev, deny, 0, 0)
	if !strings.Contains(buf.String(), "49 similar failures suppressed") {
		t.Fatalf("suppressed count not reported:\n%s", buf.String())
	}
}
