package enforcer

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

func histCount(t *testing.T, h *prometheus.HistogramVec, labels ...string) uint64 {
	t.Helper()
	m := &dto.Metric{}
	if err := h.WithLabelValues(labels...).(prometheus.Metric).Write(m); err != nil {
		t.Fatal(err)
	}
	return m.GetHistogram().GetSampleCount()
}

func TestHandleEvent_RecordsEventAndWASMMetrics(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{poolSize: 1, policyWasm: wasmtest.LoopOnUIDPolicy()})
	e.policyID = "metrics-test.wasm"
	e.evaluator.SetTimeout(20 * time.Millisecond)

	processed := testutil.ToFloat64(metrics.EventsProcessed.WithLabelValues("PROCESS"))
	execs := histCount(t, metrics.WASMExecDuration, "metrics-test.wasm")
	timeouts := testutil.ToFloat64(metrics.WASMExecErrors.WithLabelValues("metrics-test.wasm", "timeout"))

	e.handleEvent(&api.Event{PID: 0, UID: 1000, Filename: "/bin/ok"})
	e.handleEvent(&api.Event{PID: 0, UID: 1000, Filename: "/bin/ok"}) // cache hit: no WASM run
	e.handleEvent(&api.Event{PID: 0, UID: 0, Filename: "/bin/spin"})  // times out

	if d := testutil.ToFloat64(metrics.EventsProcessed.WithLabelValues("PROCESS")) - processed; d != 3 {
		t.Errorf("events processed +%v, want +3", d)
	}
	if d := histCount(t, metrics.WASMExecDuration, "metrics-test.wasm") - execs; d != 2 {
		t.Errorf("wasm executions +%d, want +2 (cache hits do not run WASM)", d)
	}
	if d := testutil.ToFloat64(metrics.WASMExecErrors.WithLabelValues("metrics-test.wasm", "timeout")) - timeouts; d != 1 {
		t.Errorf("wasm timeouts +%v, want +1", d)
	}
}

func TestReloadPolicy_RecordsPolicyLoads(t *testing.T) {
	isolateCacheDir(t)
	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	id := filepath.Base(testPolicyPath)
	ok := testutil.ToFloat64(metrics.PolicyLoads.WithLabelValues(id, metrics.StatusSuccess))
	if err := e.ReloadPolicy(); err != nil {
		t.Fatal(err)
	}
	if d := testutil.ToFloat64(metrics.PolicyLoads.WithLabelValues(id, metrics.StatusSuccess)) - ok; d != 1 {
		t.Errorf("successful loads +%v, want +1", d)
	}

	e.policyPath = filepath.Join(t.TempDir(), "gone.wasm")
	bad := testutil.ToFloat64(metrics.PolicyLoads.WithLabelValues("gone.wasm", metrics.StatusError))
	if err := e.ReloadPolicy(); err == nil {
		t.Fatal("reload of a missing policy succeeded")
	}
	if d := testutil.ToFloat64(metrics.PolicyLoads.WithLabelValues("gone.wasm", metrics.StatusError)) - bad; d != 1 {
		t.Errorf("failed loads +%v, want +1", d)
	}
}

func TestNew_SetsLoaderStatus(t *testing.T) {
	isolateCacheDir(t)
	for _, tc := range []struct {
		lsmEnforce bool
		want       float64
	}{
		// The fake platform never provides LSM enforcement.
		{lsmEnforce: true, want: 0},
		{lsmEnforce: false, want: 1},
	} {
		stubPlatform(t, &fakePlatform{}, nil)
		e, err := New(context.Background(), testPolicyPath, &Options{MetricsPort: -1, LSMEnforce: tc.lsmEnforce})
		if err != nil {
			t.Fatal(err)
		}
		e.Close()
		if got := testutil.ToFloat64(metrics.EBPFLoaderStatus); got != tc.want {
			t.Errorf("LSMEnforce=%v: loader status = %v, want %v", tc.lsmEnforce, got, tc.want)
		}
	}
}

type countingPolicyMap struct {
	fakePolicyMap
	n int
}

func (c *countingPolicyMap) Stats() (int, error) { return c.n, nil }

func TestMapEntriesMetric(t *testing.T) {
	pm := &countingPolicyMap{n: 42}
	e := &Enforcer{policyMap: pm}
	e.updateMapEntries()
	if got := testutil.ToFloat64(metrics.MapEntries.WithLabelValues("policy_map")); got != 42 {
		t.Fatalf("map entries = %v, want 42", got)
	}

	// The periodic loop refreshes it and stops with the context.
	ctx, cancel := context.WithCancel(context.Background())
	e.ctx = ctx
	pm.n = 7
	e.wg.Add(1)
	go e.mapEntriesLoop(time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for testutil.ToFloat64(metrics.MapEntries.WithLabelValues("policy_map")) != 7 {
		if time.Now().After(deadline) {
			t.Fatal("map entries not refreshed")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	e.wg.Wait()
}
