package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func getHistogramVecCount(hv *prometheus.HistogramVec, labels ...string) uint64 {
	obs, err := hv.GetMetricWithLabelValues(labels...)
	if err != nil {
		return 0
	}
	metric := &dto.Metric{}
	_ = obs.(prometheus.Metric).Write(metric)
	return metric.Histogram.GetSampleCount()
}

func getGaugeVecValue(gv *prometheus.GaugeVec, labels ...string) float64 {
	g, err := gv.GetMetricWithLabelValues(labels...)
	if err != nil {
		return 0
	}
	return getGaugeValue(g)
}

func TestExporterMetricsRegistered(t *testing.T) {
	// Touch every vector so it emits at least one series.
	HookDecisions.WithLabelValues("bprm_check", "deny").Inc()
	HookLatency.WithLabelValues("bprm_check").Observe(0.00001)
	PolicyLoads.WithLabelValues("p1", "ok").Inc()
	PolicyVersion.WithLabelValues("p1").Set(3)
	AgentHeartbeats.Inc()
	AgentRegistrations.Inc()
	WASMExecDuration.WithLabelValues("p1").Observe(0.001)
	WASMExecErrors.WithLabelValues("p1").Inc()
	EventsProcessed.WithLabelValues("exec").Inc()
	EventsDropped.Inc()
	MapEntries.WithLabelValues("policy_map").Set(7)

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	names := make(map[string]bool, len(families))
	for _, f := range families {
		names[f.GetName()] = true
	}

	want := []string{
		"warmor_lsm_decisions_total",
		"warmor_lsm_decision_duration_seconds",
		"warmor_policy_loads_total",
		"warmor_policy_version",
		"warmor_agent_heartbeats_total",
		"warmor_agent_registrations_total",
		"warmor_wasm_exec_duration_seconds",
		"warmor_wasm_exec_errors_total",
		"warmor_events_processed_total",
		"warmor_events_dropped_total",
		"warmor_ebpf_map_entries",
	}
	for _, n := range want {
		if !names[n] {
			t.Errorf("metric %q not registered with default gatherer", n)
		}
	}
}

func TestExporterMetricValues(t *testing.T) {
	before := getCounterVecValue(HookDecisions, "file_open", "allow")
	HookDecisions.WithLabelValues("file_open", "allow").Add(2)
	if got := getCounterVecValue(HookDecisions, "file_open", "allow"); got != before+2 {
		t.Errorf("HookDecisions = %v, want %v", got, before+2)
	}

	hb := getHistogramVecCount(HookLatency, "file_open")
	HookLatency.WithLabelValues("file_open").Observe(0.0001)
	if got := getHistogramVecCount(HookLatency, "file_open"); got != hb+1 {
		t.Errorf("HookLatency count = %d, want %d", got, hb+1)
	}

	PolicyVersion.WithLabelValues("p2").Set(42)
	if got := getGaugeVecValue(PolicyVersion, "p2"); got != 42 {
		t.Errorf("PolicyVersion = %v, want 42", got)
	}

	MapEntries.WithLabelValues("m").Set(5)
	if got := getGaugeVecValue(MapEntries, "m"); got != 5 {
		t.Errorf("MapEntries = %v, want 5", got)
	}

	dropped := getCounterValue(EventsDropped)
	EventsDropped.Inc()
	if got := getCounterValue(EventsDropped); got != dropped+1 {
		t.Errorf("EventsDropped = %v, want %v", got, dropped+1)
	}
}

func TestHandler_ServesMetrics(t *testing.T) {
	AgentHeartbeats.Inc()
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(buf.String(), "warmor_agent_heartbeats_total") {
		t.Error("metrics output missing warmor_agent_heartbeats_total")
	}
}

func TestListenAndServe_InvalidAddr(t *testing.T) {
	if err := ListenAndServe("invalid-addr-without-port"); err == nil {
		t.Fatal("expected error for invalid address, got nil")
	}
}
