package metrics

import (
	"errors"
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
	m, ok := obs.(prometheus.Metric)
	if !ok {
		return 0
	}
	metric := &dto.Metric{}
	if err := m.Write(metric); err != nil {
		return 0
	}
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
	// Touch every vector through its Record*/Set* helper so it emits at
	// least one series.
	RecordLSMDecision("exec", "deny")
	RecordPolicyLoad("p1", nil)
	RecordHeartbeat("agent-1", nil)
	RecordRegistration(nil)
	RecordWASMExec("p1", 0.001, errors.New("trap"), false)
	RecordEventProcessed("PROCESS")
	RecordEventDropped()
	SetMapEntries("policy_map", 7)
	SetEBPFLoaderStatus(true)
	RecordPolicyMapSync(SyncSynced)

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
		"warmor_policy_loads_total",
		"warmor_agent_heartbeats_total",
		"warmor_agent_last_heartbeat_timestamp",
		"warmor_agent_registrations_total",
		"warmor_wasm_exec_duration_seconds",
		"warmor_wasm_exec_errors_total",
		"warmor_events_processed_total",
		"warmor_events_dropped_total",
		"warmor_ebpf_map_entries",
		"warmor_ebpf_loader_status",
		"warmor_policy_map_syncs_total",
	}
	for _, n := range want {
		if !names[n] {
			t.Errorf("metric %q not registered with default gatherer", n)
		}
	}
	// Metrics nothing can produce were removed rather than left empty.
	for _, n := range []string{
		"warmor_lsm_decision_duration_seconds",
		"warmor_policy_version",
	} {
		if names[n] {
			t.Errorf("metric %q is exported but nothing updates it", n)
		}
	}
}

func TestExporterMetricValues(t *testing.T) {
	before := getCounterVecValue(HookDecisions, "file", "pass")
	RecordLSMDecision("file", "pass")
	RecordLSMDecision("file", "pass")
	if got := getCounterVecValue(HookDecisions, "file", "pass"); got != before+2 {
		t.Errorf("HookDecisions = %v, want %v", got, before+2)
	}

	loadErr := getCounterVecValue(PolicyLoads, "p2", StatusError)
	RecordPolicyLoad("p2", errors.New("bad"))
	if got := getCounterVecValue(PolicyLoads, "p2", StatusError); got != loadErr+1 {
		t.Errorf("PolicyLoads{error} = %v, want %v", got, loadErr+1)
	}

	hbErr := getCounterVecValue(AgentHeartbeats, StatusError)
	RecordHeartbeat("a2", errors.New("down"))
	if got := getCounterVecValue(AgentHeartbeats, StatusError); got != hbErr+1 {
		t.Errorf("AgentHeartbeats{error} = %v, want %v", got, hbErr+1)
	}
	if got := getGaugeVecValue(AgentLastHeartbeat, "a2"); got != 0 {
		t.Errorf("failed heartbeat set the timestamp to %v", got)
	}
	RecordHeartbeat("a2", nil)
	if got := getGaugeVecValue(AgentLastHeartbeat, "a2"); got < 1e9 {
		t.Errorf("last heartbeat timestamp = %v, want current Unix time", got)
	}

	execs := getHistogramVecCount(WASMExecDuration, "p3")
	timeouts := getCounterVecValue(WASMExecErrors, "p3", "timeout")
	RecordWASMExec("p3", 0.05, errors.New("deadline"), true)
	if got := getHistogramVecCount(WASMExecDuration, "p3"); got != execs+1 {
		t.Errorf("WASMExecDuration count = %d, want %d", got, execs+1)
	}
	if got := getCounterVecValue(WASMExecErrors, "p3", "timeout"); got != timeouts+1 {
		t.Errorf("WASMExecErrors{timeout} = %v, want %v", got, timeouts+1)
	}

	SetMapEntries("m", 5)
	if got := getGaugeVecValue(MapEntries, "m"); got != 5 {
		t.Errorf("MapEntries = %v, want 5", got)
	}

	SetEBPFLoaderStatus(false)
	if got := getGaugeValue(EBPFLoaderStatus); got != 0 {
		t.Errorf("EBPFLoaderStatus = %v, want 0", got)
	}
	SetEBPFLoaderStatus(true)
	if got := getGaugeValue(EBPFLoaderStatus); got != 1 {
		t.Errorf("EBPFLoaderStatus = %v, want 1", got)
	}
}

func TestHandler_ServesMetrics(t *testing.T) {
	RecordHeartbeat("agent-h", nil)
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
