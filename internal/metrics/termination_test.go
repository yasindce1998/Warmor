package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestTerminationMetricsRegisteredWithLabels(t *testing.T) {
	// Instantiate a child so the Vec's family is visible to Gather.
	TerminationsTotal.WithLabelValues("succeeded")
	TerminationRefusals.WithLabelValues("unknown")
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"warmor_process_terminations_total":         "outcome",
		"warmor_process_termination_refusals_total": "reason",
	}
	for name, label := range want {
		var found bool
		for _, mf := range families {
			if mf.GetName() != name {
				continue
			}
			found = true
			for _, metric := range mf.GetMetric() {
				hasLabel := false
				for _, l := range metric.GetLabel() {
					if l.GetName() == label {
						hasLabel = true
					}
				}
				if !hasLabel {
					t.Errorf("%s: missing %q label", name, label)
				}
			}
		}
		if !found {
			t.Errorf("%s: metric family not registered", name)
		}
	}
}

func TestTerminationLatencyHasBoundedBuckets(t *testing.T) {
	var m dto.Metric
	if err := TerminationLatency.Write(&m); err != nil {
		t.Fatal(err)
	}
	buckets := m.GetHistogram().GetBucket()
	if len(buckets) == 0 || len(buckets) > 20 {
		t.Fatalf("latency histogram bucket count = %d, not bounded", len(buckets))
	}
}
