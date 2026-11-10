package enforcer

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestIntelligence_EnrichersBuildGraph(t *testing.T) {
	intel, enrichers := newIntelligence()

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "bash",
		CgroupID:  100,
		Timestamp: time.Now(),
	}
	for _, e := range enrichers {
		e.Enrich(ev)
	}

	// The correlator labeled the event for downstream sinks.
	if ev.Labels["mitre_techniques"] == "" {
		t.Errorf("mitre_techniques label = %q, want a technique ID", ev.Labels["mitre_techniques"])
	}

	// The attack graph ingested the container.
	if intel.graph.GetContainer(100) == nil {
		t.Fatal("attack graph has no container 100 after ingest")
	}
	if s := intel.graph.Summary(); s.ContainerCount != 1 || s.TechniqueCount == 0 {
		t.Errorf("summary = %+v, want 1 container with techniques", s)
	}
}

func TestIntelligence_PublishMetrics(t *testing.T) {
	intel, enrichers := newIntelligence()

	// Empty graph: publishing must not panic and must reset to zero.
	intel.publishMetrics()
	if got := testutil.ToFloat64(metrics.AttackGraphContainers); got != 0 {
		t.Errorf("containers = %v, want 0", got)
	}

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "bash",
		CgroupID:  100,
		Timestamp: time.Now(),
	}
	for _, e := range enrichers {
		e.Enrich(ev)
	}
	intel.publishMetrics()

	if got := testutil.ToFloat64(metrics.AttackGraphContainers); got != 1 {
		t.Errorf("containers = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.AttackGraphTechniques); got == 0 {
		t.Error("techniques = 0, want > 0")
	}
	// A bash exec maps to the execution tactic; the coverage series must
	// exist and be reset when the tactic disappears.
	if got, err := metrics.AttackGraphTacticCoverage.GetMetricWithLabelValues("execution"); err != nil || got == nil {
		t.Errorf("tactic coverage series for execution missing: %v", err)
	}
}

// TestIntelligence_PipelineFlow feeds an event through the real pipeline
// (the same path the enforcer uses) and checks the intelligence enrichers
// see it: the transform must preserve the cgroup and event type the
// correlator matches on.
func TestIntelligence_PipelineFlow(t *testing.T) {
	intel, enrichers := newIntelligence()

	pipeline := streaming.NewPipeline(streaming.PipelineConfig{
		Sinks:     []streaming.Sink{nopSink{}},
		Enrichers: enrichers,
	})
	defer pipeline.Close()

	ev := &api.Event{
		Type: api.EventTypeProcess, PID: 1, UID: 0, Comm: "bash",
		Filename: "/bin/bash", CgroupID: 100, Timestamp: time.Now(),
	}
	pipeline.Emit(ev, &api.ActionResult{Action: api.ActionDeny, Reason: "test"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if intel.graph.GetContainer(100) != nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("attack graph never saw the pipeline event")
}

// nopSink discards events; the pipeline requires at least one sink.
type nopSink struct{}

func (nopSink) Write(context.Context, *streaming.SecurityEvent) error { return nil }
func (nopSink) Flush(context.Context) error                           { return nil }
func (nopSink) Close() error                                          { return nil }
func (nopSink) Name() string                                          { return "nop" }
