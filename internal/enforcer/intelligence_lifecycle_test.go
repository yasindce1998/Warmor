package enforcer

import (
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/yasindce1998/warmor/internal/attackgraph"
	"github.com/yasindce1998/warmor/internal/blastradius"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/streaming"
)

func TestIntelligenceMetricsExpireDuringSilence(t *testing.T) {
	now := time.Unix(1200, 0)
	clock := func() time.Time { return now }
	i := &intelligence{
		graph:         attackgraph.NewGraphWithConfig(nil, attackgraph.GraphConfig{TTL: time.Minute, Clock: clock}),
		relationships: blastradius.NewGraphWithConfig(blastradius.GraphConfig{TTL: time.Minute, Clock: clock}),
	}
	i.analyzer = blastradius.NewAnalyzer(i.relationships)
	t.Cleanup(func() { metrics.ResetBlastRadius() })
	for id := uint64(1); id <= 3; id++ {
		i.graph.Ingest(&streaming.SecurityEvent{CgroupID: id, EventType: "exec", Comm: "bash"})
		i.relationships.AddNode(&blastradius.ContainerNode{CgroupID: id})
	}
	i.relationships.AddEdge(1, 2, blastradius.EdgeNetwork, "", now)
	i.publishMetrics()
	if got := testutil.CollectAndCount(metrics.BlastRadiusReachable); got != 3 {
		t.Fatalf("exported %d series, want 3", got)
	}
	if got := testutil.ToFloat64(metrics.BlastRadiusReachable.WithLabelValues("1")); got != 1 {
		t.Fatalf("source 1 reachability %v, want 1", got)
	}
	now = now.Add(time.Minute)
	// No new event or runtime exit notification: the periodic metrics call
	// itself must expire graph nodes, edges, and stale labelled gauges.
	i.publishMetrics()
	if got := testutil.CollectAndCount(metrics.BlastRadiusReachable); got != 0 {
		t.Fatalf("retained %d expired cgroup series", got)
	}
	if got := testutil.ToFloat64(metrics.AttackGraphContainers); got != 0 {
		t.Fatalf("expired graph containers = %v", got)
	}
	if i.relationships.NodeCount() != 0 || i.relationships.EdgeCount() != 0 {
		t.Fatal("quiet relationship graph was not pruned")
	}
}

func TestIntelligenceConcurrentChurnAndMetrics(t *testing.T) {
	i := &intelligence{
		graph:         attackgraph.NewGraphWithConfig(nil, attackgraph.GraphConfig{MaxContainers: 8}),
		relationships: blastradius.NewGraphWithConfig(blastradius.GraphConfig{MaxNodes: 8, MaxEdges: 8}),
	}
	i.analyzer = blastradius.NewAnalyzer(i.relationships)
	t.Cleanup(func() { metrics.ResetBlastRadius() })
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(metrics.BlastRadiusReachable, metrics.AttackGraphContainers)
	var wg sync.WaitGroup
	wg.Go(func() {
		for n := range 2000 {
			id := uint64(n%100 + 1)
			i.graph.Ingest(&streaming.SecurityEvent{CgroupID: id, EventType: "exec", Comm: "bash"})
			i.relationships.AddNode(&blastradius.ContainerNode{CgroupID: id})
			if n%13 == 0 {
				i.graph.Remove(id)
				i.relationships.RemoveNode(id)
			}
		}
	})
	wg.Go(func() {
		for range 400 {
			i.publishMetrics()
		}
	})
	wg.Go(func() {
		for range 400 {
			families, err := registry.Gather()
			if err != nil {
				t.Errorf("gather: %v", err)
				return
			}
			for _, family := range families {
				if len(family.Metric) > 8 {
					t.Errorf("metric %s exceeded cardinality budget: %d", family.GetName(), len(family.Metric))
					return
				}
			}
		}
	})
	wg.Wait()
	i.publishMetrics()
	if got := testutil.CollectAndCount(metrics.BlastRadiusReachable); got > 8 {
		t.Fatalf("churn retained %d series", got)
	}
}
