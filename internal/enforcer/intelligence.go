package enforcer

import (
	"time"

	"github.com/yasindce1998/warmor/internal/attackgraph"
	"github.com/yasindce1998/warmor/internal/blastradius"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/streaming"
)

// intelligence holds the node-side security intelligence built from the
// event stream when --attack-graph is set: the MITRE attack graph and the
// container-relationship graph blast radius is computed from. See
// docs/design/intelligence-chain.md.
type intelligence struct {
	correlator *attackgraph.Correlator
	graph      *attackgraph.Graph
	analyzer   *blastradius.Analyzer
}

// newIntelligence builds the attack-graph enrichers. They run in pipeline
// order: the correlator labels events with MITRE techniques (so sinks like
// SIEM carry them), the blast-radius collector records container
// relationships, and the attack graph ingests the event (it correlates
// internally, so it does not depend on the first enricher).
func newIntelligence() (*intelligence, []streaming.Enricher) {
	i := &intelligence{
		correlator: attackgraph.NewCorrelator(),
	}
	i.graph = attackgraph.NewGraph(i.correlator)
	brGraph := blastradius.NewGraph()
	i.analyzer = blastradius.NewAnalyzer(brGraph)

	enrichers := []streaming.Enricher{
		i.correlator,
		eventObserver{blastradius.NewCollector(brGraph).ProcessEvent},
		eventObserver{i.graph.Ingest},
	}
	return i, enrichers
}

// eventObserver adapts a bare event consumer to streaming.Enricher.
type eventObserver struct {
	observe func(*streaming.SecurityEvent)
}

func (o eventObserver) Enrich(event *streaming.SecurityEvent) {
	if o.observe != nil {
		o.observe(event)
	}
}

// publishMetrics exports the attack-graph summary and per-container blast
// radius. It is called from the enforcer's metrics loop, not on every
// event, so a busy host pays a constant cost.
func (i *intelligence) publishMetrics() {
	if s := i.graph.Summary(); s != nil {
		coverage := make(map[string]int, len(s.TacticCoverage))
		for tactic, n := range s.TacticCoverage {
			coverage[string(tactic)] = n
		}
		metrics.SetAttackGraph(s.ContainerCount, s.TechniqueCount, s.HighestProgression, coverage)
	}

	metrics.ResetBlastRadius()
	for _, cgid := range i.graph.Containers() {
		br := i.analyzer.Reach(cgid, 0)
		if br == nil {
			continue
		}
		metrics.SetBlastRadius(cgid, len(br.Reachable))
	}
}

// attackGraphMetricsInterval is how often the intelligence metrics are
// recomputed. The graphs are updated on every event; the gauges do not
// need to be.
const attackGraphMetricsInterval = 15 * time.Second
