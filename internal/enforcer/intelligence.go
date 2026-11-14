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
	correlator    *attackgraph.Correlator
	graph         *attackgraph.Graph
	relationships *blastradius.Graph
	analyzer      *blastradius.Analyzer
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
	i.relationships = brGraph
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
// event. Retention and metric cardinality are capped by the graph limits.
func (i *intelligence) publishMetrics() {
	// Quiet hosts still expire departed cgroups before lifecycle events land.
	i.graph.Prune()
	if i.relationships != nil {
		i.relationships.Prune()
	}
	if s := i.graph.Summary(); s != nil {
		coverage := make(map[string]int, len(s.TacticCoverage))
		for tactic, n := range s.TacticCoverage {
			coverage[string(tactic)] = n
		}
		metrics.SetAttackGraph(s.ContainerCount, s.TechniqueCount, s.HighestProgression, coverage)
	}

	metrics.ResetBlastRadius()
	for cgid, reachable := range i.analyzer.ReachableCounts(i.graph.Containers()) {
		metrics.SetBlastRadius(cgid, reachable)
	}
}

// attackGraphMetricsInterval is how often the intelligence metrics are
// recomputed. The graphs are updated on every event; the gauges do not
// need to be.
const attackGraphMetricsInterval = 15 * time.Second

// State maintenance is independent of attack-graph metrics and heartbeat
// traffic: silent hosts must expire lineage and drift state too.
const stateMaintenanceInterval = 15 * time.Second

func (e *Enforcer) startStateMaintenance() {
	if e.lineageTracker == nil && e.driftCollector == nil {
		return
	}
	ticker := time.NewTicker(stateMaintenanceInterval)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer ticker.Stop()
		e.stateMaintenanceLoop(ticker.C)
	}()
}

// A tick channel lets tests advance maintenance without sleeping or starting
// the platform monitor. The caller owns the ticker and goroutine lifetime.
func (e *Enforcer) stateMaintenanceLoop(ticks <-chan time.Time) {
	for {
		select {
		case <-e.ctx.Done():
			return
		case _, ok := <-ticks:
			if !ok {
				return
			}
			if e.lineageTracker != nil {
				e.lineageTracker.Prune()
			}
			if e.driftCollector != nil {
				e.driftCollector.Prune()
			}
		}
	}
}
