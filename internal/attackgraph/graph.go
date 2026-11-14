package attackgraph

import (
	"container/list"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
)

// Node represents an observed ATT&CK technique instance in the graph.
type Node struct {
	TechniqueID string    `json:"technique_id"`
	Name        string    `json:"name"`
	Tactic      Tactic    `json:"tactic"`
	Count       int       `json:"count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// Edge represents a kill-chain progression between two technique nodes.
type Edge struct {
	From     string    `json:"from"`
	To       string    `json:"to"`
	Weight   int       `json:"weight"`
	LastSeen time.Time `json:"last_seen"`
}

// ContainerGraph holds the attack graph for a specific container.
type ContainerGraph struct {
	CgroupID uint64           `json:"cgroup_id"`
	Nodes    map[string]*Node `json:"nodes"`
	Edges    []*Edge          `json:"edges"`
	LastSeen time.Time        `json:"last_seen"`
}

// Graph maintains per-container attack graphs.
type Graph struct {
	mu         sync.RWMutex
	containers map[uint64]*ContainerGraph
	correlator *Correlator
	config     GraphConfig
	order      *list.List
	entries    map[uint64]*list.Element
}

// GraphConfig bounds retained cgroups. TTL uses local receipt time, never
// untrusted event timestamps. Technique/edge cardinality within a cgroup is
// bounded by TechniqueDB. Clock must be monotonic and safe for concurrent use.
type GraphConfig struct {
	TTL           time.Duration
	MaxContainers int
	Clock         func() time.Time
}

type observation struct {
	id uint64
	at time.Time
}

// NewGraph creates a new attack graph with the given correlator.
func NewGraph(correlator *Correlator) *Graph {
	return NewGraphWithConfig(correlator, GraphConfig{})
}

func NewGraphWithConfig(correlator *Correlator, cfg GraphConfig) *Graph {
	if cfg.TTL <= 0 {
		cfg.TTL = 30 * time.Minute
	}
	if cfg.MaxContainers <= 0 {
		cfg.MaxContainers = 4096
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if correlator == nil {
		correlator = NewCorrelator()
	}
	return &Graph{
		containers: make(map[uint64]*ContainerGraph),
		correlator: correlator,
		config:     cfg,
		order:      list.New(),
		entries:    make(map[uint64]*list.Element),
	}
}

// Ingest processes a security event and updates the attack graph.
func (g *Graph) Ingest(event *streaming.SecurityEvent) {
	if event == nil || event.CgroupID == 0 {
		return
	}

	techniques := g.correlator.Correlate(event)
	if len(techniques) == 0 {
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	received := g.config.Clock()
	now := event.Timestamp
	if now.IsZero() {
		now = received
	}
	g.prune(received)
	if el := g.entries[event.CgroupID]; el != nil {
		el.Value = observation{event.CgroupID, received}
		g.order.MoveToBack(el)
	} else {
		if len(g.containers) >= g.config.MaxContainers {
			g.remove(g.order.Front().Value.(observation).id)
		}
		g.entries[event.CgroupID] = g.order.PushBack(observation{event.CgroupID, received})
	}

	cg := g.containers[event.CgroupID]
	if cg == nil {
		cg = &ContainerGraph{
			CgroupID: event.CgroupID,
			Nodes:    make(map[string]*Node),
		}
		g.containers[event.CgroupID] = cg
	}
	if now.After(cg.LastSeen) {
		cg.LastSeen = now
	}

	for _, techID := range techniques {
		tech, ok := TechniqueDB[techID]
		if !ok {
			continue
		}

		node := cg.Nodes[techID]
		if node == nil {
			node = &Node{
				TechniqueID: techID,
				Name:        tech.Name,
				Tactic:      tech.Tactic,
				FirstSeen:   now,
			}
			cg.Nodes[techID] = node
		}
		node.Count++
		if now.After(node.LastSeen) {
			node.LastSeen = now
		}

		g.addKillChainEdges(cg, techID, now)
	}
}

// GetContainer returns an owned deep snapshot, safe to read while ingesting.
func (g *Graph) GetContainer(cgroupID uint64) *ContainerGraph {
	g.mu.RLock()
	defer g.mu.RUnlock()
	cg := g.containers[cgroupID]
	if cg == nil {
		return nil
	}
	result := *cg
	result.Nodes = make(map[string]*Node, len(cg.Nodes))
	for id, node := range cg.Nodes {
		copy := *node
		result.Nodes[id] = &copy
	}
	result.Edges = make([]*Edge, len(cg.Edges))
	for n, edge := range cg.Edges {
		copy := *edge
		result.Edges[n] = &copy
	}
	return &result
}

// Containers returns all tracked container cgroup IDs.
func (g *Graph) Containers() []uint64 {
	g.mu.RLock()
	defer g.mu.RUnlock()

	ids := make([]uint64, 0, len(g.containers))
	for id := range g.containers {
		ids = append(ids, id)
	}
	return ids
}

// Summary returns a global summary across all containers.
type GraphSummary struct {
	ContainerCount     int            `json:"container_count"`
	TechniqueCount     int            `json:"technique_count"`
	TacticCoverage     map[Tactic]int `json:"tactic_coverage"`
	HighestProgression int            `json:"highest_progression"`
}

func (g *Graph) Summary() *GraphSummary {
	g.mu.RLock()
	defer g.mu.RUnlock()

	allTechniques := make(map[string]bool)
	tacticCoverage := make(map[Tactic]int)
	highestProg := 0

	for _, cg := range g.containers {
		maxIdx := 0
		for _, node := range cg.Nodes {
			allTechniques[node.TechniqueID] = true
			tacticCoverage[node.Tactic]++
			idx := TacticIndex(node.Tactic)
			if idx > maxIdx {
				maxIdx = idx
			}
		}
		if maxIdx > highestProg {
			highestProg = maxIdx
		}
	}

	return &GraphSummary{
		ContainerCount:     len(g.containers),
		TechniqueCount:     len(allTechniques),
		TacticCoverage:     tacticCoverage,
		HighestProgression: highestProg,
	}
}

// Remove deletes a container's attack graph.
func (g *Graph) Remove(cgroupID uint64) {
	g.mu.Lock()
	g.remove(cgroupID)
	g.mu.Unlock()
}

func (g *Graph) remove(id uint64) {
	delete(g.containers, id)
	if el := g.entries[id]; el != nil {
		g.order.Remove(el)
		delete(g.entries, id)
	}
}

// Prune expires idle cgroups even when no events arrive. The owner should call
// it periodically; Ingest also prunes as a bounded hot-path fallback.
func (g *Graph) Prune() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.prune(g.config.Clock())
}

func (g *Graph) prune(now time.Time) int {
	removed := 0
	for el := g.order.Front(); el != nil; el = g.order.Front() {
		entry := el.Value.(observation)
		if now.Sub(entry.at) < g.config.TTL {
			break
		}
		g.remove(entry.id)
		removed++
	}
	return removed
}

func (g *Graph) addKillChainEdges(cg *ContainerGraph, newTechID string, now time.Time) {
	newTech, ok := TechniqueDB[newTechID]
	if !ok {
		return
	}
	newIdx := TacticIndex(newTech.Tactic)

	for techID, node := range cg.Nodes {
		if techID == newTechID {
			continue
		}
		existingIdx := TacticIndex(node.Tactic)

		if existingIdx < newIdx {
			g.addOrUpdateEdge(cg, techID, newTechID, now)
		} else if existingIdx > newIdx {
			g.addOrUpdateEdge(cg, newTechID, techID, now)
		}
	}
}

func (g *Graph) addOrUpdateEdge(cg *ContainerGraph, from, to string, now time.Time) {
	for _, edge := range cg.Edges {
		if edge.From == from && edge.To == to {
			edge.Weight++
			if now.After(edge.LastSeen) {
				edge.LastSeen = now
			}
			return
		}
	}
	cg.Edges = append(cg.Edges, &Edge{
		From:     from,
		To:       to,
		Weight:   1,
		LastSeen: now,
	})
}
