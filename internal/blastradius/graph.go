package blastradius

import (
	"container/list"
	"maps"
	"sync"
	"time"
)

// EdgeType describes the type of relationship between containers.
type EdgeType string

const (
	EdgeNetwork      EdgeType = "network"
	EdgeSharedVolume EdgeType = "shared_volume"
	EdgeSharedPID    EdgeType = "shared_pid_ns"
	EdgeSharedIPC    EdgeType = "shared_ipc_ns"
)

// ContainerNode represents a container in the blast radius graph.
type ContainerNode struct {
	CgroupID  uint64            `json:"cgroup_id"`
	Image     string            `json:"image"`
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels,omitempty"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
}

// ContainerEdge represents a directional relationship between containers.
type ContainerEdge struct {
	From     uint64    `json:"from"`
	To       uint64    `json:"to"`
	Type     EdgeType  `json:"type"`
	Details  string    `json:"details"`
	LastSeen time.Time `json:"last_seen"`
	Count    int       `json:"count"`
}

// Graph maintains the container relationship graph for blast radius analysis.
type Graph struct {
	mu       sync.RWMutex
	nodes    map[uint64]*ContainerNode
	edges    []*ContainerEdge
	config   GraphConfig
	order    *list.List
	entries  map[uint64]*list.Element
	edgeSeen map[*ContainerEdge]time.Time
}

// GraphConfig bounds nodes and relationships independently. TTL is measured
// from local receipt time; event timestamps cannot pin state in memory.
// Clock must be monotonic and safe for concurrent use.
type GraphConfig struct {
	TTL      time.Duration
	MaxNodes int
	MaxEdges int
	Clock    func() time.Time
}

type observation struct {
	id uint64
	at time.Time
}

// NewGraph creates a new blast radius graph.
func NewGraph() *Graph {
	return NewGraphWithConfig(GraphConfig{})
}

func NewGraphWithConfig(cfg GraphConfig) *Graph {
	if cfg.TTL <= 0 {
		cfg.TTL = 30 * time.Minute
	}
	if cfg.MaxNodes <= 0 {
		cfg.MaxNodes = 4096
	}
	if cfg.MaxEdges <= 0 {
		cfg.MaxEdges = 16384
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Graph{
		nodes:    make(map[uint64]*ContainerNode),
		config:   cfg,
		order:    list.New(),
		entries:  make(map[uint64]*list.Element),
		edgeSeen: make(map[*ContainerEdge]time.Time),
	}
}

// AddNode registers or updates a container node.
func (g *Graph) AddNode(node *ContainerNode) {
	if node == nil || node.CgroupID == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.config.Clock()
	g.pruneNodes(now)
	if el := g.entries[node.CgroupID]; el != nil {
		el.Value = observation{node.CgroupID, now}
		g.order.MoveToBack(el)
	} else {
		if len(g.nodes) >= g.config.MaxNodes {
			oldest, ok := g.order.Front().Value.(observation)
			if !ok {
				panic("blastradius: invalid retention list entry")
			}
			g.removeNode(oldest.id)
		}
		g.entries[node.CgroupID] = g.order.PushBack(observation{node.CgroupID, now})
	}

	existing, ok := g.nodes[node.CgroupID]
	if ok {
		if node.LastSeen.After(existing.LastSeen) {
			existing.LastSeen = node.LastSeen
		}
		if node.Image != "" {
			existing.Image = node.Image
		}
		if node.Name != "" {
			existing.Name = node.Name
		}
		if node.Namespace != "" {
			existing.Namespace = node.Namespace
		}
		if node.Labels != nil {
			existing.Labels = maps.Clone(node.Labels)
		}
		return
	}
	g.nodes[node.CgroupID] = cloneNode(node)
}

// RemoveNode removes a container and all its edges.
func (g *Graph) RemoveNode(cgroupID uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.removeNode(cgroupID)
}

func (g *Graph) removeNode(cgroupID uint64) {
	delete(g.nodes, cgroupID)
	if el := g.entries[cgroupID]; el != nil {
		g.order.Remove(el)
		delete(g.entries, cgroupID)
	}

	filtered := g.edges[:0]
	for _, e := range g.edges {
		if e.From != cgroupID && e.To != cgroupID {
			filtered = append(filtered, e)
		} else {
			delete(g.edgeSeen, e)
		}
	}
	clear(g.edges[len(filtered):])
	g.edges = filtered
}

// Prune expires idle nodes and stale relationships on the owner's periodic
// maintenance loop, including during quiet periods without new events.
func (g *Graph) Prune() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.config.Clock()
	before := len(g.nodes) + len(g.edges)
	g.pruneNodes(now)
	kept := g.edges[:0]
	for _, edge := range g.edges {
		if now.Sub(g.edgeSeen[edge]) >= g.config.TTL {
			delete(g.edgeSeen, edge)
		} else {
			kept = append(kept, edge)
		}
	}
	clear(g.edges[len(kept):])
	g.edges = kept
	return before - len(g.nodes) - len(g.edges)
}

func (g *Graph) pruneNodes(now time.Time) {
	for el := g.order.Front(); el != nil; el = g.order.Front() {
		entry, ok := el.Value.(observation)
		if !ok {
			panic("blastradius: invalid retention list entry")
		}
		if now.Sub(entry.at) < g.config.TTL {
			break
		}
		g.removeNode(entry.id)
	}
}

// AddEdge records a relationship between two containers.
func (g *Graph) AddEdge(from, to uint64, edgeType EdgeType, details string, timestamp time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.config.Clock()
	g.pruneNodes(now)
	// Relationships without observed endpoints would outlive containers and
	// manufacture reachability. Callers must register both nodes first.
	if g.nodes[from] == nil || g.nodes[to] == nil || from == to {
		return
	}

	for _, e := range g.edges {
		if e.From == from && e.To == to && e.Type == edgeType {
			e.Count++
			g.edgeSeen[e] = now
			if timestamp.After(e.LastSeen) {
				e.LastSeen = timestamp
			}
			if details != "" {
				e.Details = details
			}
			return
		}
	}

	if len(g.edges) >= g.config.MaxEdges {
		oldest := 0
		for i, e := range g.edges {
			if g.edgeSeen[e].Before(g.edgeSeen[g.edges[oldest]]) {
				oldest = i
			}
		}
		delete(g.edgeSeen, g.edges[oldest])
		g.edges = append(g.edges[:oldest], g.edges[oldest+1:]...)
	}
	edge := &ContainerEdge{
		From:     from,
		To:       to,
		Type:     edgeType,
		Details:  details,
		LastSeen: timestamp,
		Count:    1,
	}
	g.edges = append(g.edges, edge)
	g.edgeSeen[edge] = now
}

// NodeCount returns the number of tracked containers.
func (g *Graph) NodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

// EdgeCount returns the number of tracked edges.
func (g *Graph) EdgeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.edges)
}

// GetNode returns a container node by cgroup ID.
func (g *Graph) GetNode(cgroupID uint64) *ContainerNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return cloneNode(g.nodes[cgroupID])
}

// Nodes returns all container nodes.
func (g *Graph) Nodes() []*ContainerNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]*ContainerNode, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, cloneNode(n))
	}
	return nodes
}

// EdgesFrom returns all outgoing edges from a container.
func (g *Graph) EdgesFrom(cgroupID uint64) []*ContainerEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var result []*ContainerEdge
	for _, e := range g.edges {
		if e.From == cgroupID {
			copy := *e
			result = append(result, &copy)
		}
	}
	return result
}

// EdgesTo returns all incoming edges to a container.
func (g *Graph) EdgesTo(cgroupID uint64) []*ContainerEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var result []*ContainerEdge
	for _, e := range g.edges {
		if e.To == cgroupID {
			copy := *e
			result = append(result, &copy)
		}
	}
	return result
}

func cloneNode(node *ContainerNode) *ContainerNode {
	if node == nil {
		return nil
	}
	copy := *node
	copy.Labels = maps.Clone(node.Labels)
	return &copy
}
