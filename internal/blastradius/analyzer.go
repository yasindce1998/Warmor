package blastradius

// ReachableNode represents a container reachable from a compromised node.
type ReachableNode struct {
	CgroupID uint64     `json:"cgroup_id"`
	Image    string     `json:"image"`
	Name     string     `json:"name"`
	Hops     int        `json:"hops"`
	Path     []PathEdge `json:"path"`
}

// PathEdge describes one hop in the path from source to target.
type PathEdge struct {
	From    uint64   `json:"from"`
	To      uint64   `json:"to"`
	Type    EdgeType `json:"type"`
	Details string   `json:"details"`
}

// BlastRadius is the result of a blast radius query.
type BlastRadius struct {
	Source    uint64          `json:"source"`
	Reachable []ReachableNode `json:"reachable"`
	TotalHops int             `json:"total_hops"`
}

// Analyzer performs blast radius calculations on the graph.
type Analyzer struct {
	graph *Graph
}

// NewAnalyzer creates a blast radius analyzer for the given graph.
func NewAnalyzer(graph *Graph) *Analyzer {
	return &Analyzer{graph: graph}
}

// ReachableCounts returns undirected reachability counts from a single graph
// snapshot. Metrics need connected-component sizes, not a separate path-bearing
// BFS per source. Copying the bounded topology also releases the writer lock
// before traversing it, so a scrape cannot stall ingestion for V BFS queries.
func (a *Analyzer) ReachableCounts(sources []uint64) map[uint64]int {
	a.graph.mu.RLock()
	adjacency := make(map[uint64][]uint64, len(a.graph.nodes))
	for id := range a.graph.nodes {
		adjacency[id] = nil
	}
	for _, edge := range a.graph.edges {
		adjacency[edge.From] = append(adjacency[edge.From], edge.To)
		adjacency[edge.To] = append(adjacency[edge.To], edge.From)
	}
	a.graph.mu.RUnlock()
	counts := make(map[uint64]int, len(adjacency))
	for source := range adjacency {
		if _, visited := counts[source]; visited {
			continue
		}
		component := []uint64{source}
		counts[source] = 0
		for index := 0; index < len(component); index++ {
			for _, neighbor := range adjacency[component[index]] {
				if _, visited := counts[neighbor]; visited {
					continue
				}
				counts[neighbor] = 0
				component = append(component, neighbor)
			}
		}
		for _, id := range component {
			counts[id] = len(component) - 1
		}
	}
	result := make(map[uint64]int, len(sources))
	for _, source := range sources {
		result[source] = counts[source]
	}
	return result
}

// Reach computes all containers reachable from the given source via BFS.
// maxHops limits traversal depth (0 = unlimited).
func (a *Analyzer) Reach(sourceCgroupID uint64, maxHops int) *BlastRadius {
	a.graph.mu.RLock()
	defer a.graph.mu.RUnlock()

	result := &BlastRadius{
		Source: sourceCgroupID,
	}

	if _, ok := a.graph.nodes[sourceCgroupID]; !ok {
		return result
	}

	type bfsItem struct {
		cgroupID uint64
		hops     int
		path     []PathEdge
	}

	visited := make(map[uint64]bool)
	visited[sourceCgroupID] = true

	queue := []bfsItem{{cgroupID: sourceCgroupID, hops: 0}}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		if maxHops > 0 && item.hops >= maxHops {
			continue
		}

		for _, edge := range a.graph.edges {
			var neighbor uint64
			if edge.From == item.cgroupID {
				neighbor = edge.To
			} else if edge.To == item.cgroupID {
				neighbor = edge.From
			} else {
				continue
			}

			if visited[neighbor] {
				continue
			}
			visited[neighbor] = true

			newPath := make([]PathEdge, len(item.path)+1)
			copy(newPath, item.path)
			newPath[len(item.path)] = PathEdge{
				From:    item.cgroupID,
				To:      neighbor,
				Type:    edge.Type,
				Details: edge.Details,
			}

			node := a.graph.nodes[neighbor]
			reachable := ReachableNode{
				CgroupID: neighbor,
				Hops:     item.hops + 1,
				Path:     newPath,
			}
			if node != nil {
				reachable.Image = node.Image
				reachable.Name = node.Name
			}
			result.Reachable = append(result.Reachable, reachable)

			if result.TotalHops < item.hops+1 {
				result.TotalHops = item.hops + 1
			}

			queue = append(queue, bfsItem{
				cgroupID: neighbor,
				hops:     item.hops + 1,
				path:     newPath,
			})
		}
	}

	return result
}

// ReachDirected computes reachable containers following only outgoing edges (directed BFS).
func (a *Analyzer) ReachDirected(sourceCgroupID uint64, maxHops int) *BlastRadius {
	a.graph.mu.RLock()
	defer a.graph.mu.RUnlock()

	result := &BlastRadius{
		Source: sourceCgroupID,
	}

	if _, ok := a.graph.nodes[sourceCgroupID]; !ok {
		return result
	}

	type bfsItem struct {
		cgroupID uint64
		hops     int
		path     []PathEdge
	}

	visited := make(map[uint64]bool)
	visited[sourceCgroupID] = true

	queue := []bfsItem{{cgroupID: sourceCgroupID, hops: 0}}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		if maxHops > 0 && item.hops >= maxHops {
			continue
		}

		for _, edge := range a.graph.edges {
			if edge.From != item.cgroupID {
				continue
			}

			if visited[edge.To] {
				continue
			}
			visited[edge.To] = true

			newPath := make([]PathEdge, len(item.path)+1)
			copy(newPath, item.path)
			newPath[len(item.path)] = PathEdge{
				From:    item.cgroupID,
				To:      edge.To,
				Type:    edge.Type,
				Details: edge.Details,
			}

			node := a.graph.nodes[edge.To]
			reachable := ReachableNode{
				CgroupID: edge.To,
				Hops:     item.hops + 1,
				Path:     newPath,
			}
			if node != nil {
				reachable.Image = node.Image
				reachable.Name = node.Name
			}
			result.Reachable = append(result.Reachable, reachable)

			if result.TotalHops < item.hops+1 {
				result.TotalHops = item.hops + 1
			}

			queue = append(queue, bfsItem{
				cgroupID: edge.To,
				hops:     item.hops + 1,
				path:     newPath,
			})
		}
	}

	return result
}

// ImpactScore computes a simple risk score based on reachable containers.
func (a *Analyzer) ImpactScore(sourceCgroupID uint64) float64 {
	a.graph.mu.RLock()
	totalNodes := len(a.graph.nodes)
	a.graph.mu.RUnlock()

	if totalNodes <= 1 {
		return 0
	}

	reach := a.Reach(sourceCgroupID, 0)
	return float64(len(reach.Reachable)) / float64(totalNodes-1)
}

// MostConnected returns the cgroup ID of the most-connected container.
func (a *Analyzer) MostConnected() (uint64, int) {
	a.graph.mu.RLock()
	defer a.graph.mu.RUnlock()

	connections := make(map[uint64]int)
	for _, e := range a.graph.edges {
		connections[e.From]++
		connections[e.To]++
	}

	var maxID uint64
	maxCount := 0
	for id, count := range connections {
		if count > maxCount {
			maxCount = count
			maxID = id
		}
	}
	return maxID, maxCount
}
