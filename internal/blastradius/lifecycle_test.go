package blastradius

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestGraphLifecycleLimitsAndTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	g := NewGraphWithConfig(GraphConfig{TTL: time.Minute, MaxNodes: 3, MaxEdges: 2, Clock: func() time.Time { return now }})
	add := func(id uint64) { g.AddNode(&ContainerNode{CgroupID: id, LastSeen: now.Add(100 * time.Hour)}) }
	for id := uint64(1); id <= 3; id++ {
		add(id)
		now = now.Add(time.Second)
	}
	g.AddEdge(1, 2, EdgeNetwork, "first", now)
	now = now.Add(time.Second)
	g.AddEdge(2, 3, EdgeNetwork, "second", now)
	now = now.Add(time.Second)
	g.AddEdge(1, 3, EdgeSharedPID, "third", now)
	if g.EdgeCount() != 2 || len(g.EdgesFrom(1)) != 1 {
		t.Fatal("edge cap did not evict oldest relationship")
	}
	add(1)
	add(4)
	if g.GetNode(2) != nil || g.NodeCount() != 3 {
		t.Fatal("node cap did not evict oldest")
	}
	if len(g.EdgesFrom(2)) != 0 || len(g.EdgesTo(2)) != 0 {
		t.Fatal("eviction retained incident edges")
	}
	g.AddEdge(1, 99, EdgeNetwork, "unknown", now)
	if len(g.EdgesTo(99)) != 0 {
		t.Fatal("accepted edge to unobserved node")
	}
	now = now.Add(time.Minute)
	g.Prune()
	if g.NodeCount() != 0 || g.EdgeCount() != 0 || len(g.entries) != 0 || len(g.edgeSeen) != 0 || g.order.Len() != 0 {
		t.Fatal("TTL retained graph or index state")
	}
}

func TestEdgeExpiresWhileEndpointsActive(t *testing.T) {
	now := time.Unix(1000, 0)
	g := NewGraphWithConfig(GraphConfig{TTL: time.Minute, Clock: func() time.Time { return now }})
	refresh := func() {
		for id := uint64(1); id <= 2; id++ {
			g.AddNode(&ContainerNode{CgroupID: id})
		}
	}
	refresh()
	g.AddEdge(1, 2, EdgeNetwork, "stale", now)
	now = now.Add(59 * time.Second)
	refresh()
	now = now.Add(time.Second)
	g.Prune()
	if g.NodeCount() != 2 || g.EdgeCount() != 0 {
		t.Fatal("edge TTL did not expire independently of nodes")
	}
}

func TestGraphOwnedSnapshotsAndConcurrentAnalysis(t *testing.T) {
	g := NewGraphWithConfig(GraphConfig{MaxNodes: 32, MaxEdges: 32})
	input := &ContainerNode{CgroupID: 1, Labels: map[string]string{"app": "original"}}
	g.AddNode(input)
	input.Labels["app"] = "changed"
	if g.GetNode(1).Labels["app"] != "original" {
		t.Fatal("stored caller's mutable labels")
	}
	analyzer := NewAnalyzer(g)
	var wg sync.WaitGroup
	for worker := range 4 {
		wg.Go(func() {
			for n := range 1000 {
				id := uint64((n+worker)%100 + 1)
				g.AddNode(&ContainerNode{CgroupID: id, Labels: map[string]string{"app": "value"}})
				g.AddNode(&ContainerNode{CgroupID: id + 1})
				g.AddEdge(id, id+1, EdgeNetwork, "tcp", time.Now())
				for _, node := range g.Nodes() {
					node.Labels = map[string]string{"app": "mutated"}
					node.Name = "mutated"
				}
				for _, edge := range g.EdgesFrom(id) {
					edge.Details = "mutated"
				}
				for _, edge := range g.EdgesTo(id + 1) {
					edge.Count = -1
				}
				_, _ = json.Marshal(analyzer.Reach(id, 3))
				_ = analyzer.ReachDirected(id, 3)
				if n%11 == 0 {
					g.RemoveNode(id)
					g.Prune()
				}
			}
		})
	}
	wg.Wait()
	if g.NodeCount() > 32 || g.EdgeCount() > 32 || len(g.edgeSeen) > 32 || len(g.entries) > 32 {
		t.Fatal("churn exceeded budget")
	}
	for _, node := range g.Nodes() {
		if node.Name == "mutated" || node.Labels["app"] == "mutated" {
			t.Fatal("snapshot mutation escaped")
		}
	}
}
