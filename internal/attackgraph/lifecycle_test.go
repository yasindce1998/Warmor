package attackgraph

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
)

func TestGraphLifecycle(t *testing.T) {
	now := time.Unix(1000, 0)
	g := NewGraphWithConfig(nil, GraphConfig{TTL: time.Minute, MaxContainers: 3, Clock: func() time.Time { return now }})
	ingest := func(id uint64) {
		g.Ingest(&streaming.SecurityEvent{CgroupID: id, EventType: "exec", Comm: "bash", Timestamp: now.Add(100 * time.Hour)})
	}
	for id := uint64(1); id <= 3; id++ {
		ingest(id)
		now = now.Add(time.Second)
	}
	ingest(1)
	ingest(4)
	if g.GetContainer(2) != nil || len(g.Containers()) != 3 {
		t.Fatal("limit did not evict least recently observed cgroup")
	}
	now = now.Add(time.Minute)
	if removed := g.Prune(); removed != 3 {
		t.Fatalf("expired %d, want 3 despite future event timestamps", removed)
	}
	if g.Summary().ContainerCount != 0 || len(g.entries) != 0 || g.order.Len() != 0 {
		t.Fatal("retained expired graph/index state")
	}
	ingest(1)
	if g.GetContainer(1).Nodes["T1059.004"].Count != 1 {
		t.Fatal("cgroup reuse inherited old state")
	}
	g.Remove(1)
	if g.order.Len() != 0 || len(g.entries) != 0 {
		t.Fatal("Remove leaked retention index")
	}
}

func TestGraphSnapshotsConcurrentWithChurn(t *testing.T) {
	g := NewGraphWithConfig(nil, GraphConfig{MaxContainers: 32})
	var wg sync.WaitGroup
	for worker := range 4 {
		wg.Go(func() {
			for n := range 2000 {
				id := uint64((n+worker)%100 + 1)
				g.Ingest(&streaming.SecurityEvent{CgroupID: id, EventType: "exec", Comm: "bash"})
				g.Ingest(&streaming.SecurityEvent{CgroupID: id, EventType: "exec", Comm: "ps"})
				if snapshot := g.GetContainer(id); snapshot != nil {
					_, _ = json.Marshal(snapshot)
					for _, node := range snapshot.Nodes {
						node.Count = -1
					}
					for _, edge := range snapshot.Edges {
						edge.Weight = -1
					}
					clear(snapshot.Nodes)
				}
				_ = g.Summary()
				if n%11 == 0 {
					g.Remove(id)
					g.Prune()
				}
			}
		})
	}
	wg.Wait()
	if len(g.Containers()) > 32 || len(g.entries) > 32 || g.order.Len() > 32 {
		t.Fatal("churn exceeded graph budget")
	}
	for _, id := range g.Containers() {
		for _, node := range g.GetContainer(id).Nodes {
			if node.Count <= 0 {
				t.Fatal("snapshot mutated graph")
			}
		}
	}
}
