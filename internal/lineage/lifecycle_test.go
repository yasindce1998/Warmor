package lineage

import (
	"sync"
	"testing"
	"time"
)

func TestTrackerTTLAndPIDReuse(t *testing.T) {
	now := time.Unix(1200, 0)
	tr := NewTracker(TrackerConfig{TTL: time.Minute, MaxSize: 3, Clock: func() time.Time { return now }})
	tr.RecordExec(1, 0, 0, 0, "parent", "parent")
	now = now.Add(time.Second)
	tr.RecordExec(2, 1, 0, 0, "child", "child")
	if len(tr.GetAncestors(2)) != 1 {
		t.Fatal("missing observed parent")
	}
	tr.RecordExit(1)
	now = now.Add(time.Second)
	tr.RecordExec(1, 0, 0, 0, "reused", "reused")
	if len(tr.GetAncestors(2)) != 0 {
		t.Fatal("attributed child to reused parent PID")
	}
	now = now.Add(time.Minute)
	if tr.Prune() != 2 || tr.Size() != 0 || len(tr.elems) != 0 || tr.order.Len() != 0 {
		t.Fatal("TTL retained process/index state")
	}
	tr.RecordExec(3, 0, 0, 0, "quiet", "quiet")
	now = now.Add(time.Minute)
	if _, ok := tr.GetProcess(3); ok {
		t.Fatal("lookup exposed expired process without explicit prune")
	}
}

func TestConcurrentTrackerLifecycleChurn(t *testing.T) {
	tr := NewTracker(TrackerConfig{MaxSize: 32})
	var wg sync.WaitGroup
	for worker := range 4 {
		wg.Go(func() {
			for n := range 5000 {
				pid := uint32((n+worker)%100 + 1)
				tr.RecordExec(pid, pid-1, 0, 0, "process", "process")
				tr.GetAncestors(pid)
				tr.GetProcess(pid)
				if n%11 == 0 {
					tr.RecordExit(pid)
					tr.Prune()
				}
			}
		})
	}
	wg.Wait()
	if tr.Size() > 32 || len(tr.elems) > 32 || tr.order.Len() > 32 {
		t.Fatal("tracker churn exceeded budget")
	}
}
