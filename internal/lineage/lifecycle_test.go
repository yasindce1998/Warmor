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

func TestParentReexecPreservesAncestryAndRefreshesRetention(t *testing.T) {
	now := time.Unix(1200, 0)
	tr := NewTracker(TrackerConfig{TTL: time.Minute, Clock: func() time.Time { return now }})
	tr.RecordExec(10, 0, 0, 0, "parent", "/bin/parent")
	first := now
	now = now.Add(time.Second)
	tr.RecordExec(20, 10, 0, 0, "child", "/bin/child")
	if got := len(tr.GetAncestors(20)); got != 1 {
		t.Fatalf("initial ancestor count %d", got)
	}
	now = now.Add(30 * time.Second)
	tr.RecordExec(10, 0, 0, 0, "parent-reexec", "/bin/reexec")
	chain := tr.GetAncestors(20)
	if len(chain) != 1 || chain[0].PID != 10 || chain[0].Comm != "parent-reexec" {
		t.Fatalf("parent re-exec lost ancestry: %+v", chain)
	}
	if !chain[0].StartTime.Equal(first) || !chain[0].LastExec.Equal(now) {
		t.Fatalf("first observation and retention timestamps conflated: %+v", chain[0])
	}
	now = first.Add(time.Minute)
	tr.Prune()
	if _, ok := tr.GetProcess(10); !ok {
		t.Fatal("retention used first observation instead of latest exec")
	}
	now = first.Add(91 * time.Second)
	tr.Prune()
	if _, ok := tr.GetProcess(10); ok {
		t.Fatal("latest-exec TTL did not expire")
	}
}

func TestLateParentObservationDoesNotProvePIDReuse(t *testing.T) {
	now := time.Unix(1200, 0)
	tr := NewTracker(TrackerConfig{Clock: func() time.Time { return now }})
	tr.RecordExec(20, 10, 0, 0, "child", "child")
	now = now.Add(time.Second)
	tr.RecordExec(10, 0, 0, 0, "parent", "parent")
	if got := len(tr.GetAncestors(20)); got != 1 {
		t.Fatalf("late parent observation rejected without reuse provenance: %d", got)
	}
}

func TestObservedParentRemovalInvalidatesBindingAtSameTimestamp(t *testing.T) {
	now := time.Unix(1200, 0)
	tr := NewTracker(TrackerConfig{Clock: func() time.Time { return now }})
	tr.RecordExec(10, 0, 0, 0, "parent", "parent")
	tr.RecordExec(20, 10, 0, 0, "child", "child")
	tr.RecordExit(10)
	tr.RecordExec(10, 0, 0, 0, "new-process", "new-process")
	if chain := tr.GetAncestors(20); len(chain) != 0 {
		t.Fatalf("child attributed to a removed/reinserted PID at equal clock time: %+v", chain)
	}
}
