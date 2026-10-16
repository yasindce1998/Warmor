package lineage

import (
	"testing"
	"time"
)

func TestTrackerLineage(t *testing.T) {
	tr := NewTracker(TrackerConfig{})

	// Build a chain: init(1) -> bash(100) -> python(200) -> child(300)
	tr.RecordExec(1, 0, 0, 0, "init", "/sbin/init")
	tr.RecordExec(100, 1, 1000, 1000, "bash", "/bin/bash")
	tr.RecordExec(200, 100, 1000, 1000, "python", "/usr/bin/python3")
	tr.RecordExec(300, 200, 1000, 1000, "child", "/tmp/exploit")

	ancestors := tr.GetAncestors(300)
	if len(ancestors) != 3 {
		t.Fatalf("expected 3 ancestors, got %d", len(ancestors))
	}
	if ancestors[0].Comm != "python" {
		t.Errorf("expected first ancestor=python, got %s", ancestors[0].Comm)
	}
	if ancestors[1].Comm != "bash" {
		t.Errorf("expected second ancestor=bash, got %s", ancestors[1].Comm)
	}
	if ancestors[2].Comm != "init" {
		t.Errorf("expected third ancestor=init, got %s", ancestors[2].Comm)
	}
}

func TestHasAncestor(t *testing.T) {
	tr := NewTracker(TrackerConfig{})
	tr.RecordExec(1, 0, 0, 0, "init", "/sbin/init")
	tr.RecordExec(50, 1, 0, 0, "nginx", "/usr/sbin/nginx")
	tr.RecordExec(60, 50, 0, 0, "sh", "/bin/sh")
	tr.RecordExec(70, 60, 0, 0, "curl", "/usr/bin/curl")

	if !tr.HasAncestor(70, "nginx") {
		t.Error("expected curl(70) to have ancestor nginx")
	}
	if tr.HasAncestor(70, "sshd") {
		t.Error("expected curl(70) to NOT have ancestor sshd")
	}
}

func TestTrackerExit(t *testing.T) {
	tr := NewTracker(TrackerConfig{})
	tr.RecordExec(100, 1, 0, 0, "bash", "/bin/bash")

	if tr.Size() != 1 {
		t.Fatalf("expected size=1, got %d", tr.Size())
	}

	tr.RecordExit(100)
	if tr.Size() != 0 {
		t.Fatalf("expected size=0, got %d", tr.Size())
	}
}

func TestTrackerEviction(t *testing.T) {
	tr := NewTracker(TrackerConfig{MaxSize: 3})
	tr.RecordExec(1, 0, 0, 0, "a", "a")
	time.Sleep(time.Millisecond)
	tr.RecordExec(2, 1, 0, 0, "b", "b")
	time.Sleep(time.Millisecond)
	tr.RecordExec(3, 2, 0, 0, "c", "c")
	time.Sleep(time.Millisecond)
	tr.RecordExec(4, 3, 0, 0, "d", "d") // should evict oldest (PID 1)

	if tr.Size() != 3 {
		t.Fatalf("expected size=3, got %d", tr.Size())
	}
	if _, ok := tr.GetProcess(1); ok {
		t.Error("expected PID 1 to be evicted")
	}
	// Most recent should remain
	if _, ok := tr.GetProcess(4); !ok {
		t.Error("expected PID 4 to remain")
	}
}

func TestCycleDetection(t *testing.T) {
	tr := NewTracker(TrackerConfig{})
	// Create a cycle: 1->2->3->1
	tr.RecordExec(1, 3, 0, 0, "a", "a")
	tr.RecordExec(2, 1, 0, 0, "b", "b")
	tr.RecordExec(3, 2, 0, 0, "c", "c")

	// Should not infinite loop
	ancestors := tr.GetAncestors(3)
	if len(ancestors) > 3 {
		t.Errorf("cycle detection failed, got %d ancestors", len(ancestors))
	}
}

func TestTrackerEviction_ReExecIsNewest(t *testing.T) {
	tr := NewTracker(TrackerConfig{MaxSize: 3})
	tr.RecordExec(1, 0, 0, 0, "a", "a")
	tr.RecordExec(2, 0, 0, 0, "b", "b")
	tr.RecordExec(3, 0, 0, 0, "c", "c")
	tr.RecordExec(1, 0, 0, 0, "a2", "a2") // re-exec: no eviction, now newest
	if tr.Size() != 3 {
		t.Fatalf("size = %d after re-exec, want 3", tr.Size())
	}
	tr.RecordExec(4, 0, 0, 0, "d", "d") // evicts 2, the oldest
	if _, ok := tr.GetProcess(2); ok {
		t.Error("expected PID 2 to be evicted")
	}
	for _, pid := range []uint32{1, 3, 4} {
		if _, ok := tr.GetProcess(pid); !ok {
			t.Errorf("expected PID %d to remain", pid)
		}
	}
	tr.RecordExit(3)
	tr.RecordExec(5, 0, 0, 0, "e", "e") // room after exit: no eviction
	if _, ok := tr.GetProcess(1); !ok || tr.Size() != 3 {
		t.Errorf("size = %d, PID 1 present = %v; want 3, true", tr.Size(), ok)
	}
}
