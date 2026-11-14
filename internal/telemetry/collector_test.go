package telemetry

import (
	"math"
	"strings"
	"sync"
	"testing"
)

func TestCollectorActivationAndSessionFences(t *testing.T) {
	c := &Collector{}
	if c.Snapshot() != nil {
		t.Fatal("missing epoch produced evidence")
	}
	if c.SetSession(Session{SessionID: "missing-epoch"}) == nil {
		t.Fatal("accepted missing epoch")
	}
	session := Session{Epoch: "epoch", SessionID: "session"}
	if err := c.SetSession(session); err != nil {
		t.Fatal(err)
	}
	a := Assignment{Session: session, AssignmentRevision: 1}
	r := Revision{PolicyID: "policy", PolicyVersion: 1, PolicyHash: strings.Repeat("a", 64)}
	s, err := c.Prepare(a, r)
	if err != nil {
		t.Fatal(err)
	}
	c.Replace(s)
	first := c.Snapshot()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.Record(true, false, false)
			}
		}()
	}
	wg.Wait()
	c.Record(false, true, false)
	c.Record(false, false, true)
	c.RecordLoss(3)
	second := c.Snapshot()
	if first.Sequence != 1 || second.Sequence != 2 || second.Total != 2000 || second.Denied != 2000 || second.Errors != 1 || second.Excluded != 1 || second.Lost != 3 {
		t.Fatalf("torn/wrong counters: %+v", second)
	}
	if err := c.SetSession(session); err != nil {
		t.Fatal(err)
	}
	if c.Snapshot().Sequence != 3 {
		t.Fatal("same lease reset sequence")
	}
	a.AssignmentRevision++
	s2, err := c.Prepare(a, r)
	if err != nil {
		t.Fatal(err)
	}
	c.Replace(s2)
	third := c.Snapshot()
	if third.Sequence != 4 || third.Total != 0 || third.Revision.ActivationID == first.Revision.ActivationID {
		t.Fatalf("activation reset failed: %+v", third)
	}
	c.Seal()
	c.Record(true, false, false)
	if c.Snapshot() != nil {
		t.Fatal("sealed collector leaked evidence")
	}
	if err := c.SetSession(Session{Epoch: "next", SessionID: "next"}); err != nil {
		t.Fatal(err)
	}
	c.Replace(s2)
	if c.Snapshot() != nil {
		t.Fatal("revoked session activation accepted")
	}
}

func TestCollectorOverflowNeverWraps(t *testing.T) {
	c := &Collector{session: Session{Epoch: "e", SessionID: "s"}, active: &Snapshot{Total: math.MaxUint64, Denied: math.MaxUint64}}
	c.Record(true, false, false)
	if !c.active.Overflow || c.active.Total != math.MaxUint64 {
		t.Fatal("counter wrapped")
	}
	c.sequence = math.MaxUint64
	if c.Snapshot() != nil {
		t.Fatal("sequence wrapped")
	}
}
