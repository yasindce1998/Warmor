package enforcer

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/drift"
	"github.com/yasindce1998/warmor/internal/lineage"
)

func TestStateMaintenanceWithoutAttackGraph(t *testing.T) {
	for _, mode := range []string{"lineage", "drift", "both", "neither"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			e := &Enforcer{ctx: ctx} // No attack graph, pipeline, or heartbeat.
			var now, lineageCalls, driftCalls atomic.Int64
			now.Store(time.Unix(1200, 0).UnixNano())
			if mode == "lineage" || mode == "both" {
				e.lineageTracker = lineage.NewTracker(lineage.TrackerConfig{TTL: time.Minute, Clock: func() time.Time {
					lineageCalls.Add(1)
					return time.Unix(0, now.Load())
				}})
				e.lineageTracker.RecordExec(1, 0, 0, 0, "quiet", "quiet")
			}
			if mode == "drift" || mode == "both" {
				e.driftCollector = drift.NewFingerprintCollectorWithConfig(drift.CollectorConfig{TTL: time.Minute, Clock: func() time.Time {
					driftCalls.Add(1)
					return time.Unix(0, now.Load())
				}})
				e.driftCollector.Record(driftCollectorKey, "", "exec:quiet")
			}
			lineageBefore, driftBefore := lineageCalls.Load(), driftCalls.Load()
			now.Add(int64(time.Minute))
			ticks := make(chan time.Time)
			done := make(chan struct{})
			go func() { defer close(done); e.stateMaintenanceLoop(ticks) }()
			t.Cleanup(func() { cancel(); <-done })
			// The second unbuffered send is a barrier: the first tick's prune
			// calls must finish before the loop can receive the second tick.
			for range 2 {
				select {
				case ticks <- time.Time{}:
				case <-time.After(time.Second):
					t.Fatal("maintenance did not consume injected tick")
				}
			}
			// Check clock calls BEFORE using getters that lazily prune. This
			// proves periodic cleanup ran, not just cleanup during assertions.
			if e.lineageTracker != nil {
				if lineageCalls.Load() <= lineageBefore {
					t.Fatal("tick did not prune lineage")
				}
				if e.lineageTracker.Size() != 0 {
					t.Fatal("expired lineage retained")
				}
			}
			if e.driftCollector != nil {
				if driftCalls.Load() <= driftBefore {
					t.Fatal("tick did not prune drift collector")
				}
				if e.driftCollector.Snapshot(driftCollectorKey) != nil {
					t.Fatal("expired drift agent retained")
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("maintenance did not stop on cancellation")
			}
		})
	}
}

func TestStateMaintenanceOwnedLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	e := &Enforcer{ctx: ctx, lineageTracker: lineage.NewTracker(lineage.TrackerConfig{})}
	e.startStateMaintenance()
	cancel()
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("maintenance goroutine not joined on shutdown")
	}
	// A closed injected source terminates rather than spinning.
	ticks := make(chan time.Time)
	close(ticks)
	e.ctx = context.Background()
	e.stateMaintenanceLoop(ticks)
}
