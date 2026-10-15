package enforcer

import (
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

// fakeStarts is a containerStarter over a fixed table.
type fakeStarts struct {
	starts map[uint64]time.Time
	calls  int
}

func (f *fakeStarts) ContainerStart(id uint64) (time.Time, bool) {
	f.calls++
	s, ok := f.starts[id]
	return s, ok
}

// TestHandleEvent_TemporalPolicy runs a temporal (ABI v3) policy that allows
// only events whose container age is known. Process decisions read the age;
// file decisions are declared not to.
func TestHandleEvent_TemporalPolicy(t *testing.T) {
	masks := &[3]uint32{compiler.FieldBitPath | compiler.FieldBitContainerAge, compiler.FieldBitPath, compiler.FieldBitRemoteAddr}
	pm := &fakePolicyMap{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyMap: pm, policyWasm: wasmtest.AgeKnownPolicy(masks)})
	setCacheDependencies(e.cache, e.evaluator)
	now := time.Now()
	starts := &fakeStarts{starts: map[uint64]time.Time{7: now.Add(-time.Minute)}}
	e.containerStarts = starts

	exec := func(cgroup uint64) *api.Event {
		return &api.Event{PID: 0, UID: 1000, Comm: "x", Filename: "/bin/x", CgroupID: cgroup, Timestamp: now}
	}

	known := exec(7)
	e.handleEvent(known)
	e.handleEvent(exec(7))
	if known.ContainerStart.IsZero() {
		t.Error("container start not filled in for a policy that reads container age")
	}
	e.handleEvent(exec(8)) // container start unknown: the policy denies

	stats := e.GetStats()
	if stats.Allowed != 2 || stats.Denied != 1 {
		t.Fatalf("stats = %+v, want 2 allowed (known age) and 1 denied (unknown age)", stats)
	}
	if stats.CacheHits != 0 || e.cache.Stats().Size != 0 {
		t.Errorf("time-dependent decisions were cached: hits=%d size=%d", stats.CacheHits, e.cache.Stats().Size)
	}
	// path is the kernel key, but the decision also depends on the age.
	if rules := pm.snapshot(); len(rules) != 0 {
		t.Fatalf("time-dependent decision synced to the kernel: %+v", rules)
	}

	// File decisions are declared time independent: cached as usual, and
	// the container is never looked up for them.
	calls := starts.calls
	file := func() *api.Event {
		return &api.Event{PID: 0, CgroupID: 7, Timestamp: now, File: &api.FileEvent{
			BaseEvent: api.BaseEvent{Type: api.EventTypeFile}, Path: "/etc/x", Operation: "open"}}
	}
	e.handleEvent(file())
	e.handleEvent(file())
	if e.GetStats().CacheHits != 1 {
		t.Errorf("time-independent file decision not cached: hits=%d", e.GetStats().CacheHits)
	}
	if starts.calls != calls {
		t.Errorf("container start looked up %d times for a policy that does not read the age", starts.calls-calls)
	}
}

// TestHandleEvent_PreTemporalPolicyStillCached: a policy that does not
// declare ABI v3 is never sent time, so even undeclared its decisions are
// cached as before and no container lookups happen.
func TestHandleEvent_PreTemporalPolicyStillCached(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	setCacheDependencies(e.cache, e.evaluator)
	starts := &fakeStarts{}
	e.containerStarts = starts
	ev := func() *api.Event { return &api.Event{PID: 0, UID: 1000, Filename: "/usr/bin/ls", CgroupID: 7} }
	e.handleEvent(ev())
	e.handleEvent(ev())
	if hits := e.GetStats().CacheHits; hits != 1 {
		t.Errorf("CacheHits = %d, want 1", hits)
	}
	if starts.calls != 0 {
		t.Errorf("container start looked up %d times", starts.calls)
	}
}
