package cache

import (
	"bytes"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

// fakeClock lets tests control expiry without sleeping.
type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time          { return f.t }
func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

func newTestCache(size int, ttl time.Duration) (*DecisionCache, *fakeClock) {
	c := NewDecisionCache(size, ttl)
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	c.now = clk.now
	return c, clk
}

func exec(path string, uid uint32) *api.Event {
	return &api.Event{UID: uid, Filename: path}
}

var allow = &api.ActionResult{Action: api.ActionAllow, Reason: "test"}

func TestNewDecisionCache(t *testing.T) {
	c := NewDecisionCache(500, 10*time.Minute)
	if c.maxSize != 500 || c.ttl != 10*time.Minute {
		t.Fatalf("maxSize=%d ttl=%v", c.maxSize, c.ttl)
	}
	if s := c.Stats(); s.Size != 0 || s.MaxSize != 500 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestDecisionCache_GetPut(t *testing.T) {
	c, _ := newTestCache(10, time.Minute)
	ev := &api.Event{PID: 1234, UID: 1000, Comm: "bash", Filename: "/bin/bash"}
	res := &api.ActionResult{Action: api.ActionDeny, Reason: "r", Latency: time.Millisecond}

	if _, ok := c.Get(ev); ok {
		t.Fatal("hit on empty cache")
	}
	c.Put(ev, res)
	got, ok := c.Get(ev)
	if !ok || got.Action != api.ActionDeny || got.Reason != "r" || !got.Cached {
		t.Fatalf("Get = %+v, %v", got, ok)
	}
	if res.Cached {
		t.Error("Put must not alias the caller's result")
	}
	got.Reason = "mutated"
	if again, _ := c.Get(ev); again.Reason != "r" {
		t.Error("Get must return a copy")
	}
}

func TestDecisionCache_PutOverwrites(t *testing.T) {
	c, _ := newTestCache(10, time.Minute)
	ev := exec("/bin/x", 1)
	c.Put(ev, allow)
	c.Put(ev, &api.ActionResult{Action: api.ActionDeny})
	if got, _ := c.Get(ev); got.Action != api.ActionDeny {
		t.Fatalf("Action = %v, want overwritten deny", got.Action)
	}
	if c.Stats().Size != 1 {
		t.Fatalf("size = %d, want 1", c.Stats().Size)
	}
}

func TestDecisionCache_Expiration(t *testing.T) {
	c, clk := newTestCache(10, 100*time.Millisecond)
	ev := exec("/bin/expire", 1000)
	c.Put(ev, allow)
	clk.advance(99 * time.Millisecond)
	if _, ok := c.Get(ev); !ok {
		t.Fatal("entry expired early")
	}
	clk.advance(time.Millisecond)
	if _, ok := c.Get(ev); ok {
		t.Fatal("expired entry returned")
	}
	if c.Stats().Size != 0 {
		t.Error("expired entry not removed on Get")
	}
}

func TestDecisionCache_EvictsLeastRecentlyUsed(t *testing.T) {
	c, _ := newTestCache(3, time.Minute)
	a, b, d := exec("/bin/a", 1), exec("/bin/b", 1), exec("/bin/d", 1)
	c.Put(a, allow)
	c.Put(b, allow)
	c.Put(d, allow)

	// Reading a makes b the least recently used, even though a is oldest.
	if _, ok := c.Get(a); !ok {
		t.Fatal("a missing")
	}
	c.Put(exec("/bin/e", 1), allow)

	if _, ok := c.Get(a); !ok {
		t.Error("recently read entry was evicted: Get must refresh recency")
	}
	if _, ok := c.Get(b); ok {
		t.Error("least recently used entry survived eviction")
	}
	if s := c.Stats(); s.Size != 3 || s.Evictions != 1 {
		t.Errorf("stats = %+v, want size 3, 1 eviction", s)
	}
}

func TestDecisionCache_ZeroCapacityDisables(t *testing.T) {
	c, _ := newTestCache(0, time.Minute)
	c.Put(exec("/bin/a", 1), allow)
	if _, ok := c.Get(exec("/bin/a", 1)); ok || c.Stats().Size != 0 {
		t.Fatal("zero-capacity cache stored an entry")
	}
}

func TestDecisionCache_Clear(t *testing.T) {
	c, _ := newTestCache(10, time.Minute)
	for i := 0; i < 3; i++ {
		c.Put(exec(fmt.Sprintf("/bin/t%d", i), 1), allow)
	}
	c.Clear()
	if c.Stats().Size != 0 {
		t.Fatal("Clear left entries")
	}
	if _, ok := c.Get(exec("/bin/t0", 1)); ok {
		t.Fatal("hit after Clear")
	}
	// Still usable after Clear.
	c.Put(exec("/bin/t0", 1), allow)
	if _, ok := c.Get(exec("/bin/t0", 1)); !ok {
		t.Fatal("cache unusable after Clear")
	}
}

func TestDecisionCache_Stats(t *testing.T) {
	c, _ := newTestCache(10, time.Minute)
	ev := exec("/bin/test", 1000)
	c.Get(ev)
	c.Put(ev, allow)
	c.Get(ev)
	c.Get(ev)
	c.Get(ev)
	s := c.Stats()
	if s.Size != 1 || s.TotalHits != 3 || s.Misses != 1 {
		t.Fatalf("stats = %+v, want size 1, 3 hits, 1 miss", s)
	}
}

func TestDecisionCache_PIDIncludedByDefault(t *testing.T) {
	c, _ := newTestCache(10, time.Minute)
	c.Put(&api.Event{PID: 1, Filename: "/bin/x"}, allow)
	if _, ok := c.Get(&api.Event{PID: 2, Filename: "/bin/x"}); ok {
		t.Fatal("without a declaration the PID must be part of the key")
	}
}

func TestDecisionCache_PIDDroppedWhenPolicyIgnoresIt(t *testing.T) {
	c, _ := newTestCache(10, time.Minute)
	c.Put(&api.Event{PID: 1, Filename: "/bin/x"}, allow) // cleared below
	c.SetPIDRelevant(func(t api.EventType) bool { return t != api.EventTypeProcess })
	if c.Stats().Size != 0 {
		t.Fatal("SetPIDRelevant must clear entries keyed under the old rule")
	}

	c.Put(&api.Event{PID: 1, Filename: "/bin/x"}, allow)
	if _, ok := c.Get(&api.Event{PID: 2, Filename: "/bin/x"}); !ok {
		t.Error("new process missed although the policy does not read the PID")
	}
	// Network decisions still depend on the PID.
	net := func(pid uint32) *api.Event {
		return &api.Event{PID: pid, Network: &api.NetworkEvent{BaseEvent: api.BaseEvent{Type: api.EventTypeNetwork}, RemoteAddr: "1.1.1.1"}}
	}
	c.Put(net(1), allow)
	if _, ok := c.Get(net(2)); ok {
		t.Error("PID dropped for an event type whose policy reads it")
	}
}

// fullEvent returns an event with every exported field set to a non-zero
// value, typed as typ (or untyped if typ < 0).
func fullEvent(typ api.EventType) *api.Event {
	ev := &api.Event{
		PID: 10, UID: 11, GID: 12, Comm: "comm", Filename: "/file/name",
		Timestamp: time.Unix(1, 0), CgroupID: 13, LSMEvent: true,
		ContainerStart: time.Unix(0, 500*int64(time.Millisecond)),
		Process: &api.ProcessEvent{
			BaseEvent: api.BaseEvent{Type: api.EventTypeProcess, PID: 20, UID: 21, GID: 22, Comm: "pcomm", CgroupID: 23},
			Filename:  "/proc/file", Args: []string{"a", "b"},
		},
		File: &api.FileEvent{
			BaseEvent: api.BaseEvent{Type: api.EventTypeFile, PID: 30},
			Operation: "write", Path: "/etc/x", Flags: 31, Mode: 32,
		},
		Network: &api.NetworkEvent{
			BaseEvent: api.BaseEvent{Type: api.EventTypeNetwork, PID: 40},
			Operation: "connect", Protocol: "tcp", RemoteAddr: "10.0.0.1", RemotePort: 41,
			LocalAddr: "10.0.0.2", LocalPort: 42, DataSize: 43,
		},
	}
	if typ >= 0 {
		ev.SetType(typ)
	}
	return ev
}

// forEachMutation calls visit with a fresh event in which exactly one leaf
// field (found by reflection, so new api fields are covered automatically)
// was changed, or one sub-event pointer was set to nil.
func forEachMutation(t *testing.T, mk func() *api.Event, visit func(desc string, ev *api.Event)) {
	t.Helper()
	timeType := reflect.TypeOf(time.Time{})
	// count leaves first using a dry walk
	var walk func(v reflect.Value, path string, target int, n *int, ev *api.Event) bool
	walk = func(v reflect.Value, path string, target int, n *int, ev *api.Event) bool {
		switch v.Kind() {
		case reflect.Ptr:
			if v.IsNil() {
				return false
			}
			if *n == target {
				v.Set(reflect.Zero(v.Type()))
				visit(path+"=nil", ev)
				return true
			}
			*n++
			return walk(v.Elem(), path, target, n, ev)
		case reflect.Struct:
			if v.Type() == timeType {
				// A leaf: shift it by a day and a minute, which changes
				// the Unix seconds, minute of day and weekday alike.
				if *n != target {
					*n++
					return false
				}
				tv, _ := v.Interface().(time.Time)
				v.Set(reflect.ValueOf(tv.Add(25*time.Hour + time.Minute)))
				visit(path, ev)
				return true
			}
			for i := 0; i < v.NumField(); i++ {
				f := v.Field(i)
				if !f.CanSet() {
					continue
				}
				if walk(f, path+"."+v.Type().Field(i).Name, target, n, ev) {
					return true
				}
			}
			return false
		}
		if *n != target {
			*n++
			return false
		}
		switch v.Kind() {
		case reflect.String:
			v.SetString(v.String() + "x")
		case reflect.Bool:
			v.SetBool(!v.Bool())
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			v.SetInt(v.Int() + 1)
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			v.SetUint(v.Uint() + 1)
		case reflect.Slice:
			v.Set(reflect.Append(v, reflect.ValueOf("extra")))
		default:
			t.Fatalf("%s: unhandled kind %v; extend forEachMutation", path, v.Kind())
		}
		visit(path, ev)
		return true
	}
	for target := 0; ; target++ {
		ev := mk()
		n := 0
		if !walk(reflect.ValueOf(ev).Elem(), "Event", target, &n, ev) {
			if target < 20 {
				t.Fatalf("only %d mutations found; reflection walk broken", target)
			}
			return
		}
	}
}

func inputsEqual(a, b *api.Event, temporal bool) bool {
	ia, ib := wasm.PolicyInputs(a, temporal), wasm.PolicyInputs(b, temporal)
	for i := range ia {
		if !bytes.Equal(ia[i], ib[i]) {
			return false
		}
	}
	return true
}

// TestKey_CoversEveryPolicyInput: whenever a change to an event is visible
// to a policy module (through the binary ABI, the JSON ABI or the host
// callbacks), the cache key must change too, or the cached decision of one
// event would be reused for an event the policy may decide differently.
//
// The one exception is the temporal context of ABI >= 3 modules (wall
// clock, container age), which is not in the key: decisions that may
// depend on it are never cached (TestDecisionCache_TimeDependentNeverCached).
// The test pins down exactly which event fields feed it, so a new input
// cannot slip into that exception unnoticed.
func TestKey_CoversEveryPolicyInput(t *testing.T) {
	for _, temporal := range []bool{false, true} {
		temporalOnly := map[string]bool{}
		for _, typ := range []api.EventType{-1, api.EventTypeProcess, api.EventTypeFile, api.EventTypeNetwork} {
			mk := func() *api.Event { return fullEvent(typ) }
			for _, pidRelevant := range []bool{true, false} {
				c := NewDecisionCache(1, time.Minute)
				if !pidRelevant {
					c.SetPIDRelevant(func(api.EventType) bool { return false })
				}
				base := mk()
				baseKey := c.makeKey(base)
				forEachMutation(t, mk, func(desc string, ev *api.Event) {
					if inputsEqual(base, ev, temporal) {
						return
					}
					if !pidRelevant && desc == "Event.PID" {
						// Allowed to collide: the policy declared it ignores the PID.
						return
					}
					if c.makeKey(ev) != baseKey {
						return
					}
					if temporal && inputsEqual(base, ev, false) {
						// Only the temporal context differs.
						temporalOnly[desc] = true
						return
					}
					t.Errorf("type %v, pidRelevant=%v, temporal=%v: mutating %s changes what the policy sees but not the cache key",
						typ, pidRelevant, temporal, desc)
				})
			}
		}
		want := map[string]bool{}
		if temporal {
			want = map[string]bool{"Event.Timestamp": true, "Event.ContainerStart": true}
		}
		if !reflect.DeepEqual(temporalOnly, want) {
			t.Errorf("temporal=%v: fields feeding only the temporal context = %v, want %v", temporal, temporalOnly, want)
		}
	}
}

func TestDecisionCache_TimeDependentNeverCached(t *testing.T) {
	c, _ := newTestCache(10, time.Minute)
	c.Put(exec("/bin/x", 0), allow) // cleared below
	c.SetTimeDependent(func(t api.EventType) bool { return t == api.EventTypeProcess })
	if c.Stats().Size != 0 {
		t.Fatal("SetTimeDependent must clear the cache")
	}

	ev := exec("/bin/x", 0)
	c.Put(ev, allow)
	if _, ok := c.Get(ev); ok {
		t.Fatal("time-dependent decision served from the cache")
	}
	if s := c.Stats(); s.Size != 0 || s.Misses != 1 {
		t.Fatalf("stats = %+v, want nothing stored and one miss", s)
	}

	// Other event types are still cached.
	file := &api.Event{File: &api.FileEvent{BaseEvent: api.BaseEvent{Type: api.EventTypeFile}, Path: "/etc/x"}}
	c.Put(file, allow)
	if _, ok := c.Get(file); !ok {
		t.Error("time-independent event type not cached")
	}

	c.SetTimeDependent(nil)
	c.Put(ev, allow)
	if _, ok := c.Get(ev); !ok {
		t.Error("nil SetTimeDependent must cache every type")
	}
}

func TestKey_ArgsUnambiguous(t *testing.T) {
	c := NewDecisionCache(1, time.Minute)
	a := &api.Event{Process: &api.ProcessEvent{Args: []string{"ab", "c"}}}
	b := &api.Event{Process: &api.ProcessEvent{Args: []string{"a", "bc"}}}
	if c.makeKey(a) == c.makeKey(b) {
		t.Fatal("different argument vectors share a key")
	}
}

func TestDecisionCache_ConcurrentAccess(t *testing.T) {
	c := NewDecisionCache(100, time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			c.Put(exec(fmt.Sprintf("/bin/t%d", n), uint32(n)), allow)
		}(i)
		go func(n int) {
			defer wg.Done()
			c.Get(exec(fmt.Sprintf("/bin/t%d", n), uint32(n)))
			c.Stats()
		}(i)
	}
	wg.Wait()
	if c.Stats().Size == 0 {
		t.Error("no entries after concurrent puts")
	}
}

func benchEvents(n int) []*api.Event {
	evs := make([]*api.Event, n)
	for i := range evs {
		evs[i] = &api.Event{
			PID: uint32(i), UID: uint32(i % 7), Comm: "bench",
			Process: &api.ProcessEvent{Filename: fmt.Sprintf("/usr/bin/tool%d", i)},
		}
	}
	return evs
}

func BenchmarkDecisionCache_Put(b *testing.B) {
	c := NewDecisionCache(10000, 5*time.Minute)
	evs := benchEvents(20000) // twice the capacity: every Put past 10k evicts
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Put(evs[i%len(evs)], allow)
	}
}

func BenchmarkDecisionCache_Get(b *testing.B) {
	c := NewDecisionCache(10000, 5*time.Minute)
	evs := benchEvents(10000)
	for _, ev := range evs {
		c.Put(ev, allow)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := c.Get(evs[i%len(evs)]); !ok {
			b.Fatal("miss")
		}
	}
}

func BenchmarkDecisionCache_GetMiss(b *testing.B) {
	c := NewDecisionCache(10000, 5*time.Minute)
	evs := benchEvents(1000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Get(evs[i%len(evs)])
	}
}

func BenchmarkDecisionCache_GetParallel(b *testing.B) {
	c := NewDecisionCache(10000, 5*time.Minute)
	evs := benchEvents(10000)
	for _, ev := range evs {
		c.Put(ev, allow)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			c.Get(evs[i%len(evs)])
			i++
		}
	})
}

// BenchmarkDecisionCache_PutFull100k shows eviction cost does not grow with
// capacity (the previous implementation scanned every entry per eviction).
func BenchmarkDecisionCache_PutFull100k(b *testing.B) {
	c := NewDecisionCache(100000, 5*time.Minute)
	evs := benchEvents(200000)
	for _, ev := range evs[:100000] {
		c.Put(ev, allow)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Put(evs[100000+i%100000], allow)
	}
}
