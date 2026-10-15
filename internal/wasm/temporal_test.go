package wasm

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestTemporalInputs(t *testing.T) {
	ts := time.Date(2024, 3, 4, 5, 6, 7, 800_000_000, time.UTC)
	for _, tc := range []struct {
		name      string
		ts, start time.Time
		wall      int64
		age       uint64
	}{
		{"no timestamp", time.Time{}, ts, 0, 0},
		{"pre-epoch timestamp", time.Unix(-5, 0), time.Time{}, 0, 0},
		{"no container", ts, time.Time{}, ts.Unix(), 0},
		{"aged", ts, ts.Add(-90*time.Second - 500*time.Microsecond), ts.Unix(), 90_000},
		{"just started", ts, ts, ts.Unix(), 1},
		{"start a tick after the event", ts, ts.Add(10 * time.Millisecond), ts.Unix(), 1},
		{"clocks disagree", ts, ts.Add(2 * time.Second), ts.Unix(), 0},
	} {
		wall, age := temporalInputs(&api.Event{Timestamp: tc.ts, ContainerStart: tc.start})
		if wall != tc.wall || age != tc.age {
			t.Errorf("%s: got (%d, %d), want (%d, %d)", tc.name, wall, age, tc.wall, tc.age)
		}
	}
}

func TestWriteEventBinary_Temporal(t *testing.T) {
	ts := time.Unix(1_700_000_000, 0)
	ev := &api.Event{Comm: "x", Timestamp: ts, ContainerStart: ts.Add(-time.Hour)}

	buf := make([]byte, eventStructSize)
	writeEventBinary(buf, ev, false)
	for i := offWallClock; i < eventStructSize; i++ {
		if buf[i] != 0 {
			t.Fatalf("pre-temporal module: byte %d = %d, want 0", i, buf[i])
		}
	}

	writeEventBinary(buf, ev, true)
	if got := binary.LittleEndian.Uint32(buf[offWallClock:]); got != 1_700_000_000 {
		t.Errorf("wall_clock_unix = %d", got)
	}
	var a [8]byte
	copy(a[:], buf[offContainerAge:offContainerAge+6])
	if got := binary.LittleEndian.Uint64(a[:]); got != 3_600_000 {
		t.Errorf("container_age_ms = %d", got)
	}
	if buf[255] != 0 {
		t.Error("reserved byte not zero")
	}
	if string(buf[13:14]) != "x" {
		t.Error("comm overwritten")
	}

	// Beyond u32 seconds (2106) the clock is unknown, not wrapped. The
	// largest age a time.Duration can hold (~292 years) fits in u48 ms
	// with all of its bytes intact.
	far := time.Unix(1<<33, 0)
	longest := time.Duration(1<<63 - 1)
	writeEventBinary(buf, &api.Event{Timestamp: far, ContainerStart: far.Add(-longest)}, true)
	if got := binary.LittleEndian.Uint32(buf[offWallClock:]); got != 0 {
		t.Errorf("unrepresentable wall clock = %d, want 0", got)
	}
	copy(a[:], buf[offContainerAge:offContainerAge+6])
	if got, want := binary.LittleEndian.Uint64(a[:]), uint64(longest.Milliseconds()); got != want {
		t.Errorf("longest age = %d, want %d", got, want)
	}
}

func TestMarshalEventForWASM_Temporal(t *testing.T) {
	ts := time.Unix(1_700_000_000, 0)
	ev := &api.Event{Timestamp: ts, ContainerStart: ts.Add(-1500 * time.Millisecond)}
	for _, temporal := range []bool{false, true} {
		data, err := marshalEventForWASM(ev, temporal)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		_, hasWall := m["wall_clock_unix"]
		_, hasAge := m["container_age_ms"]
		if hasWall != temporal || hasAge != temporal {
			t.Fatalf("temporal=%v: keys present wall=%v age=%v", temporal, hasWall, hasAge)
		}
		if temporal && (m["wall_clock_unix"] != float64(1_700_000_000) || m["container_age_ms"] != float64(1500)) {
			t.Errorf("temporal keys = %v, %v", m["wall_clock_unix"], m["container_age_ms"])
		}
	}
}

func TestPool_TemporalAndTimeDependent(t *testing.T) {
	age := [3]uint32{compiler.FieldBitContainerAge | compiler.FieldBitPath, compiler.FieldBitPath, 0}
	for _, tc := range []struct {
		name     string
		mod      []byte
		temporal bool
		timeDep  [3]bool
	}{
		// Pre-temporal modules are never sent time, whatever they declare.
		{"abi<3 undeclared", wasmtest.ConstPolicy(0, nil), false, [3]bool{}},
		{"abi<3 declares time", wasmtest.ConstPolicy(0, &[3]uint32{compiler.FieldBitTime, 0, 0}), false, [3]bool{}},
		// A temporal module that declares nothing may read anything.
		{"abi3 undeclared", wasmtest.AgeKnownPolicy(nil), true, [3]bool{true, true, true}},
		{"abi3 declared", wasmtest.AgeKnownPolicy(&age), true, [3]bool{true, false, false}},
	} {
		pool := newPoolFromBytes(t, tc.mod, 1)
		if pool.Temporal() != tc.temporal {
			t.Errorf("%s: Temporal() = %v", tc.name, pool.Temporal())
		}
		ev := NewPolicyEvaluator(pool, "h")
		for i, want := range tc.timeDep {
			if got := ev.TimeDependent(api.EventType(i)); got != want {
				t.Errorf("%s: TimeDependent(%d) = %v, want %v", tc.name, i, got, want)
			}
		}
	}
	var nilEval *PolicyEvaluator
	if !nilEval.TimeDependent(api.EventTypeProcess) {
		t.Error("nil evaluator must be conservatively time dependent")
	}
}

func TestPolicyEvaluator_SendsContainerAge(t *testing.T) {
	pool := newPoolFromBytes(t, wasmtest.AgeKnownPolicy(nil), 1)
	ev := NewPolicyEvaluator(pool, "h")
	fixed := time.Unix(1_700_000_000, 0)
	ev.now = func() time.Time { return fixed }
	ctx := context.Background()

	known := &api.Event{Timestamp: fixed, ContainerStart: fixed.Add(-time.Minute)}
	if r, err := ev.Evaluate(ctx, known); err != nil || r.Action != api.ActionAllow {
		t.Errorf("known age: %+v, %v; want allow", r, err)
	}
	if r, err := ev.Evaluate(ctx, &api.Event{Timestamp: fixed}); err != nil || r.Action != api.ActionDeny {
		t.Errorf("unknown age: %+v, %v; want deny", r, err)
	}

	// An event without a timestamp is stamped with the evaluator's clock
	// (on a copy), so its age is still known.
	unstamped := &api.Event{ContainerStart: fixed.Add(-time.Minute)}
	if r, err := ev.Evaluate(ctx, unstamped); err != nil || r.Action != api.ActionAllow {
		t.Errorf("unstamped event: %+v, %v; want allow", r, err)
	}
	if !unstamped.Timestamp.IsZero() {
		t.Error("Evaluate modified the caller's event")
	}
}
