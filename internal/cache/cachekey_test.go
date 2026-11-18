package cache

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/policymeta"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

// This file hand-assembles a tiny ABI v6 policy module that imports the host's
// get_field_u32 callback and reads PPID (field 17) and the host-computed
// capture-quality mask (field 16). Compiled YAML policies do not read those
// fields yet, so only a hand-written module can expose the cache-key gap the
// regression below covers. The module denies an event when either observed
// value is non-zero and allows it when both are zero.

func ckULEB(v uint32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			out = append(out, b|0x80)
			continue
		}
		return append(out, b)
	}
}

func ckSLEB(v int32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if (v == 0 && b&0x40 == 0) || (v == -1 && b&0x40 != 0) {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

func ckI32(v int32) []byte { return append([]byte{0x41}, ckSLEB(v)...) }

func ckSection(id byte, body []byte) []byte {
	return append(append([]byte{id}, ckULEB(uint32(len(body)))...), body...)
}

func ckVec(items ...[]byte) []byte {
	out := ckULEB(uint32(len(items)))
	for _, item := range items {
		out = append(out, item...)
	}
	return out
}

func ckName(s string) []byte { return append(ckULEB(uint32(len(s))), s...) }

// ckCallbackPolicy builds:
//
//	(import "env" "get_field_u32" (func $field (param i32) (result i32)))
//	(func $malloc (param i32) (result i32) (i32.const 1024))
//	(func $evaluate_event (param i32) (result i32)
//	  select(allow=0, deny=1, is_zero(or(read_ppid, read_quality))))
//	(func $abi_version (result i32) (i32.const 6))
//	(func $warmor_fields_read (param i32) (result i32) declared)
//
// The evaluation reads both callbacks on every call, so a cached decision
// from an event with a different PPID or different capture loss is wrong.
func ckCallbackPolicy(declared uint32) []byte {
	fnTypeInOut := []byte{0x60, 0x01, 0x7f, 0x01, 0x7f} // (i32) -> (i32)
	fnTypeOut := []byte{0x60, 0x00, 0x01, 0x7f}         // () -> (i32)

	imp := ckName("env")
	imp = append(imp, ckName("get_field_u32")...)
	imp = append(imp, 0x00, 0x00) // function import, type 0

	// Imported function occupies index 0; defined functions start at 1.
	mallocBody := append([]byte{0x00}, ckI32(1024)...)
	mallocBody = append(mallocBody, 0x0b)

	var eval []byte
	eval = append(eval, 0x00)                             // no locals
	eval = append(eval, ckI32(int32(api.ActionAllow))...) // val1: allow
	eval = append(eval, ckI32(int32(api.ActionDeny))...)  // val2: deny
	eval = append(eval, ckI32(int32(wasm.FieldPPID))...)
	eval = append(eval, 0x10, 0x00) // call $field
	eval = append(eval, ckI32(int32(wasm.FieldCaptureQuality))...)
	eval = append(eval, 0x10, 0x00) // call $field
	eval = append(eval, 0x72)       // i32.or
	eval = append(eval, 0x45)       // i32.eqz
	eval = append(eval, 0x1b)       // select
	eval = append(eval, 0x0b)

	versionBody := append([]byte{0x00}, ckI32(int32(wasm.CaptureQualityABIVersion))...)
	versionBody = append(versionBody, 0x0b)
	fieldsBody := append([]byte{0x00}, ckI32(int32(declared))...)
	fieldsBody = append(fieldsBody, 0x0b)

	bodies := make([][]byte, 0, 4)
	for _, b := range [][]byte{mallocBody, eval, versionBody, fieldsBody} {
		bodies = append(bodies, append(ckULEB(uint32(len(b))), b...))
	}

	m := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	m = append(m, ckSection(1, ckVec(fnTypeInOut, fnTypeOut))...)
	m = append(m, ckSection(2, ckVec(imp))...)
	m = append(m, ckSection(3, ckVec(ckULEB(0), ckULEB(0), ckULEB(1), ckULEB(0)))...)
	m = append(m, ckSection(5, ckVec([]byte{0x00, 0x01}))...)
	m = append(m, ckSection(7, ckVec(
		append(ckName("memory"), 0x02, 0x00),
		append(ckName("malloc"), 0x00, 0x01),
		append(ckName("evaluate_event"), 0x00, 0x02),
		append(ckName("abi_version"), 0x00, 0x03),
		append(ckName("warmor_fields_read"), 0x00, 0x04),
	))...)
	m = append(m, ckSection(10, ckVec(bodies...))...)
	return m
}

func ckLoadCallbackPolicy(t *testing.T, declared uint32) *wasm.PolicyEvaluator {
	t.Helper()
	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close(ctx) })
	if err := rt.LoadPolicyBytes(ctx, ckCallbackPolicy(declared)); err != nil {
		t.Fatalf("load hand-written module: %v", err)
	}
	pool, err := wasm.NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close(ctx) })
	return wasm.NewPolicyEvaluator(pool, "hand-written")
}

// TestCacheKey_PPIDAndCaptureQualityAreSeparateEntries is the regression for
// the incomplete key: a hand-written module that reads get_field_u32(17) and
// (16) must not receive another event's decision when only those observations
// differ.
func TestCacheKey_PPIDAndCaptureQualityAreSeparateEntries(t *testing.T) {
	ctx := context.Background()
	declared := uint32(policymeta.FieldBitPPID | policymeta.FieldBitRequireCompleteCapture)
	evaluator := ckLoadCallbackPolicy(t, declared)

	base := func() *api.Event {
		// Same PID, path, identity, parent comm and cgroup for every event;
		// only PPID / capture telemetry will vary.
		return &api.Event{
			PID: 1000, UID: 1000, Filename: "/bin/tool",
			ParentComm: "bash", CgroupID: 42,
		}
	}
	clean := base()
	otherPPID := base()
	otherPPID.PPID = 777
	lossyCapture := base()
	lossyCapture.TruncatedFields = []string{"filename"} // quality bit FieldBitPath
	neverCached := base()
	neverCached.PPID = 999

	events := []*api.Event{clean, otherPPID, lossyCapture}
	want := []api.Action{api.ActionAllow, api.ActionDeny, api.ActionDeny}
	// First prove the module really observes both inputs: direct evaluation
	// (no cache) must give different verdicts for the three events.
	for i, ev := range events {
		res, err := evaluator.Evaluate(ctx, ev)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if res.Action != want[i] {
			t.Fatalf("event %d: action = %v, want %v", i, res.Action, want[i])
		}
	}

	c := NewDecisionCache(10, time.Minute)
	// Install the module's declaration so the test exercises the
	// declaration -> key path, not just the conservative default.
	c.SetDeclaredInputs(func(api.EventType) uint32 { return declared })
	for i, ev := range events {
		if _, hit := c.Get(ev); hit {
			t.Fatalf("event %d: hit before any Put", i)
		}
		res, err := evaluator.Evaluate(ctx, ev)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		c.Put(ev, res)
		cached, hit := c.Get(ev)
		if !hit || cached.Action != want[i] {
			t.Fatalf("event %d: cached = %+v, hit = %v", i, cached, hit)
		}
	}
	if size := c.Stats().Size; size != 3 {
		t.Fatalf("cache size = %d, want 3 distinct entries (one per observed input set)", size)
	}
	if _, hit := c.Get(neverCached); hit {
		t.Fatal("event with an unseen PPID collided with a cached entry")
	}
}

// TestCacheKey_UnchangedEventsStillHit pins the backward-compatible side:
// events that agree on every observable input keep sharing one entry, and
// clean events (no PPID, no capture loss) keep exactly the keys they had
// before the new fields existed.
func TestCacheKey_UnchangedEventsStillHit(t *testing.T) {
	c := NewDecisionCache(10, time.Minute)
	ev := &api.Event{PID: 1000, UID: 1000, Filename: "/bin/tool"}
	c.Put(ev, allow)
	for i := 0; i < 3; i++ {
		if _, hit := c.Get(&api.Event{PID: 1000, UID: 1000, Filename: "/bin/tool"}); !hit {
			t.Fatalf("hit %d: identical clean event missed the cache", i)
		}
	}
	if s := c.Stats(); s.Size != 1 || s.TotalHits != 3 {
		t.Fatalf("stats = %+v, want one entry and three hits", s)
	}

	// Two events that agree on every observable input (including PPID and
	// capture quality) still share one entry even for a hand-written module
	// that calls both callbacks on every evaluation.
	ctx := context.Background()
	evaluator := ckLoadCallbackPolicy(t, 0)
	dup := &api.Event{PID: 7, Filename: "/bin/x", PPID: 3, ParentComm: "init", CgroupID: 9}
	res, err := evaluator.Evaluate(ctx, dup)
	if err != nil {
		t.Fatal(err)
	}
	c2 := NewDecisionCache(10, time.Minute)
	c2.Put(dup, res)
	same := *dup
	if _, hit := c2.Get(&same); !hit {
		t.Fatal("identical event missed the cache")
	}
}

// TestCacheKey_DeclaredInputsRestoreOldPPIDKey exercises the declaration ->
// key path. A policy that explicitly declared it does not read FieldBitPPID
// keeps its old cache behavior (a PPID-only change is a hit), while the
// default cache stays conservative and separates the same events. Capture
// quality is never declared, so it always separates them.
func TestCacheKey_DeclaredInputsRestoreOldPPIDKey(t *testing.T) {
	base := func() *api.Event {
		return &api.Event{PID: 1000, Filename: "/bin/tool", ParentComm: "init", CgroupID: 9}
	}
	otherPPID := base()
	otherPPID.PPID = 777
	lossy := base()
	lossy.TruncatedFields = []string{"filename"}

	c := NewDecisionCache(10, time.Minute)
	c.SetDeclaredInputs(func(api.EventType) uint32 { return 0 })
	if _, hit := c.Get(base()); hit {
		t.Fatal("hit before Put")
	}
	c.Put(base(), allow)
	if _, hit := c.Get(otherPPID); !hit {
		t.Fatal("PPID-only change missed although the policy declared it does not read PPID")
	}
	if _, hit := c.Get(lossy); hit {
		t.Fatal("capture-quality change hit a cached decision (quality has no declaration bit)")
	}

	// Declaring FieldBitPPID puts it back in the key; the setter clears the
	// entries built under the previous declaration.
	if size := c.Stats().Size; size != 1 {
		t.Fatalf("size = %d, want 1", size)
	}
	c.SetDeclaredInputs(func(api.EventType) uint32 { return uint32(policymeta.FieldBitPPID) })
	if c.Stats().Size != 0 {
		t.Fatal("SetDeclaredInputs must clear keys built under the old declaration")
	}
	c.Put(base(), allow)
	if _, hit := c.Get(otherPPID); hit {
		t.Fatal("PPID-only change hit after declaring FieldBitPPID")
	}

	// With no declaration installed at all the conservative default applies.
	c2 := NewDecisionCache(10, time.Minute)
	c2.Put(base(), allow)
	if _, hit := c2.Get(otherPPID); hit {
		t.Fatal("default cache must separate PPIDs")
	}
}

// TestPolicyInputsForABI_ExposesNewCallbacks guards the root cause: the
// coverage test compared cache keys against PolicyInputsForABI, which used to
// omit fields 16 and 17 and therefore could not detect a missing key field.
func TestPolicyInputsForABI_ExposesNewCallbacks(t *testing.T) {
	base := &api.Event{PID: 1, Filename: "/bin/x", PPID: 10}
	ppidChanged := *base
	ppidChanged.PPID = 11
	lossy := *base
	lossy.TruncatedFields = []string{"filename"}

	for version := uint32(0); version <= wasm.MaxABIVersion; version++ {
		a := wasm.PolicyInputsForABI(base, version)
		if b := wasm.PolicyInputsForABI(&ppidChanged, version); bytes.Equal(a[2], b[2]) {
			t.Errorf("ABI %d: PPID change invisible to PolicyInputsForABI", version)
		}
		if b := wasm.PolicyInputsForABI(&lossy, version); bytes.Equal(a[2], b[2]) {
			t.Errorf("ABI %d: capture-quality change invisible to PolicyInputsForABI", version)
		}
	}
}
