package drift

import (
	"fmt"
	"math"
	"sync"
	"testing"
	"time"
)

func TestCollectorRollingWindow(t *testing.T) {
	now := time.Unix(1200, 0)
	fc := NewFingerprintCollectorWithConfig(CollectorConfig{Window: time.Minute, Clock: func() time.Time { return now }})
	fc.Record("agent", "image", "old")
	initial := fc.Snapshot("agent")
	if initial.Window != time.Minute || !initial.Warmup || initial.Vectors["old"] != 1 {
		t.Fatalf("initial snapshot = %+v", initial)
	}
	now = now.Add(30 * time.Second)
	fc.Record("agent", "image", "new")
	now = now.Add(30 * time.Second)
	fp := fc.Snapshot("agent")
	if fp.Warmup || fp.Window != time.Minute || fp.Vectors["old"] != 0 || fp.Vectors["new"] != 1 {
		t.Fatalf("rolling snapshot = %+v", fp)
	}
	fp.Vectors["new"] = 100
	if got := fc.Snapshot("agent").Vectors["new"]; got != 1 {
		t.Fatalf("mutated collector via snapshot: %v", got)
	}
	now = now.Add(30 * time.Second)
	if got := fc.Snapshot("agent"); len(got.Vectors) != 0 || got.Window != time.Minute || got.Warmup {
		t.Fatalf("idle window = %+v", got)
	}
	now = now.Add(time.Hour)
	fc.Record("agent", "image", "fresh")
	if got := fc.Snapshot("agent").Vectors["fresh"]; got != 1 {
		t.Fatalf("rate = %v, want 1/min", got)
	}
}

func TestCollectorIdentityChangeAndBounds(t *testing.T) {
	now := time.Unix(1200, 0)
	fc := NewFingerprintCollectorWithConfig(CollectorConfig{Window: time.Minute, TTL: 2 * time.Minute, MaxAgents: 3, MaxPatterns: 4, Clock: func() time.Time { return now }})
	for n := range 1000 {
		fc.Record("agent", "image", fmt.Sprint(n))
	}
	fp := fc.Snapshot("agent")
	if len(fp.Vectors) != 4 || fp.Vectors[OverflowPattern] != 997 {
		t.Fatalf("pattern budget/overflow = %+v", fp.Vectors)
	}
	fc.Record("agent", "new-image", "new")
	fp = fc.Snapshot("agent")
	if fp.ImageHash != "new-image" || !fp.Warmup || len(fp.Vectors) != 1 {
		t.Fatalf("mixed image identities: %+v", fp)
	}
	for n := range 10 {
		now = now.Add(time.Second)
		fc.Record(fmt.Sprint(n), "image", "pattern")
	}
	if len(fc.counters) != 3 || fc.Snapshot("agent") != nil {
		t.Fatal("agent cardinality not bounded")
	}
	now = now.Add(2 * time.Minute)
	if removed := fc.Prune(); removed != 3 || len(fc.counters) != 0 {
		t.Fatal("TTL did not remove idle agents")
	}
	fc.Record("bad", "image", string(make([]byte, MaxKeyLength+1)))
	if fc.Snapshot("bad") != nil {
		t.Fatal("accepted oversized pattern")
	}
}

func TestCollectorLongLivedRollingRate(t *testing.T) {
	now := time.Unix(1200, 0)
	fc := NewFingerprintCollectorWithConfig(CollectorConfig{Window: time.Minute, MaxPatterns: 8, Clock: func() time.Time { return now }})
	for second := range 10_000 {
		fc.Record("agent", "image", "steady")
		fc.Record("agent", "image", fmt.Sprint(second))
		now = now.Add(time.Second)
		fp := fc.Snapshot("agent")
		if len(fp.Vectors) > 8 {
			t.Fatal("pattern churn exceeded budget")
		}
		if second > 60 && (fp.Vectors["steady"] < 59 || fp.Vectors["steady"] > 60) {
			t.Fatalf("rate drifted with uptime: %v", fp.Vectors["steady"])
		}
	}
}

func TestDetectorBoundsReceiptTTLAndIdentity(t *testing.T) {
	now := time.Unix(1200, 0)
	d := NewDetector(DetectorConfig{TTL: time.Minute, MaxFingerprints: 4, MaxImages: 2, MaxAgentsPerImage: 2, MaxPatterns: 2, Clock: func() time.Time { return now }})
	submit := func(agent, image string) {
		d.Submit(&BehaviorFingerprint{AgentID: agent, ImageHash: image, Timestamp: now.Add(100 * time.Hour), Vectors: map[string]float64{"p": 1}})
	}
	for n := range 1000 {
		submit(fmt.Sprint(n), fmt.Sprint(n%3))
		now = now.Add(time.Millisecond)
		if len(d.Images()) > 2 || len(d.received) > 4 {
			t.Fatal("detector exceeded global/image limit")
		}
		for _, image := range d.Images() {
			if d.AgentCount(image) > 2 {
				t.Fatal("exceeded per-image limit")
			}
		}
	}
	submit("moving", "before")
	submit("moving", "after")
	for _, fp := range d.fingerprints["before"] {
		if fp.AgentID == "moving" {
			t.Fatal("agent remained in old image group")
		}
	}
	d.Clear("after")
	for fp := range d.received {
		if fp.ImageHash == "after" {
			t.Fatal("Clear retained receipt index")
		}
	}
	now = now.Add(time.Minute)
	d.Prune()
	if len(d.Images()) != 0 || len(d.received) != 0 {
		t.Fatal("future timestamp pinned detector state past receipt TTL")
	}
	for _, fp := range []*BehaviorFingerprint{
		nil,
		{AgentID: "a", Vectors: map[string]float64{"p": 1}},
		{AgentID: "a", ImageHash: "i", Vectors: map[string]float64{"p": math.NaN()}},
		{AgentID: "a", ImageHash: "i", Vectors: map[string]float64{"p": math.Inf(1)}},
		{AgentID: "a", ImageHash: "i", Vectors: map[string]float64{"p": -1}},
		{AgentID: "a", ImageHash: "i", Vectors: map[string]float64{"a": 1, "b": 2, "c": 3}},
	} {
		if err := d.Submit(fp); err == nil {
			t.Error("invalid fingerprint rejection was not reported")
		}
	}
	if len(d.Images()) != 0 {
		t.Fatal("accepted invalid/unidentified fingerprint")
	}
}

func TestDetectorOwnedVectorsAndComparableWindows(t *testing.T) {
	now := time.Unix(1200, 0)
	d := NewDetector(DetectorConfig{Clock: func() time.Time { return now }})
	fp := &BehaviorFingerprint{AgentID: "a", ImageHash: "i", Window: time.Minute, Timestamp: now, Vectors: map[string]float64{"unique": 10}}
	d.Submit(fp)
	fp.Vectors["unique"] = 0
	peer := &BehaviorFingerprint{AgentID: "b", ImageHash: "i", Window: 2 * time.Minute, Timestamp: now, Vectors: map[string]float64{"normal": 10}}
	d.Submit(peer)
	if len(d.Anomalies("i")) != 0 {
		t.Fatal("compared different window sizes")
	}
	peer.Window = time.Minute
	peer.Warmup = true
	d.Submit(peer)
	if len(d.Anomalies("i")) != 0 {
		t.Fatal("compared warming-up peer")
	}
	peer.Warmup = false
	peer.Timestamp = now.Add(-2 * time.Minute)
	d.Submit(peer)
	if len(d.Anomalies("i")) != 0 {
		t.Fatal("compared disjoint observation windows")
	}
	peer.Timestamp = now
	d.Submit(peer)
	if len(d.AnomaliesForAgent("a", "i")) != 1 {
		t.Fatal("expected original owned unique vector to survive mutation")
	}
}

func TestConcurrentCollectorAndDetectorLifecycle(t *testing.T) {
	fc := NewFingerprintCollectorWithConfig(CollectorConfig{MaxAgents: 8, MaxPatterns: 8})
	d := NewDetector(DetectorConfig{MaxFingerprints: 8, MaxImages: 4, MaxAgentsPerImage: 4, MaxPatterns: 8})
	var wg sync.WaitGroup
	for worker := range 6 {
		wg.Go(func() {
			for n := range 1000 {
				agent := fmt.Sprint((n + worker) % 30)
				fc.Record(agent, fmt.Sprint(n%5), fmt.Sprint(n%100))
				if fp := fc.Snapshot(agent); fp != nil {
					d.Submit(fp)
					fp.Vectors["caller-owned"] = 42
				}
				_ = d.Status()
				_ = d.Anomalies(fmt.Sprint(n % 5))
				if n%11 == 0 {
					fc.Reset(agent)
					fc.Prune()
					d.Prune()
					d.PruneStale(time.Now().Add(-time.Hour))
				}
			}
		})
	}
	wg.Wait()
	if len(fc.counters) > 8 || len(d.received) > 8 || len(d.Images()) > 4 {
		t.Fatal("concurrent churn exceeded budget")
	}
}

func TestDetectorIndependentCapacityLimits(t *testing.T) {
	now := time.Unix(1200, 0)
	for _, tc := range []struct {
		name   string
		config DetectorConfig
	}{
		{"global", DetectorConfig{MaxFingerprints: 2}},
		{"per-image", DetectorConfig{MaxAgentsPerImage: 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.config.Clock = func() time.Time { return now }
			d := NewDetector(tc.config)
			for n := range 3 {
				d.Submit(&BehaviorFingerprint{AgentID: fmt.Sprint(n), ImageHash: "image"})
				now = now.Add(time.Second)
			}
			if d.AgentCount("image") != 2 || len(d.received) != 2 {
				t.Fatal("capacity not enforced")
			}
			for _, fp := range d.fingerprints["image"] {
				if fp.AgentID == "0" {
					t.Fatal("oldest fingerprint was not evicted")
				}
			}
		})
	}
}

func TestRollingWindowRoundsBucketWidthUp(t *testing.T) {
	now := time.Unix(1200, 0)
	fc := NewFingerprintCollectorWithConfig(CollectorConfig{Window: 119 * time.Nanosecond, Clock: func() time.Time { return now }})
	if fc.bucketWidth != 2*time.Nanosecond {
		t.Fatalf("bucket width %v, want ceil(window/60)", fc.bucketWidth)
	}
	fc.Record("agent", "image", "pattern")
	now = now.Add(100 * time.Nanosecond)
	fc.Record("agent", "image", "pattern")
	fp := fc.Snapshot("agent")
	if fp.Vectors["pattern"] != 2/fc.config.Window.Minutes() {
		t.Fatal("ring overwrote in-window observation")
	}
}
