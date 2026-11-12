package drift

import (
	"math"
	"testing"
	"time"
)

func TestFingerprintCollectorRecord(t *testing.T) {
	fc := NewFingerprintCollector(5 * time.Minute)

	fc.Record("agent-1", "sha256:abc", "exec:/usr/bin/curl")
	fc.Record("agent-1", "sha256:abc", "exec:/usr/bin/curl")
	fc.Record("agent-1", "sha256:abc", "file:/etc/passwd")

	fp := fc.Snapshot("agent-1")
	if fp == nil {
		t.Fatal("expected non-nil fingerprint")
	}
	if fp.AgentID != "agent-1" {
		t.Errorf("expected agent-1, got %s", fp.AgentID)
	}
	if fp.ImageHash != "sha256:abc" {
		t.Errorf("expected sha256:abc, got %s", fp.ImageHash)
	}
	if len(fp.Vectors) != 2 {
		t.Errorf("expected 2 vectors, got %d", len(fp.Vectors))
	}
	if fp.Vectors["exec:/usr/bin/curl"] <= 0 {
		t.Error("expected positive rate for exec:/usr/bin/curl")
	}
	if fp.Vectors["file:/etc/passwd"] <= 0 {
		t.Error("expected positive rate for file:/etc/passwd")
	}
}

func TestFingerprintCollectorSnapshotNil(t *testing.T) {
	fc := NewFingerprintCollector(5 * time.Minute)

	fp := fc.Snapshot("nonexistent")
	if fp != nil {
		t.Error("expected nil for unknown agent")
	}
}

func TestFingerprintCollectorReset(t *testing.T) {
	fc := NewFingerprintCollector(5 * time.Minute)

	fc.Record("agent-1", "sha256:abc", "exec:/bin/ls")
	fc.Reset("agent-1")

	fp := fc.Snapshot("agent-1")
	if fp != nil {
		t.Error("expected nil after reset")
	}
}

func TestFingerprintRateCalculation(t *testing.T) {
	fc := NewFingerprintCollector(5 * time.Minute)

	fc.Record("agent-1", "sha256:abc", "exec:/bin/ls")
	fc.Record("agent-1", "sha256:abc", "exec:/bin/ls")

	fp := fc.Snapshot("agent-1")
	if fp == nil {
		t.Fatal("expected non-nil fingerprint")
	}
	// With elapsed clamped to at least 1 second, rate = count / minutes
	// 2 events / (1s / 60s) = 120/min (minimum, if snapshot taken instantly)
	rate := fp.Vectors["exec:/bin/ls"]
	if rate <= 0 {
		t.Errorf("expected positive rate, got %f", rate)
	}
}

func TestDetectorSubmitAndAnomalies(t *testing.T) {
	d := NewDetector(DetectorConfig{Threshold: 2.0})

	// Submit 5 agents with similar rates, 1 outlier
	for i := range 5 {
		d.Submit(&BehaviorFingerprint{
			AgentID:   agentID(i),
			ImageHash: "sha256:img1",
			Vectors:   map[string]float64{"exec:/bin/ls": 10.0},
			Timestamp: time.Now(),
		})
	}
	// Outlier agent
	d.Submit(&BehaviorFingerprint{
		AgentID:   "agent-outlier",
		ImageHash: "sha256:img1",
		Vectors:   map[string]float64{"exec:/bin/ls": 100.0},
		Timestamp: time.Now(),
	})

	anomalies := d.Anomalies("sha256:img1")
	if len(anomalies) == 0 {
		t.Fatal("expected anomalies for outlier agent")
	}

	found := false
	for _, a := range anomalies {
		if a.AgentID == "agent-outlier" && a.Pattern == "exec:/bin/ls" {
			found = true
			if a.Direction != "excess" {
				t.Errorf("expected excess direction, got %s", a.Direction)
			}
			if a.ZScore <= 2.0 {
				t.Errorf("expected z-score > 2.0, got %f", a.ZScore)
			}
		}
	}
	if !found {
		t.Error("outlier agent not detected in anomalies")
	}
}

func TestDetectorNoAnomalySingleAgent(t *testing.T) {
	d := NewDetector(DetectorConfig{Threshold: 3.0})

	d.Submit(&BehaviorFingerprint{
		AgentID:   "agent-1",
		ImageHash: "sha256:img1",
		Vectors:   map[string]float64{"exec:/bin/ls": 10.0},
		Timestamp: time.Now(),
	})

	anomalies := d.Anomalies("sha256:img1")
	if len(anomalies) != 0 {
		t.Errorf("expected no anomalies with single agent, got %d", len(anomalies))
	}
}

func TestDetectorNoAnomalyUniformRates(t *testing.T) {
	d := NewDetector(DetectorConfig{Threshold: 3.0})

	for i := range 5 {
		d.Submit(&BehaviorFingerprint{
			AgentID:   agentID(i),
			ImageHash: "sha256:img1",
			Vectors:   map[string]float64{"exec:/bin/ls": 10.0},
			Timestamp: time.Now(),
		})
	}

	anomalies := d.Anomalies("sha256:img1")
	if len(anomalies) != 0 {
		t.Errorf("expected no anomalies for uniform rates, got %d", len(anomalies))
	}
}

func TestDetectorUniquePatternDetection(t *testing.T) {
	d := NewDetector(DetectorConfig{Threshold: 3.0})

	// 4 agents have only "exec:/bin/ls"
	for i := range 4 {
		d.Submit(&BehaviorFingerprint{
			AgentID:   agentID(i),
			ImageHash: "sha256:img1",
			Vectors:   map[string]float64{"exec:/bin/ls": 10.0},
			Timestamp: time.Now(),
		})
	}
	// 1 agent has an additional unique pattern
	d.Submit(&BehaviorFingerprint{
		AgentID:   "agent-unique",
		ImageHash: "sha256:img1",
		Vectors: map[string]float64{
			"exec:/bin/ls":       10.0,
			"exec:/usr/bin/wget": 5.0,
		},
		Timestamp: time.Now(),
	})

	anomalies := d.Anomalies("sha256:img1")
	found := false
	for _, a := range anomalies {
		if a.AgentID == "agent-unique" && a.Pattern == "exec:/usr/bin/wget" && a.Direction == "unique" {
			found = true
		}
	}
	if !found {
		t.Error("expected unique pattern anomaly for agent-unique")
	}
}

func TestDetectorAnomaliesForAgent(t *testing.T) {
	d := NewDetector(DetectorConfig{Threshold: 2.0})

	for i := range 5 {
		d.Submit(&BehaviorFingerprint{
			AgentID:   agentID(i),
			ImageHash: "sha256:img1",
			Vectors:   map[string]float64{"exec:/bin/ls": 10.0},
			Timestamp: time.Now(),
		})
	}
	d.Submit(&BehaviorFingerprint{
		AgentID:   "agent-outlier",
		ImageHash: "sha256:img1",
		Vectors:   map[string]float64{"exec:/bin/ls": 100.0},
		Timestamp: time.Now(),
	})

	agentAnomalies := d.AnomaliesForAgent("agent-outlier", "sha256:img1")
	if len(agentAnomalies) == 0 {
		t.Fatal("expected anomalies for outlier agent")
	}
	for _, a := range agentAnomalies {
		if a.AgentID != "agent-outlier" {
			t.Errorf("expected only agent-outlier anomalies, got %s", a.AgentID)
		}
	}

	normalAnomalies := d.AnomaliesForAgent("agent-0", "sha256:img1")
	for _, a := range normalAnomalies {
		if a.Direction == "excess" && a.Pattern == "exec:/bin/ls" {
			t.Error("normal agent should not have excess anomaly")
		}
	}
}

func TestDetectorSubmitUpdatesExisting(t *testing.T) {
	d := NewDetector(DetectorConfig{Threshold: 3.0})

	d.Submit(&BehaviorFingerprint{
		AgentID:   "agent-1",
		ImageHash: "sha256:img1",
		Vectors:   map[string]float64{"exec:/bin/ls": 10.0},
		Timestamp: time.Now(),
	})
	d.Submit(&BehaviorFingerprint{
		AgentID:   "agent-1",
		ImageHash: "sha256:img1",
		Vectors:   map[string]float64{"exec:/bin/ls": 50.0},
		Timestamp: time.Now(),
	})

	if d.AgentCount("sha256:img1") != 1 {
		t.Errorf("expected 1 agent after update, got %d", d.AgentCount("sha256:img1"))
	}
}

func TestDetectorMultipleImages(t *testing.T) {
	d := NewDetector(DetectorConfig{Threshold: 3.0})

	d.Submit(&BehaviorFingerprint{
		AgentID:   "agent-1",
		ImageHash: "sha256:img1",
		Vectors:   map[string]float64{"exec:/bin/ls": 10.0},
		Timestamp: time.Now(),
	})
	d.Submit(&BehaviorFingerprint{
		AgentID:   "agent-2",
		ImageHash: "sha256:img2",
		Vectors:   map[string]float64{"exec:/bin/ls": 10.0},
		Timestamp: time.Now(),
	})

	images := d.Images()
	if len(images) != 2 {
		t.Errorf("expected 2 images, got %d", len(images))
	}
}

func TestDetectorClear(t *testing.T) {
	d := NewDetector(DetectorConfig{Threshold: 3.0})

	d.Submit(&BehaviorFingerprint{
		AgentID:   "agent-1",
		ImageHash: "sha256:img1",
		Vectors:   map[string]float64{"exec:/bin/ls": 10.0},
		Timestamp: time.Now(),
	})

	d.Clear("sha256:img1")
	if d.AgentCount("sha256:img1") != 0 {
		t.Error("expected 0 agents after clear")
	}
}

func TestDetectorFleetStatus(t *testing.T) {
	d := NewDetector(DetectorConfig{Threshold: 2.0})

	now := time.Now()
	for i := range 10 {
		d.Submit(&BehaviorFingerprint{
			AgentID:   agentID(i),
			ImageHash: "sha256:img1",
			Vectors:   map[string]float64{"exec:/bin/ls": 10.0},
			Timestamp: now,
		})
	}
	// Add an outlier to ensure anomaly count > 0
	d.Submit(&BehaviorFingerprint{
		AgentID:   "agent-outlier",
		ImageHash: "sha256:img1",
		Vectors:   map[string]float64{"exec:/bin/ls": 500.0},
		Timestamp: now,
	})

	statuses := d.Status()
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	s := statuses[0]
	if s.ImageHash != "sha256:img1" {
		t.Errorf("expected sha256:img1, got %s", s.ImageHash)
	}
	if s.AgentCount != 11 {
		t.Errorf("expected 11 agents, got %d", s.AgentCount)
	}
	if s.Anomalies == 0 {
		t.Error("expected anomalies > 0")
	}
	if !s.LastUpdate.Equal(now) {
		t.Errorf("expected last_update=%v, got %v", now, s.LastUpdate)
	}
}

func TestDetectorDeficitDirection(t *testing.T) {
	d := NewDetector(DetectorConfig{Threshold: 2.0})

	// 5 agents with high rate, 1 with very low rate
	for i := range 5 {
		d.Submit(&BehaviorFingerprint{
			AgentID:   agentID(i),
			ImageHash: "sha256:img1",
			Vectors:   map[string]float64{"exec:/bin/ls": 100.0},
			Timestamp: time.Now(),
		})
	}
	d.Submit(&BehaviorFingerprint{
		AgentID:   "agent-deficit",
		ImageHash: "sha256:img1",
		Vectors:   map[string]float64{"exec:/bin/ls": 0.0},
		Timestamp: time.Now(),
	})

	anomalies := d.AnomaliesForAgent("agent-deficit", "sha256:img1")
	found := false
	for _, a := range anomalies {
		if a.Direction == "deficit" && a.Pattern == "exec:/bin/ls" {
			found = true
			if a.ZScore >= 0 {
				t.Error("deficit z-score should be negative")
			}
		}
	}
	if !found {
		t.Error("expected deficit anomaly for agent-deficit")
	}
}

func TestDetectorZScoreAccuracy(t *testing.T) {
	d := NewDetector(DetectorConfig{Threshold: 0.5})

	// Manually computed: values 10,10,10,10,40 → mean=16, variance=144, stddev=12
	// z-score for 40: (40-16)/12 = 2.0
	// z-score for 10: (10-16)/12 = -0.5
	for i := range 4 {
		d.Submit(&BehaviorFingerprint{
			AgentID:   agentID(i),
			ImageHash: "sha256:img1",
			Vectors:   map[string]float64{"p": 10.0},
			Timestamp: time.Now(),
		})
	}
	d.Submit(&BehaviorFingerprint{
		AgentID:   "agent-high",
		ImageHash: "sha256:img1",
		Vectors:   map[string]float64{"p": 40.0},
		Timestamp: time.Now(),
	})

	anomalies := d.AnomaliesForAgent("agent-high", "sha256:img1")
	found := false
	for _, a := range anomalies {
		if a.Pattern == "p" {
			found = true
			expected := 2.0
			if math.Abs(a.ZScore-expected) > 0.01 {
				t.Errorf("expected z-score ~%.2f, got %.2f", expected, a.ZScore)
			}
			if math.Abs(a.MeanRate-16.0) > 0.01 {
				t.Errorf("expected mean rate ~16.0, got %.2f", a.MeanRate)
			}
		}
	}
	if !found {
		t.Error("expected anomaly for agent-high")
	}
}

func TestSubmitFromCollector(t *testing.T) {
	fc := NewFingerprintCollector(5 * time.Minute)
	fc.Record("agent-1", "sha256:img1", "exec:/bin/ls")
	fc.Record("agent-1", "sha256:img1", "exec:/bin/ls")

	d := NewDetector(DetectorConfig{Threshold: 3.0})
	d.SubmitFromCollector(fc, "agent-1")

	if d.AgentCount("sha256:img1") != 1 {
		t.Errorf("expected 1 agent after SubmitFromCollector, got %d", d.AgentCount("sha256:img1"))
	}
}

func TestSubmitFromCollectorNonexistent(t *testing.T) {
	fc := NewFingerprintCollector(5 * time.Minute)
	d := NewDetector(DetectorConfig{Threshold: 3.0})

	d.SubmitFromCollector(fc, "nonexistent")
	if d.AgentCount("any") != 0 {
		t.Error("expected no agents for nonexistent collector snapshot")
	}
}

func TestPruneStale(t *testing.T) {
	d := NewDetector(DetectorConfig{Threshold: 3.0})
	now := time.Now()

	d.Submit(&BehaviorFingerprint{AgentID: "a1", ImageHash: "img", Timestamp: now.Add(-time.Hour)})
	d.Submit(&BehaviorFingerprint{AgentID: "a2", ImageHash: "img", Timestamp: now})
	d.Submit(&BehaviorFingerprint{AgentID: "a3", ImageHash: "gone", Timestamp: now.Add(-time.Hour)})

	d.PruneStale(now.Add(-time.Minute))

	if got := d.AgentCount("img"); got != 1 {
		t.Errorf("img agent count = %d, want 1 (only the fresh fingerprint)", got)
	}
	for _, img := range d.Images() {
		if img == "gone" {
			t.Error("image with only stale fingerprints was not removed")
		}
	}
	if got := d.AgentCount("gone"); got != 0 {
		t.Errorf("gone agent count = %d, want 0", got)
	}
}

func agentID(i int) string {
	return "agent-" + string(rune('0'+i))
}
