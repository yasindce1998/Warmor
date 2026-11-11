package drift

import (
	"math"
	"sync"
	"time"
)

// DriftAnomaly represents a detected behavioral anomaly.
type DriftAnomaly struct {
	AgentID   string  `json:"agent_id"`
	Pattern   string  `json:"pattern"`
	ZScore    float64 `json:"z_score"`
	Direction string  `json:"direction"` // "excess", "deficit", or "unique"
	Rate      float64 `json:"rate"`
	MeanRate  float64 `json:"mean_rate"`
}

// DetectorConfig configures the drift detector.
type DetectorConfig struct {
	Threshold float64 // Z-score threshold (default: 3.0)
}

// Detector compares fingerprints from agents running the same image and finds outliers.
type Detector struct {
	mu           sync.RWMutex
	fingerprints map[string][]*BehaviorFingerprint // image hash → fingerprints
	threshold    float64
}

// NewDetector creates a drift detector with the given config.
func NewDetector(cfg DetectorConfig) *Detector {
	threshold := cfg.Threshold
	if threshold <= 0 {
		threshold = 3.0
	}
	return &Detector{
		fingerprints: make(map[string][]*BehaviorFingerprint),
		threshold:    threshold,
	}
}

// Submit adds or updates a fingerprint from an agent.
func (d *Detector) Submit(fp *BehaviorFingerprint) {
	d.mu.Lock()
	defer d.mu.Unlock()

	fps := d.fingerprints[fp.ImageHash]
	for i, existing := range fps {
		if existing.AgentID == fp.AgentID {
			fps[i] = fp
			return
		}
	}
	d.fingerprints[fp.ImageHash] = append(fps, fp)
}

// Anomalies returns all detected drift anomalies for a given image.
func (d *Detector) Anomalies(imageHash string) []DriftAnomaly {
	d.mu.RLock()
	defer d.mu.RUnlock()

	fps := d.fingerprints[imageHash]
	if len(fps) < 2 {
		return nil
	}

	// Collect all unique patterns across all agents
	patterns := make(map[string]bool)
	for _, fp := range fps {
		for pattern := range fp.Vectors {
			patterns[pattern] = true
		}
	}

	var anomalies []DriftAnomaly

	for pattern := range patterns {
		// Compute mean and std dev for this pattern
		var sum, sumSq float64
		n := float64(len(fps))

		for _, fp := range fps {
			rate := fp.Vectors[pattern]
			sum += rate
			sumSq += rate * rate
		}

		mean := sum / n
		variance := (sumSq / n) - (mean * mean)
		stddev := math.Sqrt(variance)

		if stddev < 1e-9 {
			continue
		}

		for _, fp := range fps {
			rate := fp.Vectors[pattern]
			z := (rate - mean) / stddev

			if math.Abs(z) > d.threshold {
				direction := "excess"
				if z < 0 {
					direction = "deficit"
				}
				anomalies = append(anomalies, DriftAnomaly{
					AgentID:   fp.AgentID,
					Pattern:   pattern,
					ZScore:    z,
					Direction: direction,
					Rate:      rate,
					MeanRate:  mean,
				})
			}
		}
	}

	// Check for unique patterns (only one agent has them)
	for _, fp := range fps {
		for pattern, rate := range fp.Vectors {
			count := 0
			for _, other := range fps {
				if other.Vectors[pattern] > 0 {
					count++
				}
			}
			if count == 1 && rate > 0 {
				anomalies = append(anomalies, DriftAnomaly{
					AgentID:   fp.AgentID,
					Pattern:   pattern,
					ZScore:    d.threshold + 1,
					Direction: "unique",
					Rate:      rate,
					MeanRate:  0,
				})
			}
		}
	}

	return anomalies
}

// AnomaliesForAgent returns drift anomalies specific to one agent.
func (d *Detector) AnomaliesForAgent(agentID, imageHash string) []DriftAnomaly {
	all := d.Anomalies(imageHash)
	var result []DriftAnomaly
	for _, a := range all {
		if a.AgentID == agentID {
			result = append(result, a)
		}
	}
	return result
}

// Images returns all tracked image hashes.
func (d *Detector) Images() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	images := make([]string, 0, len(d.fingerprints))
	for img := range d.fingerprints {
		images = append(images, img)
	}
	return images
}

// AgentCount returns the number of agents reporting for an image.
func (d *Detector) AgentCount(imageHash string) int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.fingerprints[imageHash])
}

// Clear removes all fingerprints for an image.
func (d *Detector) Clear(imageHash string) {
	d.mu.Lock()
	delete(d.fingerprints, imageHash)
	d.mu.Unlock()
}

// PruneStale removes fingerprints whose last update is older than cutoff,
// so agents that stop reporting drop out of the fleet comparison instead
// of skewing it (or lingering forever). Images left with no fingerprints
// are removed too.
func (d *Detector) PruneStale(cutoff time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for img, fps := range d.fingerprints {
		kept := make([]*BehaviorFingerprint, 0, len(fps))
		for _, fp := range fps {
			if fp.Timestamp.After(cutoff) {
				kept = append(kept, fp)
			}
		}
		if len(kept) == 0 {
			delete(d.fingerprints, img)
		} else {
			d.fingerprints[img] = kept
		}
	}
}

// SubmitFromCollector is a convenience that takes a snapshot from a collector and submits it.
func (d *Detector) SubmitFromCollector(fc *FingerprintCollector, agentID string) {
	fp := fc.Snapshot(agentID)
	if fp != nil {
		d.Submit(fp)
	}
}

// FleetStatus returns summary info per image.
type FleetStatus struct {
	ImageHash  string    `json:"image_hash"`
	AgentCount int       `json:"agent_count"`
	Anomalies  int       `json:"anomalies"`
	LastUpdate time.Time `json:"last_update"`
}

// Status returns fleet status across all images.
func (d *Detector) Status() []FleetStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var result []FleetStatus
	for img, fps := range d.fingerprints {
		var latest time.Time
		for _, fp := range fps {
			if fp.Timestamp.After(latest) {
				latest = fp.Timestamp
			}
		}
		result = append(result, FleetStatus{
			ImageHash:  img,
			AgentCount: len(fps),
			Anomalies:  len(d.Anomalies(img)),
			LastUpdate: latest,
		})
	}
	return result
}
