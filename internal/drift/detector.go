package drift

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"sync"
	"time"
)

// DefaultMaxPatterns is shared with heartbeat validation. Oversized reports
// must be rejected explicitly, not acknowledged and silently discarded.
const DefaultMaxPatterns = 1024

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
	Threshold         float64          // Z-score threshold (default: 3.0)
	TTL               time.Duration    // Local time since submission (default: 30 minutes)
	MaxFingerprints   int              // Across all images (default: 4096)
	MaxImages         int              // Default: 256
	MaxAgentsPerImage int              // Default: 256
	MaxPatterns       int              // Per fingerprint (default: 1024)
	Clock             func() time.Time // Monotonic, concurrency-safe clock
}

// Detector compares fingerprints from agents running the same image and finds outliers.
type Detector struct {
	mu           sync.RWMutex
	fingerprints map[string][]*BehaviorFingerprint // image hash → fingerprints
	threshold    float64
	config       DetectorConfig
	received     map[*BehaviorFingerprint]time.Time
}

// NewDetector creates a drift detector with the given config.
func NewDetector(cfg DetectorConfig) *Detector {
	threshold := cfg.Threshold
	if threshold <= 0 {
		threshold = 3.0
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 30 * time.Minute
	}
	if cfg.MaxFingerprints <= 0 {
		cfg.MaxFingerprints = 4096
	}
	if cfg.MaxImages <= 0 {
		cfg.MaxImages = 256
	}
	if cfg.MaxAgentsPerImage <= 0 {
		cfg.MaxAgentsPerImage = 256
	}
	if cfg.MaxPatterns <= 0 {
		cfg.MaxPatterns = DefaultMaxPatterns
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Detector{
		fingerprints: make(map[string][]*BehaviorFingerprint),
		threshold:    threshold,
		config:       cfg,
		received:     make(map[*BehaviorFingerprint]time.Time),
	}
}

// Validate applies the detector's actual admission limits without changing
// state, so transports can reject invalid reports before recording success.
func (d *Detector) Validate(fp *BehaviorFingerprint) error {
	if fp == nil {
		return errors.New("fingerprint is required")
	}
	if fp.AgentID == "" || len(fp.AgentID) > MaxKeyLength {
		return errors.New("fingerprint agent_id is required and must be at most 256 bytes")
	}
	if fp.ImageHash == "" || len(fp.ImageHash) > MaxKeyLength {
		return errors.New("fingerprint image_hash is required and must be at most 256 bytes")
	}
	if fp.Window < 0 {
		return errors.New("fingerprint window must not be negative")
	}
	if len(fp.Vectors) > d.config.MaxPatterns {
		return fmt.Errorf("fingerprint has too many patterns (maximum %d)", d.config.MaxPatterns)
	}
	for pattern, rate := range fp.Vectors {
		if len(pattern) > MaxKeyLength || math.IsNaN(rate) || math.IsInf(rate, 0) || rate < 0 {
			return errors.New("fingerprint patterns must be at most 256 bytes and rates must be finite and nonnegative")
		}
	}
	return nil
}

// Submit adds or updates a fingerprint, or reports why it was rejected.
func (d *Detector) Submit(fp *BehaviorFingerprint) error {
	if err := d.Validate(fp); err != nil {
		return err
	}
	copy := *fp
	copy.Vectors = maps.Clone(fp.Vectors)
	fp = &copy
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.config.Clock()
	d.prune(now)
	if fp.Timestamp.IsZero() || fp.Timestamp.After(now) {
		fp.Timestamp = now
	}
	// One current image per agent. Identity changes must not leave an old
	// fingerprint in its previous comparison group.
	for _, fps := range d.fingerprints {
		for _, existing := range fps {
			if existing.AgentID == fp.AgentID {
				d.remove(existing)
				break
			}
		}
	}
	for len(d.received) >= d.config.MaxFingerprints {
		d.remove(d.oldest(""))
	}
	if _, exists := d.fingerprints[fp.ImageHash]; !exists && len(d.fingerprints) >= d.config.MaxImages {
		// Drop the least recently active image as a group.
		oldImage := ""
		var oldest time.Time
		for image, fps := range d.fingerprints {
			var latest time.Time
			for _, item := range fps {
				if d.received[item].After(latest) {
					latest = d.received[item]
				}
			}
			if oldImage == "" || latest.Before(oldest) {
				oldImage, oldest = image, latest
			}
		}
		for _, item := range d.fingerprints[oldImage] {
			delete(d.received, item)
		}
		delete(d.fingerprints, oldImage)
	}
	if len(d.fingerprints[fp.ImageHash]) >= d.config.MaxAgentsPerImage {
		d.remove(d.oldest(fp.ImageHash))
	}
	d.fingerprints[fp.ImageHash] = append(d.fingerprints[fp.ImageHash], fp)
	d.received[fp] = now
	return nil
}

// Anomalies returns all detected drift anomalies for a given image.
func (d *Detector) Anomalies(imageHash string) []DriftAnomaly {
	return d.anomalies(d.snapshot()[imageHash])
}

// Compare only mature fingerprints with matching observation windows. Legacy
// fingerprints (Window == 0) compare only with other legacy fingerprints.
func (d *Detector) anomalies(fps []*BehaviorFingerprint) []DriftAnomaly {
	groups := make(map[time.Duration][]*BehaviorFingerprint)
	latest := make(map[time.Duration]time.Time)
	for _, fp := range fps {
		if !fp.Warmup && fp.Timestamp.After(latest[fp.Window]) {
			latest[fp.Window] = fp.Timestamp
		}
	}
	for _, fp := range fps {
		if fp.Warmup || (fp.Window > 0 && latest[fp.Window].Sub(fp.Timestamp) > fp.Window) {
			continue
		}
		groups[fp.Window] = append(groups[fp.Window], fp)
	}
	var result []DriftAnomaly
	for _, peers := range groups {
		result = append(result, d.compare(peers)...)
	}
	return result
}

func (d *Detector) compare(fps []*BehaviorFingerprint) []DriftAnomaly {
	if len(fps) < 2 {
		return nil
	}

	// Collect all unique patterns across all agents
	patterns := make(map[string]bool)
	positiveCounts := make(map[string]int)
	for _, fp := range fps {
		for pattern, rate := range fp.Vectors {
			patterns[pattern] = true
			if rate > 0 {
				positiveCounts[pattern]++
			}
		}
	}

	var anomalies []DriftAnomaly

	for pattern := range patterns {
		// Compute mean and std dev for this pattern
		var mean, m2 float64
		for i, fp := range fps {
			rate := fp.Vectors[pattern]
			delta := rate - mean
			mean += delta / float64(i+1)
			m2 += delta * (rate - mean)
		}
		stddev := math.Sqrt(max(0, m2/float64(len(fps))))

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
			if positiveCounts[pattern] == 1 && rate > 0 {
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
	fingerprints := d.snapshot()
	images := make([]string, 0, len(fingerprints))
	for img := range fingerprints {
		images = append(images, img)
	}
	return images
}

// AgentCount returns the number of agents reporting for an image.
func (d *Detector) AgentCount(imageHash string) int {
	return len(d.snapshot()[imageHash])
}

// Clear removes all fingerprints for an image.
func (d *Detector) Clear(imageHash string) {
	d.mu.Lock()
	for _, fp := range d.fingerprints[imageHash] {
		delete(d.received, fp)
	}
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
			} else {
				delete(d.received, fp)
			}
		}
		if len(kept) == 0 {
			delete(d.fingerprints, img)
		} else {
			d.fingerprints[img] = kept
		}
	}
}

// SubmitFromCollector submits an available snapshot and propagates admission
// errors. An agent with no snapshot is a successful no-op.
func (d *Detector) SubmitFromCollector(fc *FingerprintCollector, agentID string) error {
	fp := fc.Snapshot(agentID)
	if fp != nil {
		return d.Submit(fp)
	}
	return nil
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
	fingerprints := d.snapshot()
	var result []FleetStatus
	for img, fps := range fingerprints {
		var latest time.Time
		for _, fp := range fps {
			if fp.Timestamp.After(latest) {
				latest = fp.Timestamp
			}
		}
		result = append(result, FleetStatus{
			ImageHash:  img,
			AgentCount: len(fps),
			Anomalies:  len(d.anomalies(fps)),
			LastUpdate: latest,
		})
	}
	return result
}

// snapshot releases the lock before expensive comparisons. Submitted vectors
// are privately owned and immutable, so copying the slice is sufficient.
func (d *Detector) snapshot() map[string][]*BehaviorFingerprint {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.prune(d.config.Clock())
	result := make(map[string][]*BehaviorFingerprint, len(d.fingerprints))
	for image, fps := range d.fingerprints {
		result[image] = append([]*BehaviorFingerprint(nil), fps...)
	}
	return result
}

// Prune expires submissions by local receipt time, even if a peer supplies a
// future timestamp. Read APIs and Submit also apply this fallback.
func (d *Detector) Prune() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.prune(d.config.Clock())
}

func (d *Detector) prune(now time.Time) int {
	removed := 0
	for fp, received := range d.received {
		if now.Sub(received) >= d.config.TTL {
			d.remove(fp)
			removed++
		}
	}
	return removed
}

func (d *Detector) remove(fp *BehaviorFingerprint) {
	if fp == nil {
		return
	}
	fps := d.fingerprints[fp.ImageHash]
	for i, existing := range fps {
		if existing == fp {
			copy(fps[i:], fps[i+1:])
			fps[len(fps)-1] = nil
			fps = fps[:len(fps)-1]
			break
		}
	}
	delete(d.received, fp)
	if len(fps) == 0 {
		delete(d.fingerprints, fp.ImageHash)
	} else {
		d.fingerprints[fp.ImageHash] = fps
	}
}

func (d *Detector) oldest(image string) *BehaviorFingerprint {
	var oldest *BehaviorFingerprint
	for fp, received := range d.received {
		if image != "" && fp.ImageHash != image {
			continue
		}
		if oldest == nil || received.Before(d.received[oldest]) {
			oldest = fp
		}
	}
	return oldest
}
