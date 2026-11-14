package drift

import (
	"sync"
	"time"
)

// BehaviorFingerprint represents rates per minute over Window. Warmup marks a
// collector that has not yet observed a full window; it must not be compared
// with mature peers. ImageHash is only set when a real grouping identity exists.
type BehaviorFingerprint struct {
	AgentID   string             `json:"agent_id"`
	ImageHash string             `json:"image_hash"`
	Window    time.Duration      `json:"window"`
	Warmup    bool               `json:"warmup,omitempty"`
	Vectors   map[string]float64 `json:"vectors"`
	Timestamp time.Time          `json:"timestamp"`
}

const (
	rollingBuckets = 60
	// OverflowPattern retains rate when the pattern budget is full, without
	// retaining attacker-controlled names. It counts toward the limit.
	OverflowPattern = "__other__"
	MaxKeyLength    = 256
)

// CollectorConfig controls memory and expiry independently of event volume.
// Clock must be monotonic and safe for concurrent use.
type CollectorConfig struct {
	Window      time.Duration
	TTL         time.Duration
	MaxAgents   int
	MaxPatterns int
	Clock       func() time.Time
}

// FingerprintCollector uses a bounded rolling ring, not lifetime counters.
// Expiry has Window/60 granularity rounded up to a nanosecond (one bucket of
// undercount at the oldest boundary); rates always use the same full Window.
type FingerprintCollector struct {
	mu          sync.Mutex
	counters    map[string]*agentCounters
	config      CollectorConfig
	bucketWidth time.Duration
}

type timeBucket struct {
	start  time.Time
	counts map[string]uint64
}
type agentCounters struct {
	imageHash string
	counts    map[string]uint64
	buckets   [rollingBuckets + 1]timeBucket
	startedAt time.Time
	lastSeen  time.Time
}

func NewFingerprintCollector(window time.Duration) *FingerprintCollector {
	return NewFingerprintCollectorWithConfig(CollectorConfig{Window: window})
}

func NewFingerprintCollectorWithConfig(cfg CollectorConfig) *FingerprintCollector {
	if cfg.Window <= 0 {
		cfg.Window = 10 * time.Minute
	}
	if cfg.TTL <= 0 {
		cfg.TTL = max(30*time.Minute, 2*cfg.Window)
	}
	if cfg.MaxAgents <= 0 {
		cfg.MaxAgents = 256
	}
	if cfg.MaxPatterns <= 0 {
		cfg.MaxPatterns = 1024
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &FingerprintCollector{
		counters:    make(map[string]*agentCounters),
		config:      cfg,
		bucketWidth: (cfg.Window-1)/rollingBuckets + 1,
	}
}

// Record observes a pattern. An image change starts a new observation window;
// behavior from two image identities is never blended. Empty image identity is
// permitted for local collection but must not be used for fleet comparison.
func (fc *FingerprintCollector) Record(agentID, imageHash, pattern string) {
	if agentID == "" || pattern == "" || len(agentID) > MaxKeyLength || len(imageHash) > MaxKeyLength || len(pattern) > MaxKeyLength {
		return
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	now := fc.config.Clock()
	fc.prune(now)
	ac := fc.counters[agentID]
	if ac == nil || ac.imageHash != imageHash {
		if ac == nil && len(fc.counters) >= fc.config.MaxAgents {
			fc.evictOldest()
		}
		ac = &agentCounters{imageHash: imageHash, counts: make(map[string]uint64), startedAt: now}
		fc.counters[agentID] = ac
	}
	fc.expire(ac, now)
	ac.lastSeen = now
	if _, exists := ac.counts[pattern]; !exists && len(ac.counts) >= fc.config.MaxPatterns-1 {
		pattern = OverflowPattern
	}
	start := now.Truncate(fc.bucketWidth)
	index := (start.UnixNano() / int64(fc.bucketWidth)) % int64(len(ac.buckets))
	if index < 0 {
		index += int64(len(ac.buckets))
	}
	bucket := &ac.buckets[index]
	if bucket.counts == nil || !bucket.start.Equal(start) {
		fc.clearBucket(ac, bucket)
		bucket.start = start
		bucket.counts = make(map[string]uint64)
	}
	bucket.counts[pattern]++
	ac.counts[pattern]++
}

// Snapshot returns an owned vector. Reading it neither resets the rolling
// window nor keeps idle agents alive. Warmup snapshots are diagnostic only.
func (fc *FingerprintCollector) Snapshot(agentID string) *BehaviorFingerprint {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	now := fc.config.Clock()
	fc.prune(now)
	ac := fc.counters[agentID]
	if ac == nil {
		return nil
	}
	fc.expire(ac, now)
	vectors := make(map[string]float64, len(ac.counts))
	for pattern, count := range ac.counts {
		vectors[pattern] = float64(count) / fc.config.Window.Minutes()
	}
	return &BehaviorFingerprint{
		AgentID: agentID, ImageHash: ac.imageHash, Window: fc.config.Window,
		Warmup: now.Sub(ac.startedAt) < fc.config.Window, Vectors: vectors, Timestamp: now,
	}
}

func (fc *FingerprintCollector) clearBucket(ac *agentCounters, bucket *timeBucket) {
	for pattern, count := range bucket.counts {
		ac.counts[pattern] -= count
		if ac.counts[pattern] == 0 {
			delete(ac.counts, pattern)
		}
	}
	*bucket = timeBucket{}
}

func (fc *FingerprintCollector) expire(ac *agentCounters, now time.Time) {
	cutoff := now.Add(-fc.config.Window)
	for i := range ac.buckets {
		if !ac.buckets[i].start.After(cutoff) {
			fc.clearBucket(ac, &ac.buckets[i])
		}
	}
}

// Prune removes agents idle for TTL. Owners may call this periodically during
// silence; Record and Snapshot also apply expiry without spawning goroutines.
func (fc *FingerprintCollector) Prune() int {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.prune(fc.config.Clock())
}

func (fc *FingerprintCollector) prune(now time.Time) int {
	removed := 0
	for id, ac := range fc.counters {
		if now.Sub(ac.lastSeen) >= fc.config.TTL {
			delete(fc.counters, id)
			removed++
		}
	}
	return removed
}

func (fc *FingerprintCollector) evictOldest() {
	var oldest string
	for id, ac := range fc.counters {
		if oldest == "" || ac.lastSeen.Before(fc.counters[oldest].lastSeen) {
			oldest = id
		}
	}
	delete(fc.counters, oldest)
}

func (fc *FingerprintCollector) Reset(agentID string) {
	fc.mu.Lock()
	delete(fc.counters, agentID)
	fc.mu.Unlock()
}
