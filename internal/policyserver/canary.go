package policyserver

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

const (
	DefaultCanarySampleWindow = 10 * time.Minute
	MaxCanarySampleWindow     = 24 * time.Hour
	canaryWindowBuckets       = 128
)

// CanaryConfig controls analysis of locally attributed canary decisions. It is
// not a fleet telemetry or activation-acknowledgement contract.
type CanaryConfig struct {
	MaxDenyRateDelta  float64       `json:"max_deny_rate_delta"`
	ObservationWindow time.Duration `json:"observation_window"`
	MinSampleSize     int           `json:"min_sample_size"`
	AutoRollback      bool          `json:"auto_rollback"`
	// SampleWindow bounds sample retention. Zero selects DefaultCanarySampleWindow.
	SampleWindow time.Duration `json:"sample_window,omitempty"`
}

// Validate rejects settings that could produce an invalid or vacuous verdict.
// An ObservationWindow of zero explicitly permits immediate evaluation.
func (cfg CanaryConfig) Validate() error {
	if math.IsNaN(cfg.MaxDenyRateDelta) || math.IsInf(cfg.MaxDenyRateDelta, 0) || cfg.MaxDenyRateDelta < 0 || cfg.MaxDenyRateDelta > 1 {
		return fmt.Errorf("max deny rate delta must be finite and between 0 and 1")
	}
	if cfg.MinSampleSize <= 0 {
		return fmt.Errorf("minimum sample size must be positive")
	}
	window := cfg.sampleWindow()
	if window <= 0 || window > MaxCanarySampleWindow {
		return fmt.Errorf("sample window must be positive and at most %s", MaxCanarySampleWindow)
	}
	if cfg.ObservationWindow < 0 || cfg.ObservationWindow > window {
		return fmt.Errorf("observation window must be between zero and the sample window")
	}
	return nil
}

func (cfg CanaryConfig) sampleWindow() time.Duration {
	if cfg.SampleWindow == 0 {
		return DefaultCanarySampleWindow
	}
	return cfg.SampleWindow
}

// CanaryMetrics contains measurements for the retained rolling window.
type CanaryMetrics struct {
	BaselineDenyRate float64       `json:"baseline_deny_rate"`
	CanaryDenyRate   float64       `json:"canary_deny_rate"`
	BaselineSamples  int           `json:"baseline_samples"`
	CanarySamples    int           `json:"canary_samples"`
	ObservedFor      time.Duration `json:"observed_for"`
	Verdict          string        `json:"verdict"` // pending, healthy, degraded, rolled-back
	// Rolled-back means AbortRollout succeeded, not that the fleet acknowledged it.
	// RollbackError describes the last failed abort attempt, if any.
	RollbackError string `json:"rollback_error,omitempty"`
	// SampleOverflow makes the sample counts incomplete and prevents a health verdict.
	SampleOverflow bool `json:"sample_overflow,omitempty"`
}

type canaryRolloutAborter interface {
	AbortRollout(string) error
}

// CanaryAnalyzer monitors locally attributed canary vs baseline deny rates.
// No fleet telemetry or automatic evaluation loop is wired to this analyzer.
type CanaryAnalyzer struct {
	mu       sync.Mutex
	configs  map[string]*CanaryConfig
	counters map[string]*canaryCounters
	rollouts canaryRolloutAborter
	clock    func() time.Time
}

type canaryBucket struct {
	start         time.Time
	used          bool
	baselineTotal int
	baselineDeny  int
	canaryTotal   int
	canaryDeny    int
	overflow      bool
}

type canaryCounters struct {
	buckets       [canaryWindowBuckets]canaryBucket
	epoch         time.Time
	lastSeen      time.Time
	startedAt     time.Time
	observing     bool
	rolledBack    bool
	rollbackError string
}

// NewCanaryAnalyzer creates an analyzer attached to the given rollout manager.
// A nil manager supports observation only; abort attempts report an error.
func NewCanaryAnalyzer(rm *RolloutManager) *CanaryAnalyzer {
	ca := &CanaryAnalyzer{
		configs:  make(map[string]*CanaryConfig),
		counters: make(map[string]*canaryCounters),
		clock:    time.Now,
	}
	if rm != nil {
		ca.rollouts = rm
	}
	return ca
}

// Configure validates settings before changing state. Identical configurations
// preserve samples; changes start a new observation window. A successful abort
// remains latched until Reset. Decisions before Configure are ignored.
func (ca *CanaryAnalyzer) Configure(rolloutID string, cfg CanaryConfig) error {
	if strings.TrimSpace(rolloutID) == "" {
		return fmt.Errorf("rollout ID is required")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	cfg.SampleWindow = cfg.sampleWindow()
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if old, ok := ca.configs[rolloutID]; ok && *old == cfg {
		return nil
	}
	now := ca.clock()
	c := &canaryCounters{epoch: now, lastSeen: now}
	if old := ca.counters[rolloutID]; old != nil {
		c.rolledBack = old.rolledBack
	}
	ca.configs[rolloutID] = &cfg
	ca.counters[rolloutID] = c
	return nil
}

// RecordDecision records a trusted, locally attributed decision. This legacy
// boolean cohort API must not be used to ingest unverified fleet telemetry.
// Unknown rollout IDs are ignored rather than allocating unbounded state.
func (ca *CanaryAnalyzer) RecordDecision(rolloutID string, isCanary bool, denied bool) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	c, ok := ca.counters[rolloutID]
	if !ok {
		return
	}
	cfg := ca.configs[rolloutID]
	now := c.advance(ca.clock(), cfg.SampleWindow)
	if !c.observing {
		c.startedAt, c.observing = now, true
	}
	// Ceiling division avoids retaining samples older than SampleWindow and
	// bounds memory even at arbitrarily high event rates. Whole buckets expire
	// conservatively, at most one bucket width early.
	width := (cfg.SampleWindow-1)/canaryWindowBuckets + 1
	index := now.Sub(c.epoch) / width
	start := c.epoch.Add(index * width)
	b := &c.buckets[index%canaryWindowBuckets]
	if !b.used || !b.start.Equal(start) {
		*b = canaryBucket{start: start, used: true}
	}
	total, deny := &b.baselineTotal, &b.baselineDeny
	if isCanary {
		total, deny = &b.canaryTotal, &b.canaryDeny
	}
	if *total == int(^uint(0)>>1) {
		b.overflow = true
		return
	}
	(*total)++
	if denied {
		(*deny)++
	}
}

// Evaluate checks health and, only when explicitly configured, attempts abort.
// The boolean is true only for the call whose AbortRollout returned nil. An
// abort failure leaves the verdict degraded and may be retried on a later call.
func (ca *CanaryAnalyzer) Evaluate(rolloutID string) (CanaryMetrics, bool) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	cfg, ok := ca.configs[rolloutID]
	if !ok {
		return CanaryMetrics{Verdict: "pending"}, false
	}
	c := ca.counters[rolloutID]
	c.advance(ca.clock(), cfg.SampleWindow)
	m := ca.buildMetrics(c, cfg.SampleWindow)
	if c.rolledBack || m.SampleOverflow || m.CanarySamples < cfg.MinSampleSize || m.BaselineSamples < cfg.MinSampleSize || m.ObservedFor < cfg.ObservationWindow {
		return m, false
	}
	if m.CanaryDenyRate-m.BaselineDenyRate <= cfg.MaxDenyRateDelta {
		m.Verdict = "healthy"
		return m, false
	}
	m.Verdict = "degraded"
	if !cfg.AutoRollback {
		return m, false
	}
	if ca.rollouts == nil {
		c.rollbackError = "rollout manager is unavailable"
	} else if err := ca.rollouts.AbortRollout(rolloutID); err != nil {
		c.rollbackError = err.Error()
	} else {
		c.rolledBack = true
		c.rollbackError = ""
		m.Verdict = "rolled-back"
		m.RollbackError = ""
		return m, true
	}
	m.RollbackError = c.rollbackError
	return m, false
}

// Metrics returns current metrics without triggering evaluation or rollback.
func (ca *CanaryAnalyzer) Metrics(rolloutID string) CanaryMetrics {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	c, ok := ca.counters[rolloutID]
	if !ok {
		return CanaryMetrics{Verdict: "pending"}
	}
	window := ca.configs[rolloutID].SampleWindow
	c.advance(ca.clock(), window)
	return ca.buildMetrics(c, window)
}

// Reset clears configuration, observation state, and the successful-abort latch.
func (ca *CanaryAnalyzer) Reset(rolloutID string) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	delete(ca.configs, rolloutID)
	delete(ca.counters, rolloutID)
}

func (c *canaryCounters) advance(now time.Time, window time.Duration) time.Time {
	// Clamp backwards clocks so expired samples cannot reappear and elapsed
	// durations and bucket indices cannot become negative.
	if now.Before(c.lastSeen) {
		now = c.lastSeen
	}
	c.lastSeen = now
	cutoff := now.Add(-window)
	anySamples := false
	for i := range c.buckets {
		b := &c.buckets[i]
		if b.used && !b.start.After(cutoff) {
			*b = canaryBucket{}
		}
		anySamples = anySamples || b.used
	}
	if !anySamples {
		c.observing = false
		c.epoch = now
	}
	return now
}

func (ca *CanaryAnalyzer) buildMetrics(c *canaryCounters, window time.Duration) CanaryMetrics {
	m := CanaryMetrics{Verdict: "pending", RollbackError: c.rollbackError}
	if c.rolledBack {
		m.Verdict = "rolled-back"
	}
	if c.observing {
		m.ObservedFor = min(c.lastSeen.Sub(c.startedAt), window)
	}
	baselineDeny, canaryDeny := 0, 0
	maxInt := int(^uint(0) >> 1)
	for _, b := range c.buckets {
		if !b.used {
			continue
		}
		if b.overflow || b.baselineTotal > maxInt-m.BaselineSamples || b.canaryTotal > maxInt-m.CanarySamples {
			m.SampleOverflow = true
			// Do not publish partial counts as though they were complete.
			m.BaselineSamples, m.CanarySamples = 0, 0
			return m
		}
		m.BaselineSamples += b.baselineTotal
		m.CanarySamples += b.canaryTotal
		baselineDeny += b.baselineDeny
		canaryDeny += b.canaryDeny
	}
	if m.BaselineSamples > 0 {
		m.BaselineDenyRate = float64(baselineDeny) / float64(m.BaselineSamples)
	}
	if m.CanarySamples > 0 {
		m.CanaryDenyRate = float64(canaryDeny) / float64(m.CanarySamples)
	}
	return m
}
