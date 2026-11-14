package policyserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/telemetry"
)

const telemetryBuckets = 128

var ErrTelemetryFence = errors.New("telemetry session, assignment or acknowledgement is not eligible")

// TelemetryConfig is intentionally independent of the legacy int/event analyzer.
// There is no AutoRollback field or actuator in this report-only path.
type TelemetryConfig struct {
	Window       time.Duration `json:"window"`
	MaxGap       time.Duration `json:"max_gap"`
	Observation  time.Duration `json:"observation"`
	Lease        time.Duration `json:"lease"`
	MinSamples   uint64        `json:"min_samples"`
	MinSources   int           `json:"min_sources"`
	MaxDenyDelta float64       `json:"max_deny_delta"`
	MaxSources   int           `json:"max_sources"`
	MaxRollouts  int           `json:"max_rollouts"`
}

func (c TelemetryConfig) Validate() error {
	if c.Window < time.Second || c.Window > 24*time.Hour || c.MaxGap <= 0 || c.MaxGap > c.Window || c.Observation <= 0 || c.Observation > c.Window || c.Lease < c.MaxGap || c.Lease > 24*time.Hour || c.MinSamples == 0 || c.MinSources <= 0 || c.MaxSources < c.MinSources || c.MaxSources > 10000 || c.MaxRollouts <= 0 || c.MaxRollouts > 1024 || math.IsNaN(c.MaxDenyDelta) || math.IsInf(c.MaxDenyDelta, 0) || c.MaxDenyDelta < 0 || c.MaxDenyDelta > 1 {
		return errors.New("invalid or unbounded telemetry configuration")
	}
	return nil
}

type telemetryBinding struct {
	Revision      telemetry.Revision `json:"revision"`
	RolloutID     string             `json:"rollout_id"`
	Generation    string             `json:"generation"`
	Canary        bool               `json:"canary"`
	AssignmentKey string             `json:"assignment_key"`
}

type telemetryBucket struct {
	Start  time.Time `json:"start"`
	First  time.Time `json:"first"`
	Total  uint64    `json:"total"`
	Denied uint64    `json:"denied"`
	Bad    bool      `json:"bad"`
}

// Each authenticated source owns a fixed ring, so independent-source coverage
// requires no per-event sets and cannot be forged with agent IDs in a payload.
type telemetrySource struct {
	Session        telemetry.Session                 `json:"session"`
	Expires        time.Time                         `json:"expires"`
	NextAssignment uint64                            `json:"next_assignment"`
	Desired        *telemetryBinding                 `json:"desired,omitempty"`
	Active         *telemetryBinding                 `json:"active,omitempty"`
	Cursor         *telemetry.Snapshot               `json:"cursor,omitempty"`
	Receipt        time.Time                         `json:"receipt"`
	Suspended      bool                              `json:"suspended"`
	Buckets        [telemetryBuckets]telemetryBucket `json:"buckets"`
}

type telemetryState struct {
	Format   int                         `json:"format"`
	Epoch    string                      `json:"epoch"`
	Config   TelemetryConfig             `json:"config"`
	Rollouts map[string]string           `json:"rollouts"`
	Domains  map[string]string           `json:"domains"`
	Rosters  map[string]map[string]bool  `json:"rosters"`
	Sources  map[string]*telemetrySource `json:"sources"`
}

// TelemetryStore is a separate bounded snapshot domain, avoiding changes to the
// fleet/activation schema. Cursor, immutable attribution and buckets commit in
// ONE snapshot. Restart rotates the epoch and drops all evidence/leases; it
// never restores one side of the cursor/window pair. Configurations survive.
type TelemetryStore struct {
	mu     sync.Mutex
	state  telemetryState
	clock  func() time.Time
	path   string
	lock   *os.File
	closed bool
	fault  error
	// persist is injectable for transaction-failure tests; called before publish.
	persist func([]byte) error
}

func NewTelemetryStore(cfg TelemetryConfig) (*TelemetryStore, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	epoch, err := telemetry.NewID()
	if err != nil {
		return nil, err
	}
	anchor := time.Now()
	// Epoch-local monotonic receipt timeline survives serialization of cursors:
	// its wall representation advances only by monotonic elapsed time. Epochs
	// are never restored, so wall-clock corrections cannot stretch a window.
	clock := func() time.Time { return anchor.Add(time.Since(anchor)) }
	return &TelemetryStore{state: telemetryState{Format: 1, Epoch: epoch, Config: cfg, Rollouts: map[string]string{}, Domains: map[string]string{}, Rosters: map[string]map[string]bool{}, Sources: map[string]*telemetrySource{}}, clock: clock}, nil
}

// OpenTelemetryStore requires a private administrator-owned directory and a
// single writer. Every open creates a new analysis epoch (report-only warm-up).
func OpenTelemetryStore(path string, cfg TelemetryConfig) (*TelemetryStore, error) {
	if path == "" {
		return nil, errors.New("telemetry state path required")
	}
	t, err := NewTelemetryStore(cfg)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	lock, err := lockStateFile(abs + ".lock")
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*TelemetryStore, error) { _ = unlockStateFile(lock); return nil, err }
	t.path, t.lock = abs, lock
	if info, err := os.Lstat(abs); err == nil && !info.Mode().IsRegular() {
		return fail(errors.New("telemetry state must be a regular file"))
	}
	f, err := os.Open(abs)
	if err == nil {
		data, readErr := io.ReadAll(io.LimitReader(f, 64<<20+1))
		_ = f.Close()
		if readErr != nil {
			return fail(readErr)
		}
		if len(data) > 64<<20 {
			return fail(ErrStateLimit)
		}
		var old telemetryState
		if err := json.Unmarshal(data, &old); err != nil {
			return fail(err)
		}
		if old.Format != 1 || old.Config.Validate() != nil || len(old.Rollouts) > cfg.MaxRollouts || len(old.Sources) > cfg.MaxSources {
			return fail(errors.New("invalid telemetry state"))
		}
		// New configuration also requires a fresh epoch and full warm-up.
		for id, generation := range old.Rollouts {
			if !telemetry.ValidID(id) || !telemetry.ValidID(generation) {
				return fail(errors.New("invalid telemetry rollout"))
			}
			t.state.Rollouts[id] = generation
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	}
	t.persist = t.write
	data, _ := json.Marshal(t.state)
	if err := t.persist(data); err != nil {
		return fail(err)
	}
	return t, nil
}

// configureDomain turns a server-observed assignment domain into a fresh,
// non-reusable generation. A -> B -> A cannot resurrect generation A. The full
// registered eligible roster, including offline/unleased agents, is retained
// independently of successful telemetry reporters.
func (t *TelemetryStore) configureDomain(id, domain string, roster map[string]bool) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state.Domains[id] == domain && t.state.Rollouts[id] != "" {
		return t.state.Rollouts[id], nil
	}
	if len(roster) > t.state.Config.MaxSources {
		return "", ErrStateLimit
	}
	for agent := range roster {
		if !telemetry.ValidID(agent) {
			return "", ErrTelemetryFence
		}
	}
	generation, err := telemetry.NewID()
	if err != nil {
		return "", err
	}
	err = t.mutate(func(s *telemetryState) error {
		if _, ok := s.Rollouts[id]; !ok && len(s.Rollouts) >= s.Config.MaxRollouts {
			return ErrStateLimit
		}
		s.Rollouts[id], s.Domains[id], s.Rosters[id] = generation, domain, roster
		for _, src := range s.Sources {
			if src.Active != nil && src.Active.RolloutID == id {
				src.Buckets = [telemetryBuckets]telemetryBucket{}
			}
		}
		return nil
	})
	return generation, err
}

func (t *TelemetryStore) write(data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(t.path), ".telemetry-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, t.path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(t.path))
	if err == nil {
		err = dir.Sync()
		_ = dir.Close()
	}
	if err != nil {
		t.fault = err
	} // ambiguous commit poisons this writer
	return err
}

func (t *TelemetryStore) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	if t.lock != nil {
		return unlockStateFile(t.lock)
	}
	return nil
}

func (t *TelemetryStore) mutate(fn func(*telemetryState) error) error {
	if t.closed {
		return ErrStoreClosed
	}
	if t.fault != nil {
		return fmt.Errorf("%w: %v", ErrStatePersistence, t.fault)
	}
	// Bounded copy-on-write: no cursor is visible before its durable aggregate.
	data, err := json.Marshal(t.state)
	if err != nil {
		return err
	}
	var next telemetryState
	if err := json.Unmarshal(data, &next); err != nil {
		return err
	}
	if err := fn(&next); err != nil {
		return err
	}
	data, err = json.Marshal(next)
	if err != nil {
		return err
	}
	if len(data) > 64<<20 {
		return ErrStateLimit
	}
	if t.persist != nil {
		if err := t.persist(data); err != nil {
			return fmt.Errorf("%w: %v", ErrStatePersistence, err)
		}
	}
	t.state = next
	return nil
}

// ConfigureGeneration is a trusted control-plane API. Changing a rollout
// generation destroys its old evidence, never moves it into a new cohort.
func (t *TelemetryStore) ConfigureGeneration(id, generation string) error {
	if !telemetry.ValidID(id) || !telemetry.ValidID(generation) {
		return ErrTelemetryFence
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state.Rollouts[id] == generation {
		return nil
	}
	return t.mutate(func(s *telemetryState) error {
		if _, ok := s.Rollouts[id]; !ok && len(s.Rollouts) >= s.Config.MaxRollouts {
			return ErrStateLimit
		}
		s.Rollouts[id] = generation
		for _, src := range s.Sources {
			if src.Active != nil && src.Active.RolloutID == id {
				src.Buckets = [telemetryBuckets]telemetryBucket{}
			}
		}
		return nil
	})
}

func (t *TelemetryStore) RemoveRollout(id string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.mutate(func(s *telemetryState) error {
		delete(s.Rollouts, id)
		delete(s.Domains, id)
		delete(s.Rosters, id)
		for _, src := range s.Sources {
			if src.Active != nil && src.Active.RolloutID == id {
				src.Active = nil // preserve session high-water across terminal cleanup
				src.Buckets = [telemetryBuckets]telemetryBucket{}
			}
			if src.Desired != nil && src.Desired.RolloutID == id {
				src.Desired = nil
			}
		}
		return nil
	})
}

// AuthorizeSession replaces the only live incarnation for this authenticated
// agent. Re-registration does NOT invoke this method. No agent ID is taken from
// a telemetry payload. Expired slots can be explicitly replaced, never replayed.
func (t *TelemetryStore) AuthorizeSession(agent string) (telemetry.Session, error) {
	if !telemetry.ValidID(agent) {
		return telemetry.Session{}, ErrTelemetryFence
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	id, err := telemetry.NewID()
	if err != nil {
		return telemetry.Session{}, err
	}
	lease := telemetry.Session{Epoch: t.state.Epoch, SessionID: id}
	err = t.mutate(func(s *telemetryState) error {
		if s.Sources[agent] == nil && len(s.Sources) >= s.Config.MaxSources {
			for key, source := range s.Sources {
				if !t.clock().Before(source.Expires) {
					delete(s.Sources, key)
				}
			}
			if len(s.Sources) >= s.Config.MaxSources {
				return ErrStateLimit
			}
		}
		s.Sources[agent] = &telemetrySource{Session: lease, Expires: t.clock().Add(s.Config.Lease)}
		return nil
	})
	return lease, err
}

func liveTelemetrySource(s *telemetryState, agent string, session telemetry.Session, now time.Time) (*telemetrySource, error) {
	src := s.Sources[agent]
	if session.Validate() != nil || session.Epoch != s.Epoch || src == nil || src.Session != session || !now.Before(src.Expires) {
		return nil, ErrTelemetryFence
	}
	return src, nil
}

// issueAssignment receives only server-resolved historical cohort evidence.
func (t *TelemetryStore) issueAssignment(agent string, session telemetry.Session, b telemetryBinding) (*telemetry.Assignment, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var assignment telemetry.Assignment
	err := t.mutate(func(s *telemetryState) error {
		src, err := liveTelemetrySource(s, agent, session, t.clock())
		if err != nil {
			return err
		}
		if s.Rollouts[b.RolloutID] != b.Generation {
			return ErrTelemetryFence
		}
		if src.Desired == nil || src.Desired.AssignmentKey != b.AssignmentKey || src.Desired.Generation != b.Generation {
			if src.NextAssignment == math.MaxUint64 {
				return ErrTelemetryFence
			}
			src.NextAssignment++
			b.Revision.AssignmentRevision = src.NextAssignment
			src.Desired = &b
		}
		assignment = telemetry.Assignment{Session: session, AssignmentRevision: src.Desired.Revision.AssignmentRevision}
		return nil
	})
	return &assignment, err
}

type TelemetryIngestResult struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	Total  uint64 `json:"total"`
	Denied uint64 `json:"denied"`
}

// observeAcknowledgement invalidates evidence as soon as a durable heartbeat
// reports an activation failure or a different artifact, even without a new
// telemetry snapshot. Recovery rebaselines rather than counting that interval.
func (t *TelemetryStore) observeAcknowledgement(req HeartbeatRequest) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	src := t.state.Sources[req.AgentID]
	if src == nil || src.Active == nil || src.Suspended {
		return nil
	}
	r := src.Active.Revision
	if req.ActivationError == "" && req.PolicyID == r.PolicyID && req.PolicyVersion == r.PolicyVersion && req.PolicyHash == r.PolicyHash {
		return nil
	}
	return t.mutate(func(s *telemetryState) error {
		src := s.Sources[req.AgentID]
		src.Suspended = true
		src.Buckets = [telemetryBuckets]telemetryBucket{}
		return nil
	})
}

// ingest requires a separately recorded durable activation acknowledgement.
// The caller holds the fleet read lock until this atomic transaction finishes.
func (t *TelemetryStore) ingest(agent string, ack *Agent, report telemetry.Snapshot) (TelemetryIngestResult, error) {
	if err := report.Validate(); err != nil {
		return TelemetryIngestResult{}, err
	}
	if ack == nil || ack.ID != agent || ack.ActivationError != "" || ack.PolicyID != report.Revision.PolicyID || ack.PolicyVersion != report.Revision.PolicyVersion || ack.PolicyHash != report.Revision.PolicyHash {
		return TelemetryIngestResult{}, ErrTelemetryFence
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	result := TelemetryIngestResult{}
	now := t.clock()
	err := t.mutate(func(s *telemetryState) error {
		src, err := liveTelemetrySource(s, agent, report.Session, now)
		if err != nil {
			return err
		}
		if ack.LastHeartbeat.After(now) || now.Sub(ack.LastHeartbeat) > s.Config.MaxGap {
			return ErrTelemetryFence
		}
		if src.Cursor != nil {
			if report.Sequence < src.Cursor.Sequence {
				result.Status = "stale"
				return nil
			}
			if report.Sequence == src.Cursor.Sequence {
				if report != *src.Cursor {
					return errors.New("conflicting telemetry sequence")
				}
				result.Status = "duplicate"
				return nil
			}
			// Saturation cannot wrap back into a valid source incarnation.
			if src.Cursor.Sequence == math.MaxUint64 {
				return ErrTelemetryFence
			}
		}
		if now.Before(src.Receipt) {
			return errors.New("telemetry receipt clock reversed; new epoch required")
		}
		// A new activation can only acknowledge the current server-issued
		// assignment, once. Old A -> B -> A identities cannot switch back.
		newActivation := src.Active == nil || src.Active.Revision != report.Revision
		if newActivation {
			b := src.Desired
			if b == nil || b.Revision.AssignmentRevision != report.Revision.AssignmentRevision || b.Revision.PolicyID != report.Revision.PolicyID || b.Revision.PolicyVersion != report.Revision.PolicyVersion || b.Revision.PolicyHash != report.Revision.PolicyHash || (src.Active != nil && report.Revision.AssignmentRevision <= src.Active.Revision.AssignmentRevision) {
				return ErrTelemetryFence
			}
			if src.Active != nil && src.Active.Revision.ActivationID == report.Revision.ActivationID {
				return ErrTelemetryFence
			}
			active := *b
			active.Revision = report.Revision
			src.Active = &active
			src.Buckets = [telemetryBuckets]telemetryBucket{}
		}
		previous, receipt := src.Cursor, src.Receipt
		wasSuspended := src.Suspended
		src.Suspended = false
		src.Cursor, src.Receipt = &report, now
		result.Status = "bootstrap"
		if previous == nil || newActivation {
			return nil
		}
		if report.Total < previous.Total || report.Denied < previous.Denied || report.Errors < previous.Errors || report.Excluded < previous.Excluded || report.Lost < previous.Lost || (previous.Overflow && !report.Overflow) {
			return errors.New("telemetry counters decreased")
		}
		delta, denied := report.Total-previous.Total, report.Denied-previous.Denied
		if denied > delta {
			return errors.New("impossible telemetry deny delta")
		}
		if wasSuspended {
			return nil
		}
		result.Status = "cursor-only"
		if s.Rollouts[src.Active.RolloutID] != src.Active.Generation {
			result.Reason = "historical-generation"
			return nil
		}
		if now.Sub(receipt) > s.Config.MaxGap || now.Sub(receipt) >= s.Config.Window {
			result.Reason = "reporting-gap"
			return nil
		}
		// Place the delta at the START of its receipt interval, so a whole
		// bucket expires early, never keeping any part of an old interval.
		width := (s.Config.Window-1)/telemetryBuckets + 1
		start := receipt.Truncate(width)
		index := uint64(start.UnixNano()/int64(width)) % telemetryBuckets
		bucket := &src.Buckets[index]
		if !bucket.Start.Equal(start) {
			*bucket = telemetryBucket{Start: start}
		}
		if report.Overflow || report.Errors != previous.Errors || report.Excluded != previous.Excluded || report.Lost != previous.Lost {
			bucket.Bad = true
			result.Reason = "unreliable-population"
			return nil
		}
		if math.MaxUint64-bucket.Total < delta || math.MaxUint64-bucket.Denied < denied {
			bucket.Bad = true
			result.Reason = "overflow"
			return nil
		}
		bucket.Total += delta
		bucket.Denied += denied
		if delta > 0 && bucket.First.IsZero() {
			bucket.First = now
		}
		result.Status, result.Total, result.Denied = "accepted", delta, denied
		return nil
	})
	return result, err
}

type TelemetryCohortReport struct {
	Total    uint64  `json:"total"`
	Denied   uint64  `json:"denied"`
	Sources  int     `json:"sources"`
	Assigned int     `json:"assigned"`
	DenyRate float64 `json:"deny_rate"`
}

type TelemetryReport struct {
	RolloutID       string                `json:"rollout_id"`
	Generation      string                `json:"generation"`
	Population      string                `json:"population"`
	Epoch           string                `json:"epoch"`
	Baseline        TelemetryCohortReport `json:"baseline"`
	Canary          TelemetryCohortReport `json:"canary"`
	ObservedFor     time.Duration         `json:"observed_for"`
	MaxReportingGap time.Duration         `json:"max_reporting_gap"`
	Verdict         string                `json:"verdict"`
	Reason          string                `json:"reason,omitempty"`
	ReportOnly      bool                  `json:"report_only"`
}

// Report is an aggregate analyzer, NOT a loop over RecordDecision or an abort
// callback. Checked uint64 sums never pass through the legacy int counters.
func (t *TelemetryStore) Report(id string) TelemetryReport {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, now := &t.state, t.clock()
	r := TelemetryReport{RolloutID: id, Generation: s.Rollouts[id], Population: telemetry.Population, Epoch: s.Epoch, Verdict: "pending", Reason: "insufficient-fresh-coverage", ReportOnly: true, MaxReportingGap: s.Config.MaxGap}
	if t.closed || t.fault != nil || r.Generation == "" {
		r.Reason = "unavailable-generation"
		return r
	}
	var baselineFirst, canaryFirst time.Time
	bad := false
	if roster := s.Rosters[id]; roster != nil {
		for _, canary := range roster {
			if canary {
				r.Canary.Assigned++
			} else {
				r.Baseline.Assigned++
			}
		}
	}
	for _, src := range s.Sources {
		if b := src.Desired; s.Rosters[id] == nil && b != nil && b.RolloutID == id && b.Generation == r.Generation {
			cohort := &r.Baseline
			if b.Canary {
				cohort = &r.Canary
			}
			cohort.Assigned++
		}
		b := src.Active
		if src.Suspended || b == nil || b.RolloutID != id || b.Generation != r.Generation || !now.Before(src.Expires) || now.Before(src.Receipt) || now.Sub(src.Receipt) > s.Config.MaxGap {
			continue
		}
		cohort := &r.Baseline
		first := &baselineFirst
		if b.Canary {
			cohort = &r.Canary
			first = &canaryFirst
		}
		has := false
		for _, bucket := range src.Buckets {
			if bucket.Start.IsZero() || now.Before(bucket.Start) || now.Sub(bucket.Start) >= s.Config.Window {
				continue
			}
			bad = bad || bucket.Bad
			if math.MaxUint64-cohort.Total < bucket.Total || math.MaxUint64-cohort.Denied < bucket.Denied {
				bad = true
				continue
			}
			cohort.Total += bucket.Total
			cohort.Denied += bucket.Denied
			if bucket.Total > 0 {
				has = true
				if first.IsZero() || bucket.First.Before(*first) {
					*first = bucket.First
				}
			}
		}
		if has {
			cohort.Sources++
		}
	}
	if bad {
		r.Baseline.Total, r.Baseline.Denied, r.Canary.Total, r.Canary.Denied = 0, 0, 0, 0
		r.Reason = "unreliable-or-overflow"
		return r
	}
	if !baselineFirst.IsZero() && !canaryFirst.IsZero() {
		first := baselineFirst
		if canaryFirst.After(first) {
			first = canaryFirst
		}
		r.ObservedFor = now.Sub(first)
	}
	if r.Baseline.Total > 0 {
		r.Baseline.DenyRate = float64(r.Baseline.Denied) / float64(r.Baseline.Total)
	}
	if r.Canary.Total > 0 {
		r.Canary.DenyRate = float64(r.Canary.Denied) / float64(r.Canary.Total)
	}
	if r.Baseline.Total < s.Config.MinSamples || r.Canary.Total < s.Config.MinSamples || r.Baseline.Sources < s.Config.MinSources || r.Canary.Sources < s.Config.MinSources || r.Baseline.Sources < r.Baseline.Assigned || r.Canary.Sources < r.Canary.Assigned || r.ObservedFor < s.Config.Observation {
		return r
	}
	r.Verdict, r.Reason = "healthy", ""
	if r.Canary.DenyRate-r.Baseline.DenyRate > s.Config.MaxDenyDelta {
		r.Verdict = "degraded"
	}
	return r
}
