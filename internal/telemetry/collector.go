// Package telemetry defines the optional, versioned acknowledged-decision wire
// contract. It contains no rollout actuator and no process-wide outcome cache.
package telemetry

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"sync"
)

const SchemaVersion = 1

// Population deliberately excludes kernel verdicts, independent filters,
// audit/learning decisions and error-derived fallback denies. It is not a
// measurement of successful kernel enforcement or complete node traffic.
const Population = "userspace-policy-decisions-v1"

type Session struct {
	Epoch     string `json:"epoch"`
	SessionID string `json:"session_id"`
}

type Revision struct {
	PolicyID           string `json:"policy_id"`
	PolicyVersion      int64  `json:"policy_version"`
	PolicyHash         string `json:"policy_hash"`
	AssignmentRevision uint64 `json:"assignment_revision"`
	ActivationID       string `json:"activation_id"`
}

// Assignment is issued by the server, not inferred from an artifact version.
// Cohort attribution is deliberately absent from the agent-facing contract.
type Assignment struct {
	Session
	AssignmentRevision uint64 `json:"assignment_revision"`
}

type Snapshot struct {
	SchemaVersion uint32 `json:"schema_version"`
	Session
	Revision Revision `json:"revision"`
	Sequence uint64   `json:"sequence"`
	Total    uint64   `json:"total"`
	Denied   uint64   `json:"denied"`
	Errors   uint64   `json:"errors"`
	Excluded uint64   `json:"excluded"`
	Lost     uint64   `json:"lost"`
	Overflow bool     `json:"overflow"`
}

func ValidID(s string) bool {
	if len(s) == 0 || len(s) > 128 || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func (s Session) Validate() error {
	if !ValidID(s.Epoch) || !ValidID(s.SessionID) {
		return errors.New("telemetry requires an authorized epoch and session")
	}
	return nil
}

func (r Revision) Validate() error {
	hash, err := hex.DecodeString(r.PolicyHash)
	if !ValidID(r.PolicyID) || r.PolicyVersion <= 0 || err != nil || len(hash) != 32 || strings.ToLower(r.PolicyHash) != r.PolicyHash || r.AssignmentRevision == 0 || !ValidID(r.ActivationID) {
		return errors.New("invalid telemetry activation revision")
	}
	return nil
}

func (s Snapshot) Validate() error {
	if s.SchemaVersion != SchemaVersion || s.Sequence == 0 || s.Denied > s.Total {
		return errors.New("invalid telemetry snapshot schema, sequence or counters")
	}
	if err := s.Session.Validate(); err != nil {
		return err
	}
	return s.Revision.Validate()
}

func NewID() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Collector retains exactly one activation and one session-wide sequence.
// The enforcer's event drain barrier orders Replace/Seal against event counting.
// Snapshot uses the same mutex as counters; it cannot read a torn activation.
// A missing session/activation produces no evidence, never a legacy fallback.
type Collector struct {
	mu       sync.Mutex
	session  Session
	sequence uint64
	active   *Snapshot
}

func (c *Collector) SetSession(s Session) error {
	if err := s.Validate(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == s {
		return nil // reusing a lease cannot reset the high-water sequence
	}
	c.session, c.sequence, c.active = s, 0, nil
	return nil
}

func (c *Collector) Session() Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session
}

// Prepare does all fallible work before an enforcer commits an activation.
func (c *Collector) Prepare(a Assignment, r Revision) (Snapshot, error) {
	id, err := NewID()
	if err != nil {
		return Snapshot{}, err
	}
	r.AssignmentRevision, r.ActivationID = a.AssignmentRevision, id
	s := Snapshot{SchemaVersion: SchemaVersion, Session: a.Session, Revision: r}
	if err := s.Session.Validate(); err != nil {
		return Snapshot{}, err
	}
	if err := r.Validate(); err != nil {
		return Snapshot{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != a.Session {
		return Snapshot{}, errors.New("collector session changed")
	}
	return s, nil
}

// Replace installs a prepared, zero-counter activation. If a lease changed
// during activation, seal instead of attributing decisions to the old lease.
func (c *Collector) Replace(s Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active = nil
	if s.Session != c.session || s.Revision.Validate() != nil {
		return
	}
	s.Sequence, s.Total, s.Denied, s.Errors, s.Excluded, s.Lost, s.Overflow = 0, 0, 0, 0, 0, 0, false
	c.active = &s
}

func (c *Collector) Seal() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active = nil
}

// Record counts each finalized event, including each userspace cache hit, not
// cache insertion or cached ActionResult metadata. Errors are never denials.
func (c *Collector) Record(denied, evaluationError, excluded bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active == nil {
		return
	}
	s := c.active
	inc := func(n *uint64) {
		if *n == math.MaxUint64 {
			s.Overflow = true
		} else {
			(*n)++
		}
	}
	switch {
	case evaluationError:
		inc(&s.Errors)
	case excluded:
		inc(&s.Excluded)
	default:
		inc(&s.Total)
		if denied {
			inc(&s.Denied)
		}
	}
}

// RecordLoss exposes known sensor loss, not an estimate of undetectable loss.
func (c *Collector) RecordLoss(n uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != nil {
		if math.MaxUint64-c.active.Lost < n {
			c.active.Overflow = true
		} else {
			c.active.Lost += n
		}
	}
}

func (c *Collector) Snapshot() *Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active == nil || c.sequence == math.MaxUint64 {
		return nil // never wrap; a new authorized session is required
	}
	c.sequence++
	s := *c.active
	s.Sequence = c.sequence
	return &s
}

// Matches does not consume a sequence or expose cached decision outcomes.
func (c *Collector) Matches(a Assignment, policyID string, version int64, hash string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active != nil && c.session == a.Session && c.active.Revision.AssignmentRevision == a.AssignmentRevision && c.active.Revision.PolicyID == policyID && c.active.Revision.PolicyVersion == version && c.active.Revision.PolicyHash == hash
}

func (c *Collector) ActiveRevision() Revision {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active == nil {
		return Revision{}
	}
	return c.active.Revision
}
