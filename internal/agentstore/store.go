// Package agentstore persists assignment replay protection and the active
// immutable revision reference together. It is a library, not daemon wiring.
package agentstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/yasindce1998/warmor/internal/crypto/assignment"
)

const (
	maxStateBytes = 2 << 20
	maxPolicies   = 1024
)

var (
	ErrReplay        = errors.New("deployment sequence is not above durable high-water mark")
	ErrRollback      = errors.New("explicit rollback authorization required or source mismatch")
	ErrState         = errors.New("invalid assignment state")
	ErrClosed        = errors.New("assignment store closed")
	ErrIndeterminate = errors.New("assignment publication durability indeterminate; stop activation and reopen")
)

// Active is both activation metadata and the authoritative revision pointer.
// Revision names an already-fsynced immutable directory beside the state file.
// No separately published symlink/file may be used as the activation authority.
type Active struct {
	Revision string          `json:"revision"`
	Envelope json.RawMessage `json:"envelope"`
}

type State struct {
	Format    int               `json:"format"`
	Target    assignment.Target `json:"target"`
	HighWater uint64            `json:"high_water"`
	// Policies retains the highest version and its full identity for every
	// seen policy ID. It is bounded, never silently evicted or reset on rotation.
	Policies  map[string]assignment.Policy `json:"policies"`
	LastClock int64                        `json:"last_clock"` // greatest trusted commit time, Unix nanos
	Active    *Active                      `json:"active"`
}

type disk struct {
	SHA256 string          `json:"sha256"`
	State  json.RawMessage `json:"state"`
}

// Store is single-writer across processes and serialized across goroutines.
// Parent storage must be private and support reliable local rename/fsync/locks.
type Store struct {
	mu    sync.Mutex
	path  string
	lock  *os.File
	state State
	fault error
	// Per-instance injection points, kept private so production cannot disable
	// durability. Tests cover pre-rename and uncertain post-rename failures.
	fileSync func(*os.File) error
	publish  func(string, string) (bool, error)
}

// Create is explicit first enrollment; it refuses existing state. Never call
// Create as an automatic fallback when Open fails, even for missing state.
func Create(path string, target assignment.Target) (*Store, error) {
	return open(path, target, true)
}

// Open refuses missing, corrupt, unsupported or wrong-target state. It does not
// by itself authorize execution: verify the active envelope and exact artifact
// with current local trust/requirements before restoring an evaluator.
func Open(path string, target assignment.Target) (*Store, error) {
	return open(path, target, false)
}

func open(path string, target assignment.Target, create bool) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: path required", ErrState)
	}
	if err := target.Validate(); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	abs = filepath.Join(dir, filepath.Base(abs))
	lock, err := lockFile(abs + ".lock")
	if err != nil {
		return nil, fmt.Errorf("lock assignment state: %w", err)
	}
	s := &Store{path: abs, lock: lock, fileSync: func(f *os.File) error { return f.Sync() }, publish: publishFile}
	fail := func(err error) (*Store, error) { _ = lock.Close(); return nil, err }
	info, err := os.Lstat(abs)
	if create {
		if err == nil {
			return fail(fmt.Errorf("%w: state already exists", ErrState))
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fail(err)
		}
		s.state = State{Format: 1, Target: target, Policies: map[string]assignment.Policy{}}
		if err := s.write(s.state); err != nil {
			return fail(err)
		}
		return s, nil
	}
	if err != nil {
		return fail(err)
	}
	if !info.Mode().IsRegular() {
		return fail(fmt.Errorf("%w: regular state file required", ErrState))
	}
	f, err := os.Open(abs)
	if err != nil {
		return fail(err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	closeErr := f.Close()
	if err != nil {
		return fail(err)
	}
	if closeErr != nil {
		return fail(closeErr)
	}
	if len(data) > maxStateBytes {
		return fail(fmt.Errorf("%w: state too large", ErrState))
	}
	var d disk
	if err := json.Unmarshal(data, &d); err != nil {
		return fail(fmt.Errorf("%w: %v", ErrState, err))
	}
	canonical, err := json.Marshal(d)
	if err != nil || !bytes.Equal(data, canonical) || assignment.Digest(d.State) != d.SHA256 {
		return fail(fmt.Errorf("%w: encoding/checksum", ErrState))
	}
	if err := json.Unmarshal(d.State, &s.state); err != nil {
		return fail(fmt.Errorf("%w: %v", ErrState, err))
	}
	canonical, err = json.Marshal(s.state)
	if err != nil || !bytes.Equal(d.State, canonical) {
		return fail(fmt.Errorf("%w: noncanonical state", ErrState))
	}
	if err := validate(s.state, target); err != nil {
		return fail(err)
	}
	// A visible record may have survived a prior failed directory-sync only
	// in cache. Re-publish the exact recovered state with the full durability
	// barrier before exposing marks or allowing startup acknowledgement.
	if err := s.write(s.state); err != nil {
		return fail(err)
	}
	return s, nil
}

func revisionValid(name string) bool {
	if !strings.HasPrefix(name, "revision-") || len(name) <= len("revision-") || len(name) > 128 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

func validate(st State, target assignment.Target) error {
	bad := func() error { return ErrState }
	if st.Format != 1 || st.Target != target || st.Policies == nil || len(st.Policies) > maxPolicies {
		return bad()
	}
	if st.Active == nil {
		if st.HighWater != 0 || st.LastClock != 0 || len(st.Policies) != 0 {
			return bad()
		}
		return nil
	}
	if !revisionValid(st.Active.Revision) || st.LastClock <= 0 {
		return bad()
	}
	e, err := assignment.Decode(st.Active.Envelope)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrState, err)
	}
	d := e.Deployment
	if d.Target != target || d.Sequence != st.HighWater || st.LastClock/1e9 < d.IssuedAt || st.LastClock/1e9 >= d.ExpiresAt {
		return bad()
	}
	for id, p := range st.Policies {
		if id != p.ID || p.Validate() != nil {
			return bad()
		}
	}
	p, ok := st.Policies[d.Policy.ID]
	if !ok || p.Version < d.Policy.Version {
		return bad()
	}
	if (p.Version > d.Policy.Version || p != d.Policy) && d.Rollback == nil {
		return bad()
	}
	return nil
}

func copyState(st State) State {
	cp := st
	cp.Policies = make(map[string]assignment.Policy, len(st.Policies))
	for id, p := range st.Policies {
		cp.Policies[id] = p
	}
	if st.Active != nil {
		a := *st.Active
		a.Envelope = bytes.Clone(a.Envelope)
		cp.Active = &a
	}
	return cp
}

// Snapshot is a defensive copy. In particular, mutating it cannot reset marks.
func (s *Store) Snapshot() (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return State{}, ErrClosed
	}
	if s.fault != nil {
		return State{}, s.fault
	}
	return copyState(s.state), nil
}

// Commit belongs inside the enforcer's quiesced durable-publication callback,
// after artifact verification, actual ABI/posture checks, candidate preparation
// and immutable revision fsync, and BEFORE the infallible evaluator swap.
// On success this one record selects both the revision and its replay marks.
// On any failure do not swap/acknowledge; ErrIndeterminate additionally requires
// stopping activation and reopening/reconciling the authoritative disk record.
func (s *Store) Commit(v assignment.Verified, revision string, clock assignment.Clock) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return ErrClosed
	}
	if s.fault != nil {
		return s.fault
	}
	if err := v.CheckTime(clock); err != nil {
		return err
	}
	if !revisionValid(revision) {
		return fmt.Errorf("%w: unsafe revision name", ErrState)
	}
	// UnixNano is intentionally bounded: durable clock serialization must not
	// wrap for far-future clock values. Millennia are not valid daemon time.
	if clock.Now.Year() < 1970 || clock.Now.Year() > 2200 {
		return assignment.ErrClock
	}
	if clock.Now.UnixNano() < s.state.LastClock {
		return assignment.ErrClock
	}
	e := v.Envelope()
	d := e.Deployment
	if d.Target != s.state.Target {
		return assignment.ErrAudience
	}
	if d.Sequence <= s.state.HighWater {
		return ErrReplay
	}
	needsRollback := false
	if p, ok := s.state.Policies[d.Policy.ID]; ok {
		needsRollback = d.Policy.Version < p.Version || (d.Policy.Version == p.Version && d.Policy != p)
	} else if len(s.state.Policies) >= maxPolicies {
		return fmt.Errorf("%w: policy history full", ErrState)
	}
	if s.state.Active != nil {
		old, err := assignment.Decode(s.state.Active.Envelope)
		if err != nil {
			return fmt.Errorf("%w: active envelope", ErrState)
		}
		needsRollback = needsRollback || d.Policy.Posture.WeakerThan(old.Deployment.Policy.Posture)
		if r := d.Rollback; r != nil && (r.FromSequence != old.Deployment.Sequence || r.From != old.Deployment.Policy) {
			return ErrRollback
		}
	} else if d.Rollback != nil {
		return ErrRollback
	}
	if needsRollback && d.Rollback == nil {
		return ErrRollback
	}
	encoded, err := assignment.Encode(e)
	if err != nil {
		return err
	}
	next := copyState(s.state)
	next.HighWater, next.LastClock = d.Sequence, clock.Now.UnixNano()
	next.Active = &Active{Revision: revision, Envelope: encoded}
	if p, ok := next.Policies[d.Policy.ID]; !ok || d.Policy.Version > p.Version {
		next.Policies[d.Policy.ID] = d.Policy
	}
	if err := validate(next, next.Target); err != nil {
		return err
	}
	if err := s.write(next); err != nil {
		return err
	}
	s.state = next
	return nil
}

func (s *Store) write(st State) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	data, err = json.Marshal(disk{SHA256: hex.EncodeToString(sum[:]), State: data})
	if err != nil {
		return err
	}
	if len(data) > maxStateBytes {
		return fmt.Errorf("%w: snapshot too large", ErrState)
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".assignment-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := s.fileSync(f); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	published, err := s.publish(f.Name(), s.path)
	if err != nil && published {
		s.fault = fmt.Errorf("%w: %v", ErrIndeterminate, err)
		return s.fault
	}
	return err
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}
