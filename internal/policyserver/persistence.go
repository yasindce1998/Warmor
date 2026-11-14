package policyserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// StoreLimits bound in-memory and durable stores. Zero values use defaults.
// Revisions are never silently evicted: reaching a limit rejects the mutation.
type StoreLimits struct {
	MaxSnapshotBytes     int64
	MaxWASMBytes         int64
	MaxRetainedWASMBytes int64
	MaxPolicies          int
	MaxVersionsPerPolicy int
	MaxAgents            int
	MaxRollouts          int
	MaxBindings          int
	MaxAuditEntries      int
}

func DefaultStoreLimits() StoreLimits {
	return StoreLimits{
		MaxSnapshotBytes: 256 << 20, MaxWASMBytes: 16 << 20, MaxRetainedWASMBytes: 128 << 20,
		MaxPolicies: 1024, MaxVersionsPerPolicy: 128, MaxAgents: 10000,
		MaxRollouts: 4096, MaxBindings: 10000, MaxAuditEntries: 10000,
	}
}

func normalizeLimits(l StoreLimits) StoreLimits {
	d := DefaultStoreLimits()
	if l.MaxSnapshotBytes > 0 {
		d.MaxSnapshotBytes = l.MaxSnapshotBytes
	}
	if l.MaxWASMBytes > 0 {
		d.MaxWASMBytes = l.MaxWASMBytes
	}
	if l.MaxRetainedWASMBytes > 0 {
		d.MaxRetainedWASMBytes = l.MaxRetainedWASMBytes
	}
	if l.MaxPolicies > 0 {
		d.MaxPolicies = l.MaxPolicies
	}
	if l.MaxVersionsPerPolicy > 0 {
		d.MaxVersionsPerPolicy = l.MaxVersionsPerPolicy
	}
	if l.MaxAgents > 0 {
		d.MaxAgents = l.MaxAgents
	}
	if l.MaxRollouts > 0 {
		d.MaxRollouts = l.MaxRollouts
	}
	if l.MaxBindings > 0 {
		d.MaxBindings = l.MaxBindings
	}
	if l.MaxAuditEntries > 0 {
		d.MaxAuditEntries = l.MaxAuditEntries
	}
	return d
}

type StoreOptions struct {
	Limits    StoreLimits
	VerifyKey ed25519.PublicKey
}

// AuditEntry records a committed management mutation. Heartbeats are persisted
// but not audited, so routine liveness traffic does not evict management history.
type AuditEntry struct {
	Sequence uint64    `json:"sequence"`
	At       time.Time `json:"at"`
	Action   string    `json:"action"`
	Resource string    `json:"resource"`
}

type diskVersion struct {
	Data      []byte `json:"data"`
	Hash      string `json:"hash"`
	Path      string `json:"path"`
	Signature []byte `json:"signature,omitempty"`
}

type storeSnapshot struct {
	Deployments map[string][]byte                 `json:"deployments,omitempty"`
	Policies    map[string]*Policy                `json:"policies"`
	Agents      map[string]*Agent                 `json:"agents"`
	Versions    map[string]map[int64]*diskVersion `json:"versions"`
	Rollouts    map[string]*RolloutState          `json:"rollouts"`
	Bindings    map[string]*ContainerBinding      `json:"bindings"`
	Audit       []AuditEntry                      `json:"audit"`
	Sequence    uint64                            `json:"sequence"`
}

type snapshotEnvelope struct {
	Format int             `json:"format"`
	SHA256 string          `json:"sha256"`
	State  json.RawMessage `json:"state"`
}

type snapshotBackend struct {
	path  string
	lock  *os.File
	fault error
}

var (
	ErrStoreClosed      = errors.New("policy store is closed")
	ErrStateLimit       = errors.New("policy state resource limit exceeded")
	ErrStatePersistence = errors.New("policy state persistence failed")
)

// OpenStore opens a single-writer snapshot. Missing state is initialized;
// corrupt/unsupported state fails closed, never silently replaced. The parent
// directory must be private to the administrator, not API clients.
func OpenStore(path string, opts StoreOptions) (*Store, error) {
	if path == "" {
		return nil, errors.New("state file path required")
	}
	if opts.VerifyKey != nil && len(opts.VerifyKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid verification key")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	abs = filepath.Join(dir, filepath.Base(abs))
	if info, err := os.Lstat(abs); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("state file must be a regular file, not a symlink")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	lock, err := lockStateFile(abs + ".lock")
	if err != nil {
		return nil, fmt.Errorf("lock state: %w", err)
	}
	b := &snapshotBackend{path: abs, lock: lock}
	s := NewStore()
	s.backend = b
	s.limits = normalizeLimits(opts.Limits)
	s.verifyKey = slices.Clone(opts.VerifyKey)
	fail := func(err error) (*Store, error) { _ = unlockStateFile(lock); return nil, err }
	f, err := os.Open(abs)
	if errors.Is(err, os.ErrNotExist) {
		if _, err := b.write(s.snapshotLocked(), s.limits.MaxSnapshotBytes); err != nil {
			return fail(err)
		}
		return s, nil
	}
	if err != nil {
		return fail(err)
	}
	data, err := io.ReadAll(io.LimitReader(f, s.limits.MaxSnapshotBytes+1))
	closeErr := f.Close()
	if err != nil {
		return fail(err)
	}
	if closeErr != nil {
		return fail(closeErr)
	}
	if int64(len(data)) > s.limits.MaxSnapshotBytes {
		return fail(ErrStateLimit)
	}
	var e snapshotEnvelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return fail(fmt.Errorf("decode state: %w", err))
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return fail(errors.New("trailing state data"))
	}
	if e.Format != 1 {
		return fail(fmt.Errorf("unsupported state format %d", e.Format))
	}
	hash := sha256.Sum256(e.State)
	if e.SHA256 != hex.EncodeToString(hash[:]) {
		return fail(errors.New("state checksum mismatch"))
	}
	var d storeSnapshot
	dec = json.NewDecoder(bytes.NewReader(e.State))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return fail(fmt.Errorf("decode snapshot: %w", err))
	}
	if d.Versions == nil {
		return fail(errors.New("missing revision index"))
	}
	for _, vs := range d.Versions {
		for _, v := range vs {
			if v == nil {
				return fail(errors.New("null revision"))
			}
		}
	}
	s.restoreLocked(d)
	if err := s.validateLocked(true); err != nil {
		return fail(fmt.Errorf("invalid state: %w", err))
	}
	return s, nil
}

// Close releases the writer lock. Successful mutations are already synced.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.backend != nil {
		return unlockStateFile(s.backend.lock)
	}
	return nil
}

func (s *Store) ListAudit() []AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.audit)
}

// mutateLocked commits a whole transaction or restores the old state. Callers
// hold mu. Immutable module bytes are shared, never copied or mutated internally.
func (s *Store) mutateLocked(action, resource string, fn func() error) error {
	if s.closed {
		return ErrStoreClosed
	}
	if s.backend != nil && s.backend.fault != nil {
		return fmt.Errorf("%w: %v", ErrStatePersistence, s.backend.fault)
	}
	before := s.snapshotLocked()
	if err := fn(); err != nil {
		s.restoreLocked(before)
		return err
	}
	s.sequence++
	if action != "" {
		s.audit = append(s.audit, AuditEntry{s.sequence, time.Now().UTC(), action, resource})
		if len(s.audit) > s.limits.MaxAuditEntries {
			s.audit = slices.Clone(s.audit[len(s.audit)-s.limits.MaxAuditEntries:])
		}
	}
	if err := s.validateLocked(false); err != nil {
		s.restoreLocked(before)
		return err
	}
	if s.backend != nil {
		committed, err := s.backend.write(s.snapshotLocked(), s.limits.MaxSnapshotBytes)
		if err != nil {
			if !committed {
				s.restoreLocked(before)
			} else {
				s.backend.fault = err
			}
			return fmt.Errorf("%w: %w", ErrStatePersistence, err)
		}
	}
	return nil
}

func (s *Store) snapshotLocked() storeSnapshot {
	d := storeSnapshot{Policies: make(map[string]*Policy), Agents: make(map[string]*Agent), Versions: make(map[string]map[int64]*diskVersion), Rollouts: make(map[string]*RolloutState), Bindings: make(map[string]*ContainerBinding), Audit: slices.Clone(s.audit), Sequence: s.sequence}
	d.Deployments = make(map[string][]byte, len(s.deployments))
	for id, b := range s.deployments {
		d.Deployments[id] = slices.Clone(b)
	}
	for id, p := range s.policies {
		d.Policies[id] = clonePolicy(p)
	}
	for id, a := range s.agents {
		d.Agents[id] = cloneAgent(a)
	}
	for id, vs := range s.versions {
		d.Versions[id] = make(map[int64]*diskVersion)
		for n, v := range vs {
			d.Versions[id][n] = &diskVersion{v.data, v.hash, v.path, v.sig}
		}
	}
	for id, r := range s.rollouts {
		d.Rollouts[id] = cloneRollout(r)
	}
	for id, b := range s.bindings {
		cp := *b
		cp.Labels = maps.Clone(b.Labels)
		d.Bindings[id] = &cp
	}
	return d
}

func (s *Store) restoreLocked(d storeSnapshot) {
	s.policies, s.agents, s.rollouts, s.bindings = d.Policies, d.Agents, d.Rollouts, d.Bindings
	s.audit, s.sequence = d.Audit, d.Sequence
	s.deployments = d.Deployments
	if s.deployments == nil {
		s.deployments = make(map[string][]byte)
	}
	s.versions = make(map[string]map[int64]*policyVersion)
	for id, vs := range d.Versions {
		s.versions[id] = make(map[int64]*policyVersion)
		for n, v := range vs {
			if v != nil {
				s.versions[id][n] = &policyVersion{v.Data, v.Hash, v.Path, v.Signature}
			}
		}
	}
}

// write returns committed after replacement. A post-replacement sync failure
// has an indeterminate crash outcome: the store then refuses further mutations.
func (b *snapshotBackend) write(state storeSnapshot, maxBytes int64) (bool, error) {
	payload, err := json.Marshal(state)
	if err != nil {
		return false, err
	}
	hash := sha256.Sum256(payload)
	data, err := json.Marshal(snapshotEnvelope{1, hex.EncodeToString(hash[:]), payload})
	if err != nil {
		return false, err
	}
	if int64(len(data)) > maxBytes {
		return false, ErrStateLimit
	}
	f, err := os.CreateTemp(filepath.Dir(b.path), ".warmor-state-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return false, err
	}
	return publishSnapshot(f.Name(), b.path)
}

func validStateID(id string) bool {
	return id != "" && len(id) <= 256 && utf8.ValidString(id) && !strings.ContainsAny(id, "/\\\x00\r\n")
}
func stringsCompare(a, b string) int { return strings.Compare(a, b) }

func validLabels(labels map[string]string) bool {
	if len(labels) > 64 {
		return false
	}
	for k, v := range labels {
		if k == "" || len(k) > 256 || len(v) > 4096 || !utf8.ValidString(k) || !utf8.ValidString(v) {
			return false
		}
	}
	return true
}

func labelsSizeBound(labels map[string]string) int64 {
	var size int64
	for k, v := range labels {
		size += 8 + int64(6*(len(k)+len(v)))
	}
	return size
}

func (s *Store) validateLocked(integrity bool) error {
	if err := s.validateDeploymentsLocked(integrity); err != nil {
		return err
	}
	l := s.limits
	if s.policies == nil || s.agents == nil || s.rollouts == nil || s.bindings == nil {
		return errors.New("missing state collections")
	}
	if len(s.policies) > l.MaxPolicies || len(s.agents) > l.MaxAgents || len(s.rollouts) > l.MaxRollouts || len(s.bindings) > l.MaxBindings || len(s.audit) > l.MaxAuditEntries {
		return ErrStateLimit
	}
	if len(s.versions) != len(s.policies) {
		return errors.New("policy revision index mismatch")
	}
	var total int64
	// Conservative metadata bound prevents encoding a huge snapshot before the
	// exact serialized-size check. JSON string escaping costs at most 6x.
	estimated := int64(1024 + len(s.audit)*1024)
	for _, a := range s.audit {
		estimated += int64(6 * (len(a.Action) + len(a.Resource)))
	}
	for id, p := range s.policies {
		if p == nil || !validStateID(id) || p.ID != id || !validLabels(p.Selector) || len(p.Name) > 4096 || len(p.Description) > 16384 || !utf8.ValidString(p.Name) || !utf8.ValidString(p.Description) {
			return errors.New("invalid policy metadata")
		}
		estimated += 2048 + int64(6*(len(id)+len(p.ID)+len(p.Name)+len(p.Description)+len(p.WASMPath)+len(p.WASMHash))) + labelsSizeBound(p.Selector)
		vs := s.versions[id]
		if len(vs) > l.MaxVersionsPerPolicy {
			return ErrStateLimit
		}
		if p.Version <= 0 || int64(len(vs)) != p.Version || vs[p.Version] == nil || vs[p.ActiveVersion] == nil {
			return errors.New("missing policy revision")
		}
		for n, v := range vs {
			if v == nil || n <= 0 || n > p.Version || len(v.path) > 4096 || !utf8.ValidString(v.path) {
				return errors.New("invalid revision")
			}
			if int64(len(v.data)) > l.MaxWASMBytes {
				return ErrStateLimit
			}
			total += int64(len(v.data))
			if total > l.MaxRetainedWASMBytes {
				return ErrStateLimit
			}
			estimated += 512 + int64(base64.StdEncoding.EncodedLen(len(v.data))+base64.StdEncoding.EncodedLen(len(v.sig))+6*(len(v.path)+len(v.hash)))
			if integrity {
				h := sha256.Sum256(v.data)
				if v.hash != hex.EncodeToString(h[:]) {
					return errors.New("revision digest mismatch")
				}
				if len(v.sig) != 0 && len(v.sig) != ed25519.SignatureSize {
					return errors.New("invalid revision signature")
				}
				if s.verifyKey != nil && (len(s.verifyKey) != ed25519.PublicKeySize || !ed25519.Verify(s.verifyKey, v.data, v.sig)) {
					return errors.New("revision signature verification failed")
				}
			}
		}
		latest := vs[p.Version]
		if latest.hash != p.WASMHash || latest.path != p.WASMPath || (len(latest.sig) > 0) != p.Signed {
			return errors.New("revision metadata mismatch")
		}
	}
	for id, a := range s.agents {
		if a == nil || !validStateID(id) || a.ID != id || !validLabels(a.Labels) || len(a.Hostname) > 4096 || !utf8.ValidString(a.Hostname) ||
			(a.PolicyID != "" && !validStateID(a.PolicyID)) || a.PolicyVersion < 0 ||
			len(a.PolicyHash) > 64 || !utf8.ValidString(a.PolicyHash) || len(a.EnvelopeHash) > 64 || !utf8.ValidString(a.EnvelopeHash) || len(a.ActivationError) > 4096 || !utf8.ValidString(a.ActivationError) {
			return errors.New("invalid agent")
		}
		estimated += 1024 + int64(6*(len(id)+len(a.ID)+len(a.Hostname)+len(a.PolicyID)+len(a.PolicyHash)+len(a.EnvelopeHash)+len(a.ActivationError))) + labelsSizeBound(a.Labels)
	}
	active := make(map[string]bool)
	for id, r := range s.rollouts {
		if r == nil || !validStateID(id) || r.ID != id || s.versions[r.PolicyID][r.BaseVersion] == nil || s.versions[r.PolicyID][r.TargetVersion] == nil || r.BasePolicyID != "" || r.Percentage < 0 || r.Percentage > 100 {
			return errors.New("invalid rollout")
		}
		estimated += 1024 + int64(6*(len(id)+len(r.ID)+len(r.PolicyID)))
		switch r.Status {
		case "active":
			if active[r.PolicyID] || r.CompletedAt != nil {
				return errors.New("conflicting active rollout")
			}
			active[r.PolicyID] = true
		case "completed":
			if r.Percentage != 100 || r.CompletedAt == nil {
				return errors.New("invalid completed rollout")
			}
		case "aborted":
			if r.CompletedAt == nil {
				return errors.New("invalid aborted rollout")
			}
		default:
			return errors.New("invalid rollout status")
		}
	}
	for id, b := range s.bindings {
		if b == nil || !validStateID(id) || b.ContainerID != id || !validStateID(b.PolicyID) || !validLabels(b.Labels) || b.PID < 0 || (b.Owner != "" && !validStateID(b.Owner)) {
			return errors.New("invalid binding")
		}
		estimated += 1024 + int64(6*(len(id)+len(b.ContainerID)+len(b.PolicyID)+len(b.Owner))) + labelsSizeBound(b.Labels)
	}
	if estimated > l.MaxSnapshotBytes {
		return ErrStateLimit
	}
	var seq uint64
	for _, a := range s.audit {
		if a.Sequence <= seq || a.Sequence > s.sequence || a.At.IsZero() || len(a.Action) > 128 || len(a.Resource) > 256 {
			return errors.New("invalid audit history")
		}
		seq = a.Sequence
	}
	return nil
}

func (s *Store) activeRolloutLocked(id string) bool {
	for _, r := range s.rollouts {
		if r.PolicyID == id && r.Status == "active" {
			return true
		}
	}
	return false
}
