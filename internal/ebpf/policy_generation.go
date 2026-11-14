//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/yasindce1998/warmor/pkg/api"
)

const (
	// GenerationMaxEntries includes the ID and default-deny markers, not just
	// rules. All inner maps have the same fixed layout for Linux 6.1 support.
	GenerationMaxEntries   = 65536
	GenerationMaxDomains   = 64
	generationMarkerFamily = 255
	generationIDEvent      = 255
)

var (
	ErrGenerationBusy  = errors.New("candidate or undrained generation already exists")
	ErrStaleGeneration = errors.New("stale or unknown policy generation")
)

// GenerationRule is an exact static identity. Use Pattern for exec, mount and
// ptrace; Address+Port for connect/bind. No file/basename or hash identities.
type GenerationRule struct {
	CgroupID  uint64
	EventType uint8
	Pattern   string
	Address   string
	Port      uint16
	Action    uint8
	Audit     bool
}

// GenerationDomain marks a complete exec/connect allowlist. CgroupID 0 is the
// explicit global fallback, never an inferred workload identity.
type GenerationDomain struct {
	CgroupID  uint64
	EventType uint8
	Mode      uint8
}

// GenerationSpec is copied into a fresh, unreachable kernel map by Prepare.
// It must describe the COMPLETE candidate static policy and default-deny set.
// Dynamic decisions are intentionally not copied from the old generation.
type GenerationSpec struct {
	Rules       []GenerationRule
	DefaultDeny []GenerationDomain
}

type generationValue struct {
	Policy     PolicyValue
	Generation uint64
}

type generationMap interface {
	Put(key, value any) error
	Close() error
}

type generationBackend interface {
	create() (generationMap, error)
	publish(generationMap) error
}

type kernelGenerationBackend struct{ active *ebpf.Map }

func generationMapSpec() *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name: "warmor_gen", Type: ebpf.Hash, KeySize: 288, ValueSize: 16,
		MaxEntries: GenerationMaxEntries, Flags: unix.BPF_F_NO_PREALLOC,
	}
}

func (b kernelGenerationBackend) create() (generationMap, error) {
	return ebpf.NewMap(generationMapSpec())
}

func (b kernelGenerationBackend) publish(m generationMap) error {
	inner, ok := m.(*ebpf.Map)
	if !ok {
		return errors.New("not a kernel generation map")
	}
	// ARRAY_OF_MAPS replaces a map pointer under kernel RCU. An in-flight
	// non-sleepable hook retains the old map for its entire invocation.
	return b.active.Put(uint32(0), inner)
}

type policyGeneration struct {
	id    uint64
	mapFD generationMap
	ready bool
}

// GenerationManager is an opt-in, single-writer double buffer. It owns at most
// two inner maps: active+candidate OR active+retiring (including failed cleanup).
// Obtain it once from LSMLoader.PolicyGenerations. No daemon path uses it yet.
//
// Activate is atomic ONLY for the kernel's rules+markers+ID. The caller MUST
// serialize userspace evaluator publication, event dispatch, dynamic writeback
// and drain acknowledgement; see docs/design/kernel-generations.md. A mutex in
// this helper cannot make a userspace/kernel activation atomic.
type GenerationManager struct {
	mu        sync.Mutex
	backend   generationBackend
	highestID uint64
	active    *policyGeneration
	candidate *policyGeneration
	retiring  *policyGeneration
	closed    bool
}

func generationMarker(cgroupID uint64, eventType uint8) PolicyKey {
	return PolicyKey{CgroupID: cgroupID, EventType: eventType, Family: generationMarkerFamily}
}

func generationRuleKey(rule GenerationRule) (PolicyKey, error) {
	if rule.Action != ActionAllow && rule.Action != ActionDeny {
		return PolicyKey{}, fmt.Errorf("invalid policy action %d", rule.Action)
	}
	if rule.EventType == EventTypeNetwork || rule.EventType == EventTypeBind {
		if rule.Pattern != "" {
			return PolicyKey{}, errors.New("endpoint rule must not contain a pattern")
		}
		return endpointPolicyKey(rule.CgroupID, rule.EventType, rule.Address, rule.Port)
	}
	if rule.Address != "" || rule.Port != 0 {
		return PolicyKey{}, errors.New("string rule must not contain an endpoint")
	}
	return stringPolicyKey(rule.CgroupID, rule.EventType, rule.Pattern)
}

func generationPolicyValue(action uint8, audit bool) generationValue {
	v := generationValue{Policy: PolicyValue{Action: action}}
	if audit {
		v.Policy.Audit = 1
	}
	return v
}

// Prepare builds a complete candidate without modifying the active map. IDs
// must increase strictly, including failed/aborted builds, preventing stale
// event/writeback ABA collisions. Duplicate identities (even identical rules)
// are rejected rather than relying on insertion order. All validation occurs
// before creating a BPF map; oversized input is rejected before allocating an
// auxiliary index. A failed cleanup blocks subsequent builds until Abort retries.
func (m *GenerationManager) Prepare(id uint64, spec GenerationSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("generation manager closed")
	}
	if id == 0 || id <= m.highestID {
		return ErrStaleGeneration
	}
	if m.candidate != nil || m.retiring != nil {
		return ErrGenerationBusy
	}
	m.highestID = id
	if len(spec.DefaultDeny) > GenerationMaxDomains || len(spec.Rules) > GenerationMaxEntries-1-len(spec.DefaultDeny) {
		return errors.New("generation exceeds bounded rule/domain capacity")
	}
	entries := make(map[PolicyKey]generationValue, 1+len(spec.Rules)+len(spec.DefaultDeny))
	entries[generationMarker(0, generationIDEvent)] = generationValue{Generation: id}
	for _, rule := range spec.Rules {
		key, err := generationRuleKey(rule)
		if err != nil {
			return fmt.Errorf("generation rule: %w", err)
		}
		if _, exists := entries[key]; exists {
			return fmt.Errorf("duplicate generation rule identity: %+v", key)
		}
		entries[key] = generationPolicyValue(rule.Action, rule.Audit)
	}
	for _, domain := range spec.DefaultDeny {
		// Only these hooks implement complete, deny-on-miss domains today.
		if (domain.EventType != EventTypeExec && domain.EventType != EventTypeNetwork) ||
			(domain.Mode != DefaultDenyModeDeny && domain.Mode != DefaultDenyModeAudit) {
			return fmt.Errorf("invalid generation default-deny domain: %+v", domain)
		}
		key := generationMarker(domain.CgroupID, domain.EventType)
		if _, exists := entries[key]; exists {
			return errors.New("duplicate generation default-deny domain")
		}
		entries[key] = generationValue{Policy: PolicyValue{Action: domain.Mode}}
	}
	inner, err := m.backend.create()
	if err != nil {
		return fmt.Errorf("create candidate generation: %w", err)
	}
	m.candidate = &policyGeneration{id: id, mapFD: inner}
	for key, value := range entries {
		if err := inner.Put(key, value); err != nil {
			return errors.Join(fmt.Errorf("populate candidate generation: %w", err), m.abort())
		}
	}
	m.candidate.ready = true
	return nil
}

// Activate replaces the active inner-map pointer with one BPF_MAP_UPDATE_ELEM.
// On failure the old pointer and candidate are unchanged; retry or Abort.
// On success the old map is retained until AcknowledgeDrain, never cleared.
// There is deliberately no switch-back-to-legacy or automatic rollback API.
func (m *GenerationManager) Activate(id uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.candidate == nil || m.candidate.id != id || !m.candidate.ready {
		return ErrStaleGeneration
	}
	if err := m.backend.publish(m.candidate.mapFD); err != nil {
		return fmt.Errorf("publish candidate generation: %w", err)
	}
	m.retiring = m.active
	if m.retiring == nil {
		// The first switch must also drain unversioned userspace work. Legacy
		// map FDs remain owned by the loader and are never cleared here.
		m.retiring = &policyGeneration{id: 0}
	}
	m.active, m.candidate = m.candidate, nil
	return nil
}

// Abort discards only the named candidate. Failed Close is retained for retry,
// and the candidate cannot be activated after any cleanup attempt.
func (m *GenerationManager) Abort(id uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.candidate == nil || m.candidate.id != id {
		return ErrStaleGeneration
	}
	return m.abort()
}

func (m *GenerationManager) abort() error {
	m.candidate.ready = false
	if err := m.candidate.mapFD.Close(); err != nil {
		return fmt.Errorf("close candidate generation: %w", err)
	}
	m.candidate = nil
	return nil
}

// AcknowledgeDrain asserts that all old-generation userspace work has completed
// and its evaluator may be released. This is a CALLER ASSERTION, not a kernel
// grace-period/ring-buffer barrier. It closes the old FD without deleting any
// entries: kernel RCU protects already-running hooks even after FD release.
func (m *GenerationManager) AcknowledgeDrain(id uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.retiring == nil || m.retiring.id != id {
		return ErrStaleGeneration
	}
	if m.retiring.mapFD != nil {
		if err := m.retiring.mapFD.Close(); err != nil {
			return fmt.Errorf("retire policy generation: %w", err)
		}
	}
	m.retiring = nil
	return nil
}

// SyncEvent accepts writeback only for the currently active generation and a
// fully represented, nonzero-cgroup operation. Late old-generation decisions
// cannot poison the new map. Capacity failures are returned (never LRU evict a
// static rule/marker); the caller must surface them rather than claim success.
func (m *GenerationManager) SyncEvent(id uint64, event *api.Event, action uint8, audit bool) error {
	key, err := eventPolicyKey(event)
	if err != nil {
		return err
	}
	if action != ActionAllow && action != ActionDeny {
		return fmt.Errorf("invalid policy action %d", action)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.active == nil || m.active.id != id {
		return ErrStaleGeneration
	}
	return m.active.mapFD.Put(key, generationPolicyValue(action, audit))
}

// Close is only for loader teardown AFTER hooks/event workers stop. It never
// clears the outer pointer (which could fall back to legacy policy). Closing
// FDs alone does not deactivate a map still referenced by attached programs.
func (m *GenerationManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	var errs []error
	for _, state := range []**policyGeneration{&m.candidate, &m.retiring, &m.active} {
		if *state != nil {
			if (*state).mapFD == nil {
				*state = nil
				continue
			}
			if err := (*state).mapFD.Close(); err != nil {
				errs = append(errs, err)
			} else {
				*state = nil
			}
		}
	}
	return errors.Join(errs...)
}
