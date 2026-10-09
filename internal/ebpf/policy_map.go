//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
)

const (
	EventTypeExec    uint8 = 0
	EventTypeFile    uint8 = 1
	EventTypeNetwork uint8 = 2
	EventTypeBind    uint8 = 3
	EventTypeListen  uint8 = 4
	EventTypePtrace  uint8 = 5
	EventTypeMount   uint8 = 6

	ActionAllow uint8 = 0
	ActionDeny  uint8 = 1
)

// PolicyKey matches struct policy_key in warmor_lsm.h
type PolicyKey struct {
	CgroupID  uint64
	RuleHash  uint32
	EventType uint8
	Pad       [3]uint8
}

// PolicyValue matches struct policy_value in warmor_lsm.h
type PolicyValue struct {
	Action   uint8
	Audit    uint8
	Pad      uint16
	HitCount uint32
}

// CachedDecision represents a WASM policy evaluation result to be compiled into the BPF map.
type CachedDecision struct {
	CgroupID  uint64
	EventType uint8
	Pattern   string
	Action    uint8
	Audit     bool
}

// PolicyMapManager manages the BPF policy map from userspace.
type PolicyMapManager struct {
	policyMap *ebpf.Map
	mu        sync.Mutex
}

// NewPolicyMapManager wraps an existing BPF map.
func NewPolicyMapManager(m *ebpf.Map) *PolicyMapManager {
	return &PolicyMapManager{policyMap: m}
}

// HashPattern computes the FNV-1a hash of a pattern string, matching the BPF-side implementation.
func HashPattern(pattern string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(pattern))
	return h.Sum32()
}

// Longest strings the BPF programs hash in full, per event type. Each program
// reads its string into a fixed buffer and skips the policy map when the read
// fills the buffer (the string may have been truncated), so only strings of at
// most bufsize-2 bytes can ever be matched by a rule.
const (
	maxExecPatternLen   = 254 // lsm_exec fname_buf[WARMOR_HASH_STR_MAX]
	maxMountPatternLen  = 62  // lsm_mount type_buf[64]
	maxPtracePatternLen = 15  // task comm, TASK_COMM_LEN 16 (never truncated)
)

// ErrNotKernelMatchable is returned for rules the BPF programs could never
// match exactly. Such rules are refused rather than written: a key that only
// covers part of what userspace decided on would apply the decision to other
// events, which is worse than no kernel fast-path at all.
var ErrNotKernelMatchable = errors.New("rule cannot be matched exactly by the BPF programs")

// ruleHash returns the policy_map rule_hash the BPF program for eventType
// computes for pattern, or ErrNotKernelMatchable if the program never sees
// pattern as a whole.
func ruleHash(eventType uint8, pattern string) (uint32, error) {
	var maxLen int
	switch eventType {
	case EventTypeExec:
		maxLen = maxExecPatternLen
	case EventTypeMount:
		maxLen = maxMountPatternLen
	case EventTypePtrace:
		maxLen = maxPtracePatternLen
	case EventTypeFile:
		// lsm_file only sees the dentry basename, never the path userspace
		// evaluated, so a file rule would match every same-named file.
		return 0, fmt.Errorf("file event: %w", ErrNotKernelMatchable)
	default:
		// Network/bind/listen are keyed on binary endpoint hashes; use
		// SetEndpointRule, SetNetworkRule or HashPort instead.
		return 0, fmt.Errorf("event type %d is not keyed by string: %w", eventType, ErrNotKernelMatchable)
	}
	// The kernel stops hashing at the first NUL.
	if len(pattern) > maxLen || strings.IndexByte(pattern, 0) >= 0 {
		return 0, fmt.Errorf("pattern %q for event type %d: %w", pattern, eventType, ErrNotKernelMatchable)
	}
	return HashPattern(pattern), nil
}

// endpointHash returns the rule_hash lsm_connect/lsm_bind compute for addr and
// port. The BPF programs hash the raw sockaddr fields as loaded from memory
// (network-order bytes read as native integers), so reproduce those values.
func endpointHash(addr string, port uint16) (uint32, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return 0, fmt.Errorf("invalid endpoint address %q", addr)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], port)
	rawPort := binary.NativeEndian.Uint16(portBytes[:])
	if ip4 := ip.To4(); ip4 != nil {
		return HashIPv4Endpoint(binary.NativeEndian.Uint32(ip4), rawPort), nil
	}
	var ip16 [16]byte
	copy(ip16[:], ip.To16())
	return HashIPv6Endpoint(ip16, rawPort), nil
}

// HashIPv4Endpoint hashes an IPv4 address and port, matching the BPF-side implementation.
func HashIPv4Endpoint(addr uint32, port uint16) uint32 {
	hash := uint32(2166136261)
	hash ^= addr & 0xFF
	hash *= 16777619
	hash ^= (addr >> 8) & 0xFF
	hash *= 16777619
	hash ^= (addr >> 16) & 0xFF
	hash *= 16777619
	hash ^= (addr >> 24) & 0xFF
	hash *= 16777619
	hash ^= uint32(port & 0xFF)
	hash *= 16777619
	hash ^= uint32((port >> 8) & 0xFF)
	hash *= 16777619
	return hash
}

// HashIPv6Endpoint hashes an IPv6 address and port.
func HashIPv6Endpoint(addr [16]byte, port uint16) uint32 {
	hash := uint32(2166136261)
	for i := 0; i < 16; i++ {
		hash ^= uint32(addr[i])
		hash *= 16777619
	}
	hash ^= uint32(port & 0xFF)
	hash *= 16777619
	hash ^= uint32((port >> 8) & 0xFF)
	hash *= 16777619
	return hash
}

// HashPort hashes a 2-byte port value with FNV-1a, matching the BPF-side hash_port.
func HashPort(port uint16) uint32 {
	hash := uint32(2166136261)
	hash ^= uint32(port & 0xFF)
	hash *= 16777619
	hash ^= uint32((port >> 8) & 0xFF)
	hash *= 16777619
	return hash
}

// SetRule adds or updates a policy rule in the BPF map. Patterns the kernel
// cannot match exactly are refused with ErrNotKernelMatchable.
func (m *PolicyMapManager) SetRule(cgroupID uint64, eventType uint8, pattern string, action uint8, audit bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	hash, err := ruleHash(eventType, pattern)
	if err != nil {
		return err
	}

	key := PolicyKey{
		CgroupID:  cgroupID,
		RuleHash:  hash,
		EventType: eventType,
	}

	auditByte := uint8(0)
	if audit {
		auditByte = 1
	}

	val := PolicyValue{
		Action: action,
		Audit:  auditByte,
	}

	return m.policyMap.Put(key, val)
}

// SetNetworkRule adds a network rule using IP+port hash.
func (m *PolicyMapManager) SetNetworkRule(cgroupID uint64, addrHash uint32, action uint8, audit bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := PolicyKey{
		CgroupID:  cgroupID,
		RuleHash:  addrHash,
		EventType: EventTypeNetwork,
	}

	auditByte := uint8(0)
	if audit {
		auditByte = 1
	}

	val := PolicyValue{
		Action: action,
		Audit:  auditByte,
	}

	return m.policyMap.Put(key, val)
}

// SetEndpointRule adds a connect or bind rule for addr:port (port in host
// order), keyed exactly as lsm_connect/lsm_bind look it up.
func (m *PolicyMapManager) SetEndpointRule(cgroupID uint64, eventType uint8, addr string, port uint16, action uint8, audit bool) error {
	if eventType != EventTypeNetwork && eventType != EventTypeBind {
		return fmt.Errorf("event type %d is not an endpoint event: %w", eventType, ErrNotKernelMatchable)
	}
	hash, err := endpointHash(addr, port)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := PolicyKey{
		CgroupID:  cgroupID,
		RuleHash:  hash,
		EventType: eventType,
	}

	auditByte := uint8(0)
	if audit {
		auditByte = 1
	}

	val := PolicyValue{
		Action: action,
		Audit:  auditByte,
	}

	return m.policyMap.Put(key, val)
}

// DeleteRule removes a policy rule from the BPF map.
func (m *PolicyMapManager) DeleteRule(cgroupID uint64, eventType uint8, pattern string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	hash, err := ruleHash(eventType, pattern)
	if err != nil {
		return err
	}

	key := PolicyKey{
		CgroupID:  cgroupID,
		RuleHash:  hash,
		EventType: eventType,
	}

	return m.policyMap.Delete(key)
}

// Clear removes all entries from the policy map.
func (m *PolicyMapManager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var key PolicyKey
	iter := m.policyMap.Iterate()
	var keysToDelete []PolicyKey
	for iter.Next(&key, new(PolicyValue)) {
		keysToDelete = append(keysToDelete, key)
	}

	for _, k := range keysToDelete {
		_ = m.policyMap.Delete(k)
	}
	return nil
}

// SyncFromWASM batch-updates the policy map from WASM evaluation results.
func (m *PolicyMapManager) SyncFromWASM(decisions []CachedDecision) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, d := range decisions {
		hash, err := ruleHash(d.EventType, d.Pattern)
		if err != nil {
			// Not expressible in the kernel map; userspace still enforces it.
			continue
		}
		key := PolicyKey{
			CgroupID:  d.CgroupID,
			RuleHash:  hash,
			EventType: d.EventType,
		}

		auditByte := uint8(0)
		if d.Audit {
			auditByte = 1
		}

		val := PolicyValue{
			Action: d.Action,
			Audit:  auditByte,
		}

		if err := m.policyMap.Put(key, val); err != nil {
			return fmt.Errorf("set rule for pattern %q: %w", d.Pattern, err)
		}
	}
	return nil
}

// Stats returns the current number of entries in the policy map.
func (m *PolicyMapManager) Stats() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	var key PolicyKey
	iter := m.policyMap.Iterate()
	for iter.Next(&key, new(PolicyValue)) {
		count++
	}
	return count, nil
}

// SetEnforce updates the lsm_enforce map to enable/disable kernel blocking.
func SetEnforce(enforceMap *ebpf.Map, enabled bool) error {
	key := uint32(0)
	val := uint8(0)
	if enabled {
		val = 1
	}
	return enforceMap.Put(key, val)
}

// SetLSMCgroupFilter populates the LSM cgroup filter map.
func SetLSMCgroupFilter(filterMap *ebpf.Map, ids []uint64) error {
	// Clear existing
	var key uint64
	iter := filterMap.Iterate()
	for iter.Next(&key, new(uint8)) {
		_ = filterMap.Delete(key)
	}

	if len(ids) == 0 {
		return nil
	}

	// Insert sentinel
	var sentinel uint64
	val := uint8(1)
	if err := filterMap.Put(sentinel, val); err != nil {
		return fmt.Errorf("set lsm cgroup filter sentinel: %w", err)
	}

	for _, id := range ids {
		if err := filterMap.Put(id, val); err != nil {
			return fmt.Errorf("set lsm cgroup filter id %d: %w", id, err)
		}
	}
	return nil
}

// Ensure PolicyKey is serialized correctly for BPF map operations
func (k PolicyKey) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 16)
	binary.NativeEndian.PutUint64(buf[0:8], k.CgroupID)
	binary.NativeEndian.PutUint32(buf[8:12], k.RuleHash)
	buf[12] = k.EventType
	buf[13] = 0
	buf[14] = 0
	buf[15] = 0
	return buf, nil
}
