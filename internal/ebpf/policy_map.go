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
	"unicode/utf8"

	"github.com/cilium/ebpf"

	"github.com/yasindce1998/warmor/internal/kernelmap"
	"github.com/yasindce1998/warmor/pkg/api"
)

// PolicyKey matches struct policy_key in warmor_lsm.h
type PolicyKey struct {
	CgroupID  uint64
	EventType uint8
	Family    uint8
	Port      [2]byte // network byte order on every architecture
	Address   [16]byte
	Path      [256]byte
	Pad       [4]uint8
}

// PolicyValue matches struct policy_value in warmor_lsm.h
type PolicyValue struct {
	Action   uint8
	Audit    uint8
	Pad      uint16
	HitCount uint32
}

// DefaultDenyKey matches struct default_deny_key in warmor_lsm.h.
type DefaultDenyKey struct {
	CgroupID  uint64
	EventType uint8
	Pad       [7]uint8
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
	policyMap policyMapBackend
	// defaultDenyMap marks (cgroup, event_type) domains whose policy-map
	// entries are a complete allowlist; a miss in a marked domain is denied
	// by the BPF programs. Nil when the loaded objects predate the map (or
	// in tests): default-deny is then unavailable and Clear is a no-op for
	// it. See docs/design/kernel-default-deny.md.
	defaultDenyMap defaultDenyBackend
	mu             sync.Mutex
}

// setDefaultDenyMap attaches the kernel default_deny map. Called by the LSM
// loader right after NewPolicyMapManager; not exported because the marking
// API below is the only supported writer.
func (m *PolicyMapManager) setDefaultDenyMap(dd *ebpf.Map) {
	if dd == nil {
		return
	}
	m.defaultDenyMap = kernelDefaultDenyMap{dd}
}

// defaultDenyBackend is the subset of *ebpf.Map the default-deny map uses.
type defaultDenyBackend interface {
	Put(key, value any) error
	Delete(key any) error
	// ddKeys returns every key currently in the map.
	ddKeys() ([]DefaultDenyKey, error)
}

// kernelDefaultDenyMap adapts a loaded *ebpf.Map to defaultDenyBackend.
type kernelDefaultDenyMap struct{ *ebpf.Map }

func (m kernelDefaultDenyMap) ddKeys() ([]DefaultDenyKey, error) {
	var (
		key  DefaultDenyKey
		keys []DefaultDenyKey
	)
	iter := m.Iterate()
	for iter.Next(&key, new(uint8)) {
		keys = append(keys, key)
	}
	return keys, iter.Err()
}

// SetDefaultDeny marks the global (cgroup_id = 0) domain for eventType as
// default-deny: the BPF programs deny a policy-map miss for it. mode is
// DefaultDenyModeDeny or DefaultDenyModeAudit.
func (m *PolicyMapManager) SetDefaultDeny(eventType uint8, mode uint8) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.defaultDenyMap == nil {
		return errors.New("default-deny map not loaded")
	}
	if mode != DefaultDenyModeDeny && mode != DefaultDenyModeAudit {
		return fmt.Errorf("invalid default-deny mode %d", mode)
	}
	return m.defaultDenyMap.Put(DefaultDenyKey{EventType: eventType}, mode)
}

// ClearDefaultDeny unmarks every default-deny domain. Called before the
// policy map is rebuilt so misses allow (today's behaviour) while the new
// allowlist is preloaded; the marking goes back in only after the entries.
func (m *PolicyMapManager) ClearDefaultDeny() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.defaultDenyMap == nil {
		return nil
	}
	keys, err := m.defaultDenyMap.ddKeys()
	var errs []error
	if err != nil {
		errs = append(errs, fmt.Errorf("iterate default-deny map: %w", err))
	}
	for _, k := range keys {
		if err := m.defaultDenyMap.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete default-deny key %+v: %w", k, err))
		}
	}
	return errors.Join(errs...)
}

// policyMapBackend is the subset of *ebpf.Map the manager uses, so the
// userspace logic can be tested without loading BPF into a kernel.
type policyMapBackend interface {
	Put(key, value any) error
	Delete(key any) error
	// keys returns every key currently in the map.
	keys() ([]PolicyKey, error)
}

// kernelPolicyMap adapts a loaded *ebpf.Map to policyMapBackend.
type kernelPolicyMap struct{ *ebpf.Map }

func (m kernelPolicyMap) keys() ([]PolicyKey, error) {
	var (
		key  PolicyKey
		keys []PolicyKey
	)
	iter := m.Iterate()
	for iter.Next(&key, new(PolicyValue)) {
		keys = append(keys, key)
	}
	return keys, iter.Err()
}

// NewPolicyMapManager wraps an existing BPF map.
func NewPolicyMapManager(m *ebpf.Map) *PolicyMapManager {
	if m == nil {
		return &PolicyMapManager{}
	}
	return &PolicyMapManager{policyMap: kernelPolicyMap{m}}
}

// HashPattern is retained for the observation-only unix_watch map and legacy
// callers. Hashes are NOT accepted as security policy identities.
func HashPattern(pattern string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(pattern))
	return h.Sum32()
}

// Per-domain caps for string-keyed policy identities. These bound what may be
// written into the kernel policy map; they are NOT the raw sizes of the BPF
// sensor buffers.
//
// The exec cap is the shared exact-path identity limit, 127 bytes
// (kernelmap.MaxPolicyPathBytes), NOT the 254 bytes that lsm_exec's
// policy_key.path[256] could physically hold. The binary WASM ABI exposes only
// 128 primary-string bytes and reserves one for the truncation/NUL boundary.
// Accepting a 128..254-byte key would let a raw/external writer install a
// kernel allow for a path WASM only ever saw as a truncated prefix, breaking
// the complete-allowlist proof that kernel default-deny depends on. Userspace
// evaluation is unaffected: WASM still sees the full path; only kernel-map
// writes beyond 127 bytes are refused, never silently truncated. See
// docs/design/kernel-default-deny.md. Mount and ptrace are tighter still,
// bounded by their own sensor buffers.
const (
	maxExecPatternLen   = kernelmap.MaxPolicyPathBytes // 127: WASM ABI 128 minus one reserved byte, not the 256-byte BPF key buffer
	maxMountPatternLen  = 62                           // lsm_mount type_buf[64]
	maxPtracePatternLen = 15                           // task comm, TASK_COMM_LEN 16 (never truncated)
)

// ErrNotKernelMatchable is returned for rules the BPF programs could never
// match exactly. Such rules are refused rather than written: a key that only
// covers part of what userspace decided on would apply the decision to other
// events, which is worse than no kernel fast-path at all.
var ErrNotKernelMatchable = kernelmap.ErrNotKernelMatchable

// stringPolicyKey preserves every byte, with a zero-padded tail. No path
// cleaning, symlink resolution, or basename substitution is performed.
// Patterns longer than the shared exact-input limit are refused outright:
// truncating one would make a partial path a reusable kernel identity that
// WASM never evaluated in full.
func stringPolicyKey(cgroupID uint64, eventType uint8, pattern string) (PolicyKey, error) {
	key := PolicyKey{CgroupID: cgroupID, EventType: eventType}
	// Enforce the 127-byte identity limit for every string-keyed domain before
	// the per-domain switch. The BPF key buffer is 256 bytes, but only the
	// first 127 are a valid complete identity (binary WASM ABI: 128 bytes with
	// one reserved); anything longer must not reach the kernel map.
	if len(pattern) > kernelmap.MaxPolicyPathBytes {
		return key, fmt.Errorf("pattern of %d bytes for event type %d exceeds kernel identity limit %d: %w",
			len(pattern), eventType, kernelmap.MaxPolicyPathBytes, ErrNotKernelMatchable)
	}
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
		return key, fmt.Errorf("file event: %w", ErrNotKernelMatchable)
	default:
		return key, fmt.Errorf("event type %d is not keyed by string: %w", eventType, ErrNotKernelMatchable)
	}
	// The sensor and WASM both treat NUL as the end of a string.
	if pattern == "" || len(pattern) > maxLen || strings.IndexByte(pattern, 0) >= 0 || !utf8.ValidString(pattern) {
		return key, fmt.Errorf("pattern %q for event type %d: %w", pattern, eventType, ErrNotKernelMatchable)
	}
	copy(key.Path[:], pattern)
	return key, nil
}

func endpointPolicyKey(cgroupID uint64, eventType uint8, addr string, port uint16) (PolicyKey, error) {
	key := PolicyKey{CgroupID: cgroupID, EventType: eventType}
	if eventType != EventTypeNetwork && eventType != EventTypeBind {
		return key, fmt.Errorf("event type %d is not an endpoint event: %w", eventType, ErrNotKernelMatchable)
	}
	ip := net.ParseIP(addr)
	// Policy eq compares the sensor's canonical string, not semantic IP
	// equality. Other spellings could preload a rule WASM never matches.
	if ip == nil || ip.String() != addr {
		return key, fmt.Errorf("noncanonical endpoint address %q: %w", addr, ErrNotKernelMatchable)
	}
	binary.BigEndian.PutUint16(key.Port[:], port)
	if ip4 := ip.To4(); ip4 != nil {
		key.Family = 2
		copy(key.Address[:4], ip4)
	} else {
		key.Family = 10
		copy(key.Address[:], ip.To16())
	}
	return key, nil
}

// HashIPv4Endpoint is a legacy hash helper, not a security identity.
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

// HashIPv6Endpoint is a legacy hash helper, not a security identity.
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

// HashPort is a legacy hash helper, not a security identity.
func HashPort(port uint16) uint32 {
	hash := uint32(2166136261)
	hash ^= uint32(port & 0xFF)
	hash *= 16777619
	hash ^= uint32((port >> 8) & 0xFF)
	hash *= 16777619
	return hash
}

// SetRule adds or updates a policy rule in the BPF map. Patterns the kernel
// cannot match exactly — including exec paths longer than
// kernelmap.MaxPolicyPathBytes (127) — are refused with ErrNotKernelMatchable.
// They are never truncated to fit the 256-byte BPF key buffer: userspace WASM
// evaluation still sees the full path, but only kernel-map sync is refused.
func (m *PolicyMapManager) SetRule(cgroupID uint64, eventType uint8, pattern string, action uint8, audit bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, err := stringPolicyKey(cgroupID, eventType, pattern)
	if err != nil {
		return err
	}

	auditByte := uint8(0)
	if audit {
		auditByte = 1
	}

	val := PolicyValue{
		Action: action,
		Audit:  auditByte,
	}

	return m.put(key, val)
}

// SetNetworkRule cannot safely reconstruct an endpoint from a hash.
// Deprecated: use SetEndpointRule. Retained only for source compatibility;
// it always returns ErrNotKernelMatchable and never modifies the map.
func (m *PolicyMapManager) SetNetworkRule(cgroupID uint64, addrHash uint32, action uint8, audit bool) error {
	return fmt.Errorf("hash-only endpoint rules are unsafe: %w", ErrNotKernelMatchable)
}

// SetEndpointRule adds a connect or bind rule for addr:port (port in host
// order), keyed exactly as lsm_connect/lsm_bind look it up.
func (m *PolicyMapManager) SetEndpointRule(cgroupID uint64, eventType uint8, addr string, port uint16, action uint8, audit bool) error {
	key, err := endpointPolicyKey(cgroupID, eventType, addr, port)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	auditByte := uint8(0)
	if audit {
		auditByte = 1
	}

	val := PolicyValue{
		Action: action,
		Audit:  auditByte,
	}

	return m.put(key, val)
}

// put requires mu. Unknown actions must never become kernel allows.
func (m *PolicyMapManager) put(key PolicyKey, val PolicyValue) error {
	if val.Action != ActionAllow && val.Action != ActionDeny {
		return fmt.Errorf("invalid policy action %d", val.Action)
	}
	if m.policyMap == nil {
		return errors.New("policy map not loaded")
	}
	return m.policyMap.Put(key, val)
}

// DeleteRule removes a policy rule from the BPF map.
func (m *PolicyMapManager) DeleteRule(cgroupID uint64, eventType uint8, pattern string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, err := stringPolicyKey(cgroupID, eventType, pattern)
	if err != nil {
		return err
	}

	if m.policyMap == nil {
		return errors.New("policy map not loaded")
	}
	return m.policyMap.Delete(key)
}

// Clear removes all entries from the policy map. Every delete is attempted;
// failures (other than a key that vanished concurrently, e.g. by LRU
// eviction) are returned joined, so a caller never believes stale kernel
// decisions are gone when they are not.
func (m *PolicyMapManager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.policyMap == nil {
		return errors.New("policy map not loaded")
	}

	keysToDelete, err := m.policyMap.keys()
	var errs []error
	if err != nil {
		errs = append(errs, fmt.Errorf("iterate policy map: %w", err))
	}

	for _, k := range keysToDelete {
		if err := m.policyMap.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete policy map key %+v: %w", k, err))
		}
	}
	return errors.Join(errs...)
}

// SyncFromWASM batch-updates the policy map from WASM evaluation results.
func (m *PolicyMapManager) SyncFromWASM(decisions []CachedDecision) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, d := range decisions {
		// Evaluated inputs, not explicit static identities. Unknown scope
		// and ABI prefixes must not create reusable entries.
		if d.CgroupID == 0 || (d.EventType == EventTypeExec && len(d.Pattern) > kernelmap.MaxPolicyPathBytes) {
			continue
		}
		key, err := stringPolicyKey(d.CgroupID, d.EventType, d.Pattern)
		if err != nil {
			// Not expressible in the kernel map; userspace still enforces it.
			continue
		}
		auditByte := uint8(0)
		if d.Audit {
			auditByte = 1
		}

		val := PolicyValue{
			Action: d.Action,
			Audit:  auditByte,
		}

		if err := m.put(key, val); err != nil {
			return fmt.Errorf("set rule for pattern %q: %w", d.Pattern, err)
		}
	}
	return nil
}

// Stats returns the current number of entries in the policy map.
func (m *PolicyMapManager) Stats() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.policyMap == nil {
		return 0, errors.New("policy map not loaded")
	}
	keys, err := m.policyMap.keys()
	return len(keys), err
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
	return replaceCgroupFilter(kernelCgroupFilter{filterMap}, ids, len(ids) > 0)
}

// Ensure PolicyKey is serialized correctly for BPF map operations
func (k PolicyKey) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 288)
	binary.NativeEndian.PutUint64(buf[0:8], k.CgroupID)
	buf[8] = k.EventType
	buf[9] = k.Family
	copy(buf[10:12], k.Port[:])
	copy(buf[12:28], k.Address[:])
	copy(buf[28:284], k.Path[:])
	return buf, nil
}

// SyncEvent is the enforcer's dynamic-decision entry point. It must prove
// completeness in both the sensor and binary WASM ABI; explicit static-rule
// writes instead use SetRule/SetEndpointRule. Unknown cgroups are not global.
func (m *PolicyMapManager) SyncEvent(event *api.Event, action uint8, audit bool) error {
	key, err := eventPolicyKey(event)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.put(key, generationPolicyValue(action, audit).Policy)
}

func eventPolicyKey(event *api.Event) (PolicyKey, error) {
	if event == nil || event.CgroupID == 0 {
		return PolicyKey{}, fmt.Errorf("missing event scope: %w", ErrNotKernelMatchable)
	}
	switch event.GetType() {
	case api.EventTypeProcess:
		if event.Hook != "" && event.Hook != "exec" {
			break
		}
		path := event.Filename
		if event.Process != nil {
			path = event.Process.Filename
		}
		if len(path) > kernelmap.MaxPolicyPathBytes {
			break
		}
		return stringPolicyKey(event.CgroupID, EventTypeExec, path)
	case api.EventTypeNetwork:
		if event.Network == nil {
			break
		}
		// Bind and connect are distinct kernel domains (EVENT_TYPE_BIND vs
		// EVENT_TYPE_NETWORK) with the same exact {family, addr, port} key.
		// The live sensor reports Operation="connect" for bind events, so the
		// hook — not the operation — is what separates them. Syncing a bind
		// decision under the connect key would apply it to connects WASM
		// never evaluated, and vice versa.
		if event.Hook == "bind" {
			return endpointPolicyKey(event.CgroupID, EventTypeBind, event.Network.RemoteAddr, event.Network.RemotePort)
		}
		if event.Network.Operation != "connect" ||
			(event.Hook != "" && event.Hook != "connect") {
			break
		}
		return endpointPolicyKey(event.CgroupID, EventTypeNetwork, event.Network.RemoteAddr, event.Network.RemotePort)
	}
	return PolicyKey{}, fmt.Errorf("incomplete or unsupported event identity: %w", ErrNotKernelMatchable)
}

// KernelKeyFields reports which event fields (compiler field names) the BPF
// programs' policy_map key covers per event type, besides the cgroup: the
// exec filename for process events and the remote endpoint for connects.
// File events are never keyed (lsm_file only sees the basename). The
// enforcer only syncs decisions that depend on nothing else.
//
// This is the hook-agnostic view kept for interface compatibility with maps
// whose keys do not vary by hook. For Linux decisions, KernelKeyFieldsForEvent
// is authoritative: it additionally separates the bind key from the connect
// key and refuses hooks with no exact kernel identity.
func (m *PolicyMapManager) KernelKeyFields(t api.EventType) []string {
	switch t {
	case api.EventTypeProcess:
		return []string{"path"}
	case api.EventTypeNetwork:
		return []string{"remote_addr", "remote_port"}
	default:
		return nil
	}
}

// KernelKeyFieldsForEvent is the hook-aware form of KernelKeyFields. It
// reports the compiler field names the kernel policy-map key covers for this
// exact event, so the enforcer can prove a decision is fully determined by
// the key before writing it back.
//
// Bind is a separate kernel domain keyed by the same exact endpoint as
// connect. It is only matchable for Hook=="bind" and only when the decision
// depends on nothing beyond {remote_addr, remote_port}: the BPF key carries
// no other policy-visible field. In particular, network policies must not
// read `operation` on bind for now — the live sensor reports Operation
// "connect" for bind events, so a decision that branches on `operation`
// cannot be reproduced by the kernel's bind key and is refused rather than
// applied to other events. Other network hooks (connect_unix, listen) have
// no exact policy-map key and are never synced.
func (m *PolicyMapManager) KernelKeyFieldsForEvent(event *api.Event) []string {
	if event == nil {
		return nil
	}
	switch event.GetType() {
	case api.EventTypeProcess:
		if event.Hook != "" && event.Hook != "exec" {
			return nil
		}
		return []string{"path"}
	case api.EventTypeNetwork:
		switch event.Hook {
		case "", "connect", "bind":
			return []string{"remote_addr", "remote_port"}
		default:
			// connect_unix, listen and any future hook have no exact key.
			return nil
		}
	default:
		return nil
	}
}
