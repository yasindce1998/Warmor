//go:build windows

package efw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"

	"github.com/yasindce1998/warmor/internal/kernelmap"
	"github.com/yasindce1998/warmor/internal/platform/winutil"
	"github.com/yasindce1998/warmor/pkg/api"
)

// ErrNotKernelMatchable is returned for decisions the kernel programs could
// not apply exactly, so they are left to userspace.
var ErrNotKernelMatchable = kernelmap.ErrNotKernelMatchable

// PolicyMap writes WASM decisions into the kernel maps so the next identical
// operation is decided in the kernel, synchronously.
//
// Keys always include the image: a decision only applies to the executable
// it was made for.
type PolicyMap struct {
	paths *winutil.DevicePathMap
	procs *winutil.ProcTable

	procDeny  *ebpf.Map // nil without the process hook
	netPolicy *ebpf.Map // nil without the network hooks
	procInfo  *ebpf.Map
}

// SetRule implements enforcer.PolicyMapSyncer for process rules keyed on the
// image path (event type 0). Other event types need the full event; see
// SyncEvent.
func (m *PolicyMap) SetRule(_ uint64, eventType uint8, pattern string, action uint8, audit bool) error {
	if eventType != 0 {
		return fmt.Errorf("event type %d: %w", eventType, ErrNotKernelMatchable)
	}
	return m.setProcess(winutil.ImageHash(m.paths.Untranslate(pattern)), action, audit)
}

// SyncEvent writes the decision for one event. Preferred over SetRule by the
// enforcer because network keys need the process image, which the generic
// SetRule/SetEndpointRule calls do not carry.
func (m *PolicyMap) SyncEvent(ev *api.Event, action uint8, audit bool) error {
	switch ev.GetType() {
	case api.EventTypeProcess:
		return m.setProcess(m.imageHash(ev.PID, ev.Filename), action, audit)

	case api.EventTypeNetwork:
		if m.netPolicy == nil || ev.Network == nil {
			return ErrNotKernelMatchable
		}
		addr, err := netip.ParseAddr(ev.Network.RemoteAddr)
		if err != nil {
			return fmt.Errorf("%w: remote address %q", ErrNotKernelMatchable, ev.Network.RemoteAddr)
		}
		key, err := netKey(m.imageHash(ev.PID, ev.Filename), ev.Network.Operation, ev.Network.Protocol,
			netip.AddrPortFrom(addr, ev.Network.RemotePort))
		if err != nil {
			return fmt.Errorf("%w: %v", ErrNotKernelMatchable, err)
		}
		return m.put(m.netPolicy, key, action, audit)

	default:
		// No eBPF-for-Windows file hook exists.
		return ErrNotKernelMatchable
	}
}

// imageHash resolves the NT image of the process an event came from. The
// process table holds the exact path the kernel reported; the drive-letter
// path is only reversed as a fallback.
func (m *PolicyMap) imageHash(pid uint32, image string) uint64 {
	if p, ok := m.procs.Get(pid); ok && p.NTImage != "" && (image == "" || p.Image == image) {
		return winutil.ImageHash(p.NTImage)
	}
	if image == "" {
		return 0
	}
	return winutil.ImageHash(m.paths.Untranslate(image))
}

func (m *PolicyMap) setProcess(hash uint64, action uint8, audit bool) error {
	if m.procDeny == nil {
		return ErrNotKernelMatchable
	}
	if hash == 0 {
		return fmt.Errorf("%w: image path not hashable", ErrNotKernelMatchable)
	}
	return m.put(m.procDeny, u64Bytes(hash), action, audit)
}

// put writes a deny (or audit-deny) rule, or deletes the key for an allow:
// the kernel default is to allow.
func (m *PolicyMap) put(mp *ebpf.Map, key []byte, action uint8, audit bool) error {
	if action == 0 {
		if err := mp.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		return nil
	}
	return mp.Put(key, policyValue(true, audit))
}

// TrackProcess tells the network hooks which image a PID runs. Called for
// processes seen by ETW or the startup snapshot; processes reported by the
// eBPF process hook are tracked as their records arrive.
func (m *PolicyMap) TrackProcess(info winutil.ProcInfo) {
	m.trackHash(info.PID, winutil.ImageHash(info.NTImage))
}

func (m *PolicyMap) trackHash(pid uint32, hash uint64) {
	if m == nil || m.procInfo == nil || hash == 0 {
		return
	}
	_ = m.procInfo.Put(u32Bytes(pid), u64Bytes(hash))
}

// ForgetProcess drops a PID from the network hooks' process map, so a reused
// PID never inherits another image's rules.
func (m *PolicyMap) ForgetProcess(pid uint32) {
	if m == nil || m.procInfo == nil {
		return
	}
	_ = m.procInfo.Delete(u32Bytes(pid))
}

func u64Bytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

func u32Bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// Clear implements enforcer.PolicyMapSyncer: it removes every decision the
// previous policy compiled into the kernel maps, so a reload never leaves the
// kernel enforcing stale rules. Per-PID image tracking (procInfo) is not a
// policy decision and is kept. All deletes are attempted; failures are
// returned joined.
func (m *PolicyMap) Clear() error {
	var errs []error
	for _, mp := range []*ebpf.Map{m.procDeny, m.netPolicy} {
		if mp == nil {
			continue
		}
		if err := clearMap(mp); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func clearMap(mp *ebpf.Map) error {
	var (
		keys [][]byte
		errs []error
	)
	key := make([]byte, mp.KeySize())
	val := make([]byte, mp.ValueSize())
	iter := mp.Iterate()
	for iter.Next(&key, &val) {
		keys = append(keys, append([]byte(nil), key...))
	}
	if err := iter.Err(); err != nil {
		errs = append(errs, fmt.Errorf("iterate policy map: %w", err))
	}
	for _, k := range keys {
		if err := mp.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete policy map key %x: %w", k, err))
		}
	}
	return errors.Join(errs...)
}

// KernelKeyFields reports which event fields (compiler field names) the
// kernel keys cover. Process keys are the image path; network keys are the
// image plus operation, protocol and remote endpoint (the image is not a
// policy-visible field of network events, so it only narrows the key).
func (m *PolicyMap) KernelKeyFields(t api.EventType) []string {
	switch t {
	case api.EventTypeProcess:
		return []string{"path"}
	case api.EventTypeNetwork:
		return []string{"operation", "protocol", "remote_addr", "remote_port"}
	default:
		return nil
	}
}
