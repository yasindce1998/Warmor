//go:build linux

package ebpf

import (
	"fmt"
	"github.com/cilium/ebpf"
)

// CgroupFilterCapacity reserves the active-scope sentinel in the 1024-slot map.
const CgroupFilterCapacity = 1023

type cgroupFilterMap interface {
	keys() ([]uint64, error)
	put(uint64) error
	delete(uint64) error
}
type kernelCgroupFilter struct{ m *ebpf.Map }

func (m kernelCgroupFilter) keys() ([]uint64, error) {
	var keys []uint64
	var key uint64
	it := m.m.Iterate()
	for it.Next(&key, new(uint8)) {
		keys = append(keys, key)
	}
	return keys, it.Err()
}
func (m kernelCgroupFilter) put(id uint64) error    { return m.m.Put(id, uint8(1)) }
func (m kernelCgroupFilter) delete(id uint64) error { return m.m.Delete(id) }

// Scoped replacement never removes the sentinel, including for empty sets.
// Validate capacity before mutation and add before removing old coverage. Map
// failures are returned, not hidden; callers must withdraw readiness on error.
// Updates are not atomic across maps and may retain obsolete IDs until retry.
func replaceCgroupFilter(m cgroupFilterMap, ids []uint64, scoped bool) error {
	want := make(map[uint64]bool, len(ids))
	for _, id := range ids {
		if id == 0 {
			return fmt.Errorf("cgroup ID 0 is reserved for the filter sentinel")
		}
		want[id] = true
	}
	if len(want) > CgroupFilterCapacity {
		return fmt.Errorf("cgroup filter capacity exceeded: %d exact IDs, maximum %d", len(want), CgroupFilterCapacity)
	}
	keys, err := m.keys()
	if err != nil {
		return fmt.Errorf("list cgroup filter: %w", err)
	}
	existing := make(map[uint64]bool, len(keys))
	for _, id := range keys {
		if id != 0 {
			existing[id] = true
		}
	}
	union := len(existing)
	for id := range want {
		if !existing[id] {
			union++
		}
	}
	if union > CgroupFilterCapacity {
		return fmt.Errorf("cgroup filter transition capacity exceeded: %d old+new IDs, maximum %d", union, CgroupFilterCapacity)
	}
	if scoped {
		if err := m.put(0); err != nil {
			return fmt.Errorf("activate cgroup filter: %w", err)
		}
	}
	for id := range want {
		if !existing[id] {
			if err := m.put(id); err != nil {
				return fmt.Errorf("set cgroup filter ID %d (existing coverage retained): %w", id, err)
			}
		}
	}
	for _, id := range keys {
		if id == 0 && scoped || want[id] {
			continue
		}
		if err := m.delete(id); err != nil {
			return fmt.Errorf("remove cgroup filter ID %d: %w", id, err)
		}
	}
	return nil
}
