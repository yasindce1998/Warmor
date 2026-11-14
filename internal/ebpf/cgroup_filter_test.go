//go:build linux

package ebpf

import (
	"errors"
	"strings"
	"testing"
)

type fakeCgroupFilter struct {
	entries                                     map[uint64]bool
	failPut, failDelete, failList, sentinelLost bool
}

func (m *fakeCgroupFilter) keys() ([]uint64, error) {
	if m.failList {
		return nil, errors.New("iterate failure")
	}
	var ids []uint64
	for id := range m.entries {
		ids = append(ids, id)
	}
	return ids, nil
}
func (m *fakeCgroupFilter) put(id uint64) error {
	if m.failPut && id != 0 {
		return errors.New("write failure")
	}
	m.entries[id] = true
	return nil
}
func (m *fakeCgroupFilter) delete(id uint64) error {
	if m.failDelete {
		return errors.New("delete failure")
	}
	delete(m.entries, id)
	if !m.entries[0] {
		m.sentinelLost = true
	}
	return nil
}
func TestCgroupFilterReconcileNeverDisablesScope(t *testing.T) {
	m := &fakeCgroupFilter{entries: map[uint64]bool{0: true, 1: true, 2: true}}
	for _, ids := range [][]uint64{{2, 3}, {}, {4, 5}, {5}} {
		if err := replaceCgroupFilter(m, ids, true); err != nil {
			t.Fatal(err)
		}
		if !m.entries[0] || m.sentinelLost || len(m.entries) != len(ids)+1 {
			t.Fatal(m.entries)
		}
		for _, id := range ids {
			if !m.entries[id] {
				t.Fatal(id)
			}
		}
	}
}
func TestCgroupFilterFailuresPreserveSentinel(t *testing.T) {
	for _, kind := range []string{"put", "delete", "list", "capacity", "zero", "transition"} {
		t.Run(kind, func(t *testing.T) {
			m := &fakeCgroupFilter{entries: map[uint64]bool{0: true, 1: true}, failPut: kind == "put", failDelete: kind == "delete", failList: kind == "list"}
			ids := []uint64{2}
			if kind == "capacity" {
				ids = make([]uint64, CgroupFilterCapacity+1)
				for i := range ids {
					ids[i] = uint64(i + 1)
				}
			}
			if kind == "transition" {
				for i := 1; i <= CgroupFilterCapacity; i++ {
					m.entries[uint64(i)] = true
				}
				ids = []uint64{99999}
			}
			if kind == "zero" {
				ids = []uint64{0}
			}
			err := replaceCgroupFilter(m, ids, true)
			if err == nil || !m.entries[0] || m.sentinelLost {
				t.Fatalf("err=%v, map=%v", err, m.entries)
			}
			if kind == "put" && !m.entries[1] {
				t.Fatal("failed add removed coverage")
			}
			if (kind == "capacity" || kind == "transition") && (!strings.Contains(err.Error(), "capacity") || !m.entries[1]) {
				t.Fatal(err, m.entries)
			}
		})
	}
}
