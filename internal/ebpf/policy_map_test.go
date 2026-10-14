//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
)

// fakeBackend is an in-memory policyMapBackend.
type fakeBackend struct {
	entries   map[PolicyKey]PolicyValue
	deleteErr map[PolicyKey]error
	iterErr   error
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{entries: map[PolicyKey]PolicyValue{}, deleteErr: map[PolicyKey]error{}}
}

func (f *fakeBackend) Put(key, value any) error {
	f.entries[key.(PolicyKey)] = value.(PolicyValue)
	return nil
}

func (f *fakeBackend) Delete(key any) error {
	k := key.(PolicyKey)
	if err := f.deleteErr[k]; err != nil {
		return err
	}
	if _, ok := f.entries[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(f.entries, k)
	return nil
}

func (f *fakeBackend) keys() ([]PolicyKey, error) {
	var ks []PolicyKey
	for k := range f.entries {
		ks = append(ks, k)
	}
	return ks, f.iterErr
}

func TestClear_RemovesAllEntries(t *testing.T) {
	b := newFakeBackend()
	m := &PolicyMapManager{policyMap: b}
	for i := 0; i < 5; i++ {
		if err := m.SetRule(uint64(i), EventTypeExec, fmt.Sprintf("/bin/p%d", i), ActionDeny, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if n, _ := m.Stats(); n != 0 {
		t.Fatalf("%d entries left after Clear", n)
	}
}

func TestClear_ReturnsDeleteErrors(t *testing.T) {
	b := newFakeBackend()
	m := &PolicyMapManager{policyMap: b}
	_ = m.SetRule(1, EventTypeExec, "/bin/a", ActionDeny, false)
	_ = m.SetRule(1, EventTypeExec, "/bin/b", ActionDeny, false)
	stuck := PolicyKey{CgroupID: 1, RuleHash: HashPattern("/bin/a"), EventType: EventTypeExec}
	boom := errors.New("EPERM")
	b.deleteErr[stuck] = boom

	err := m.Clear()
	if !errors.Is(err, boom) {
		t.Fatalf("Clear err = %v, want delete failure", err)
	}
	// Every other key is still attempted.
	if len(b.entries) != 1 {
		t.Fatalf("entries left = %d, want only the undeletable one", len(b.entries))
	}
}

func TestClear_IgnoresVanishedKeysButReportsIterErrors(t *testing.T) {
	b := newFakeBackend()
	m := &PolicyMapManager{policyMap: b}
	_ = m.SetRule(1, EventTypeExec, "/bin/a", ActionDeny, false)
	k := PolicyKey{CgroupID: 1, RuleHash: HashPattern("/bin/a"), EventType: EventTypeExec}
	// Simulate LRU eviction between iteration and delete.
	b.deleteErr[k] = fmt.Errorf("lookup: %w", ebpf.ErrKeyNotExist)
	if err := m.Clear(); err != nil {
		t.Fatalf("vanished key must not fail Clear: %v", err)
	}

	b.iterErr = errors.New("iteration aborted")
	if err := m.Clear(); err == nil {
		t.Fatal("iteration error must be returned")
	}
}

func TestClear_NilMap(t *testing.T) {
	if err := NewPolicyMapManager(nil).Clear(); err == nil {
		t.Fatal("Clear on an unloaded map must fail, not pretend success")
	}
}

// TestPolicyMapIsLRU checks every compiled LSM object declares policy_map as
// an LRU hash, so a full map evicts instead of refusing new decisions. It
// only parses the embedded ELF; no kernel is needed.
func TestPolicyMapIsLRU(t *testing.T) {
	loaders := map[string]func() (*ebpf.CollectionSpec, error){
		"exec": loadLsm_exec, "file": loadLsm_file, "connect": loadLsm_connect,
		"bind": loadLsm_bind, "listen": loadLsm_listen, "ptrace": loadLsm_ptrace,
		"mount": loadLsm_mount,
	}
	for name, load := range loaders {
		spec, err := load()
		if err != nil {
			t.Fatalf("%s: load spec: %v", name, err)
		}
		m, ok := spec.Maps["policy_map"]
		if !ok {
			t.Fatalf("%s: no policy_map", name)
		}
		if m.Type != ebpf.LRUHash {
			t.Errorf("%s: policy_map type = %v, want LRUHash", name, m.Type)
		}
		if m.MaxEntries != 65536 {
			t.Errorf("%s: policy_map max_entries = %d", name, m.MaxEntries)
		}
	}
}
