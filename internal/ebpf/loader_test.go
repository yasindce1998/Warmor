//go:build linux

package ebpf

import (
	"errors"
	"testing"
)

// fakePerCPUMap mimics *ebpf.Map.Lookup for a PERCPU_ARRAY slot without
// needing kernel privileges.
type fakePerCPUMap struct {
	values []uint64
	err    error
}

func (f fakePerCPUMap) Lookup(_, value any) error {
	if f.err != nil {
		return f.err
	}
	out, ok := value.(*[]uint64)
	if !ok {
		return errors.New("unexpected value type")
	}
	*out = f.values
	return nil
}

func TestSumTracepointDrops(t *testing.T) {
	got, err := sumTracepointDrops(fakePerCPUMap{values: []uint64{1, 3, 0, 7}})
	if err != nil {
		t.Fatalf("sumTracepointDrops: %v", err)
	}
	if got != 11 {
		t.Errorf("total = %d, want 11", got)
	}

	got, err = sumTracepointDrops(fakePerCPUMap{})
	if err != nil || got != 0 {
		t.Errorf("empty map = (%d, %v), want (0, nil)", got, err)
	}
}

func TestSumTracepointDropsLookupError(t *testing.T) {
	want := errors.New("lookup failed")
	if _, err := sumTracepointDrops(fakePerCPUMap{err: want}); !errors.Is(err, want) {
		t.Errorf("err = %v, want %v", err, want)
	}
}

func TestTracepointDropsUnloadedLoader(t *testing.T) {
	// A Loader with no objects loaded has no maps to read; it must return an
	// empty report rather than panic (test doubles rely on this).
	drops, err := (&Loader{}).TracepointDrops()
	if err != nil {
		t.Fatalf("TracepointDrops: %v", err)
	}
	if len(drops) != 0 {
		t.Errorf("drops = %v, want empty", drops)
	}
}
