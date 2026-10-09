//go:build linux

package ebpf

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestComputeBootTimeOffset(t *testing.T) {
	off := computeBootTimeOffset()
	if off <= 0 {
		t.Fatalf("computeBootTimeOffset() = %v, want positive (wall clock > monotonic)", off)
	}

	// Converting the current CLOCK_MONOTONIC reading (what bpf_ktime_get_ns
	// returns) must land close to time.Now().
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatalf("ClockGettime: %v", err)
	}
	got := bootTimeToWallClock(uint64(ts.Nano()))
	if d := time.Since(got); d < -time.Second || d > time.Second {
		t.Errorf("bootTimeToWallClock(now) off by %v", d)
	}
}
