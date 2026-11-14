//go:build linux

package ebpf

import "testing"

func TestLSMEventPreservesRawKernelTimestamp(t *testing.T) {
	const stamp uint64 = 9876543210123
	event := (&LSMEvent{Timestamp: stamp}).ToEvent()
	if event.KernelTimestampNS != stamp {
		t.Fatalf("timestamp = %d, want %d", event.KernelTimestampNS, stamp)
	}
}
