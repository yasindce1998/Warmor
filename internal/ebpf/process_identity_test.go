package ebpf

import "testing"

func TestTracepointEventsPreserveRawKernelTimestamp(t *testing.T) {
	const stamp uint64 = 9876543210123
	for name, event := range map[string]Event{
		"exec":    (&ExecveEvent{Timestamp: stamp}).ToEvent(),
		"file":    (&OpenatEvent{Timestamp: stamp}).ToEvent(),
		"network": (&ConnectEvent{Timestamp: stamp}).ToEvent(),
	} {
		if event.KernelTimestampNS != stamp {
			t.Errorf("%s timestamp = %d, want %d", name, event.KernelTimestampNS, stamp)
		}
	}
}
