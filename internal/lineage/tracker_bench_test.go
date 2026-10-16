package lineage

import "testing"

// BenchmarkRecordExec measures RecordExec of new PIDs into a tracker that is
// already at its default capacity (100000), which is the steady state of a
// long-running daemon: nothing calls RecordExit, so every exec of a new PID
// evicts one.
func BenchmarkRecordExec(b *testing.B) {
	tr := NewTracker(TrackerConfig{})
	const full = 100000
	for pid := uint32(1); pid <= full; pid++ {
		tr.RecordExec(pid, 0, 1000, 1000, "sh", "/bin/sh")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		tr.RecordExec(uint32(full+1+i), 0, 1000, 1000, "sh", "/bin/sh")
	}
}
