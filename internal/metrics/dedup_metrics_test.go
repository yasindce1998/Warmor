package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The correlation layer records a duplicate only when it confidently pairs a
// tracepoint with its LSM twin. This counter must be a plain labelled counter
// so operators can alert on double-observation suppression per event type.
func TestRecordDuplicateEvent(t *testing.T) {
	for _, eventType := range []string{"exec", "file", "network"} {
		before := testutil.ToFloat64(DuplicateEvents.WithLabelValues(eventType))
		RecordDuplicateEvent(eventType)
		RecordDuplicateEvent(eventType)
		after := testutil.ToFloat64(DuplicateEvents.WithLabelValues(eventType))
		if after != before+2 {
			t.Fatalf("%s duplicate counter = %v, want %v", eventType, after, before+2)
		}
	}
}
