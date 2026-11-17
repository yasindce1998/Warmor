package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The tracepoint drop counter makes a full ring buffer observable. It is a
// plain counter keyed by hook so operators can alert on loss per monitor.
func TestRecordTracepointEventsDropped(t *testing.T) {
	for _, hook := range []string{"execve", "openat", "connect"} {
		before := testutil.ToFloat64(TracepointEventsDropped.WithLabelValues(hook))
		RecordTracepointEventsDropped(hook, 3)
		RecordTracepointEventsDropped(hook, 2)
		after := testutil.ToFloat64(TracepointEventsDropped.WithLabelValues(hook))
		if after != before+5 {
			t.Errorf("%s: counter = %v, want %v", hook, after, before+5)
		}
	}
}
