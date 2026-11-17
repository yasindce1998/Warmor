package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The Linux platform applies backpressure rather than dropping enforcement
// events. This counter is the visibility signal for a full userspace channel;
// it must be a plain counter that operators can alert on and it must not be
// conflated with StreamingLosses (which counts real sink/ingress drops).
func TestRecordEventChannelBackpressure(t *testing.T) {
	before := testutil.ToFloat64(EventChannelBackpressure)
	RecordEventChannelBackpressure()
	RecordEventChannelBackpressure()
	after := testutil.ToFloat64(EventChannelBackpressure)
	if after != before+2 {
		t.Fatalf("backpressure counter = %v, want %v", after, before+2)
	}
}
