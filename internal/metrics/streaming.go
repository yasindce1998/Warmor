package metrics

import "github.com/prometheus/client_golang/prometheus"

// Streaming labels are fixed boundary/operation and sink classes, never
// user-provided sink names, file paths or collector URLs.
var StreamingLosses = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "warmor", Subsystem: "streaming", Name: "dropped_total",
	Help: "Streaming events discarded by boundary and sink class (fan-out losses count separately per sink).",
}, []string{"boundary", "sink"})

var StreamingErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "warmor", Subsystem: "streaming", Name: "errors_total",
	Help: "Failed sink operations by sink class and operation; retries can fail without losing an event.",
}, []string{"sink", "operation"})

// EventChannelBackpressure counts platform-to-enforcer event deliveries that
// found the userspace event channel full and had to wait for capacity. The
// Linux delivery path applies backpressure instead of dropping enforcement
// events, so this is the honest saturation signal: it increments when a del-
// ivery blocks, and there is no corresponding "dropped" event to hide. This
// is distinct from StreamingLosses, which tracks events actually discarded by
// the streaming pipeline's own (non-blocking) ingress and sink queues.
var EventChannelBackpressure = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: "warmor", Subsystem: "streaming", Name: "event_channel_backpressure_total",
	Help: "Number of platform event deliveries that blocked because the userspace event channel was full (no event was dropped).",
})

// DuplicateEvents counts tracepoint+LSM observations for one syscall that were
// confidently correlated into a single event. The twin is suppressed so SIEM,
// lineage and policy caches see the operation once; an unpaired observation is
// never counted here (both are delivered in that case).
var DuplicateEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "warmor", Name: "duplicate_events_total",
	Help: "Tracepoint/LSM event pairs merged after kernel-timestamp correlation, by event type.",
}, []string{"event_type"})

// RecordDuplicateEvent counts one confidently correlated tracepoint+LSM pair.
func RecordDuplicateEvent(eventType string) {
	DuplicateEvents.WithLabelValues(eventType).Inc()
}

func RecordStreamingLoss(boundary, sink string, n uint64) {
	StreamingLosses.WithLabelValues(boundary, sink).Add(float64(n))
}
func RecordStreamingError(sink, operation string) {
	StreamingErrors.WithLabelValues(sink, operation).Inc()
}

// RecordEventChannelBackpressure counts one delivery that had to wait because
// the userspace event channel was full. Deliveries with free capacity do not
// call it, so a non-zero value means the consumer is falling behind.
func RecordEventChannelBackpressure() {
	EventChannelBackpressure.Inc()
}

func init() {
	prometheus.MustRegister(StreamingLosses, StreamingErrors, EventChannelBackpressure, DuplicateEvents)
}
