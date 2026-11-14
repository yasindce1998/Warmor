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

func RecordStreamingLoss(boundary, sink string, n uint64) {
	StreamingLosses.WithLabelValues(boundary, sink).Add(float64(n))
}
func RecordStreamingError(sink, operation string) {
	StreamingErrors.WithLabelValues(sink, operation).Inc()
}
func init() { prometheus.MustRegister(StreamingLosses, StreamingErrors) }
