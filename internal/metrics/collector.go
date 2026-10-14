package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// EventsTotal counts total events by action
	EventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "warmor_events_total",
			Help: "Total number of events processed",
		},
		[]string{"action"},
	)

	// CacheHitsTotal counts cache hits
	CacheHitsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "warmor_cache_hits_total",
			Help: "Total number of cache hits",
		},
	)

	// CacheMissesTotal counts cache misses
	CacheMissesTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "warmor_cache_misses_total",
			Help: "Total number of cache misses",
		},
	)

	// CacheSize tracks current cache size
	CacheSize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "warmor_cache_size",
			Help: "Current number of entries in cache",
		},
	)

	// EvaluationLatency tracks policy evaluation latency
	EvaluationLatency = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "warmor_evaluation_latency_microseconds",
			Help:    "Policy evaluation latency in microseconds",
			Buckets: []float64{10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000},
		},
	)

	// PolicyInfo provides policy metadata
	PolicyInfo = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "warmor_policy_info",
			Help: "Information about loaded policy",
		},
		[]string{"path", "version"},
	)

	// EventsProcessingErrors counts processing errors
	EventsProcessingErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "warmor_events_processing_errors_total",
			Help: "Total number of event processing errors",
		},
	)

	// AuditDeniedTotal counts deny decisions downgraded to log in audit mode
	AuditDeniedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "warmor_audit_denied_total",
			Help: "Total number of deny decisions downgraded to log (audit mode)",
		},
	)
)

// RecordEvent records an event with its action
func RecordEvent(action string) {
	EventsTotal.WithLabelValues(action).Inc()
}

// RecordCacheHit records a cache hit
func RecordCacheHit() {
	CacheHitsTotal.Inc()
}

// RecordCacheMiss records a cache miss
func RecordCacheMiss() {
	CacheMissesTotal.Inc()
}

// RecordLatency records evaluation latency in microseconds
func RecordLatency(microseconds float64) {
	EvaluationLatency.Observe(microseconds)
}

// UpdateCacheSize updates the cache size gauge
func UpdateCacheSize(size int) {
	CacheSize.Set(float64(size))
}

// SetPolicyInfo sets policy metadata
func SetPolicyInfo(path, version string) {
	PolicyInfo.WithLabelValues(path, version).Set(1)
}

// RecordProcessingError records a processing error
func RecordProcessingError() {
	EventsProcessingErrors.Inc()
}

// RecordAuditDenied records a deny decision downgraded to log in audit mode
func RecordAuditDenied() {
	AuditDeniedTotal.Inc()
}

// Policy signature rejection sources.
const (
	PolicySourceFile   = "file"
	PolicySourceServer = "server"
)

// PolicySignatureFailures counts policies refused because their signature
// was missing or did not verify. source is "file" (startup or reload from
// disk) or "server" (policy server download).
var PolicySignatureFailures = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "warmor_policy_signature_failures_total",
		Help: "Total number of policies rejected because their signature was missing or invalid",
	},
	[]string{"source"},
)

// RecordPolicySignatureFailure records a rejected policy signature.
func RecordPolicySignatureFailure(source string) {
	PolicySignatureFailures.WithLabelValues(source).Inc()
}
