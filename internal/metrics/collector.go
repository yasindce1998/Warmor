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

	// AuditSuppressedKernelDeniesTotal counts DENY decisions that were synced
	// to the kernel policy map with the audit flag set. The LSM programs
	// compute blocked = is_enforce_enabled() && !val->audit, so these denies
	// were logged rather than refused by the kernel. This measures the gap
	// between the userspace decision and the kernel's actual behavior; it is
	// distinct from AuditDeniedTotal (the userspace audit downgrade) and never
	// counts a real kernel denial (audit=false).
	AuditSuppressedKernelDeniesTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "warmor_audit_suppressed_kernel_denies_total",
			Help: "Total number of DENY decisions synced to the kernel with the audit flag set, so the kernel logged rather than blocked them.",
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

// RecordAuditSuppressedKernelDeny records a DENY decision synced with the
// audit flag set: the kernel logged it instead of refusing it.
func RecordAuditSuppressedKernelDeny() {
	AuditSuppressedKernelDeniesTotal.Inc()
}

// Bounded kernel policy-map sync failure reasons. This set is deliberately
// closed: it is a Prometheus label, so it must never be derived from raw error
// strings (unbounded cardinality). Add a reason here only when a distinct,
// actionable failure mode needs its own alert.
const (
	SyncReasonMapFull         = "map_full"
	SyncReasonVerifierReject  = "verifier_reject"
	SyncReasonInvalidKey      = "invalid_key"
	SyncReasonGenerationStale = "generation_stale"
	SyncReasonUnknown         = "unknown"
)

// KernelSyncFailuresTotal counts userspace decisions that did not reach the
// kernel policy-map fast path, by reason. A failure is any sync outcome other
// than a successful write: a full/permission-denied map, an unmatchable or
// unsound key, or a decision made by a replaced generation. Each leaves the
// kernel without a fast-path entry even though userspace still enforces it.
var KernelSyncFailuresTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "warmor_kernel_sync_failures_total",
		Help: "Total userspace decisions not synced to the kernel policy map, by reason (map_full, verifier_reject, invalid_key, generation_stale, unknown).",
	},
	[]string{"reason"},
)

// KernelSyncSuccessesTotal is the denominator for the kernel sync failure
// ratio, so dashboards can see coverage degrading rather than just raw errors.
var KernelSyncSuccessesTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "warmor_kernel_sync_successes_total",
		Help: "Total userspace decisions successfully synced to the kernel policy map.",
	},
)

// KernelSyncHealthy is 1 while recent kernel syncs stay below the degraded
// threshold and 0 once they exceed it. It is an observability posture signal
// published next to readiness; it never changes the readiness verdict.
var KernelSyncHealthy = promauto.NewGauge(
	prometheus.GaugeOpts{
		Name: "warmor_kernel_sync_healthy",
		Help: "1 when recent kernel policy-map syncs are healthy, 0 when failures exceed the bounded threshold (observability only; does not gate readiness).",
	},
)

// RecordKernelSyncFailure counts one decision that did not reach the kernel
// policy-map fast path. reason must be one of the bounded SyncReason* values.
func RecordKernelSyncFailure(reason string) {
	KernelSyncFailuresTotal.WithLabelValues(reason).Inc()
}

// RecordKernelSyncSuccess counts one decision successfully synced to kernel.
func RecordKernelSyncSuccess() {
	KernelSyncSuccessesTotal.Inc()
}

// SetKernelSyncHealthy publishes the kernel fast-path posture as a gauge.
func SetKernelSyncHealthy(healthy bool) {
	if healthy {
		KernelSyncHealthy.Set(1)
	} else {
		KernelSyncHealthy.Set(0)
	}
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
