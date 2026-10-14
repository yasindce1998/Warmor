package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	HookDecisions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "lsm",
			Name:      "decisions_total",
			Help:      "Total LSM hook decisions by hook type and action.",
		},
		[]string{"hook", "action"},
	)

	HookLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "warmor",
			Subsystem: "lsm",
			Name:      "decision_duration_seconds",
			Help:      "Time taken for LSM hook decision in seconds.",
			Buckets:   []float64{.000001, .000005, .00001, .00005, .0001, .0005, .001, .005, .01},
		},
		[]string{"hook"},
	)

	PolicyLoads = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "policy",
			Name:      "loads_total",
			Help:      "Policy load attempts by status.",
		},
		[]string{"policy_id", "status"},
	)

	PolicyVersion = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "warmor",
			Subsystem: "policy",
			Name:      "version",
			Help:      "Currently active policy version.",
		},
		[]string{"policy_id"},
	)

	AgentHeartbeats = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "agent",
			Name:      "heartbeats_total",
			Help:      "Total heartbeats sent to policy server.",
		},
	)

	AgentRegistrations = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "agent",
			Name:      "registrations_total",
			Help:      "Total registration attempts.",
		},
	)

	WASMExecDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "warmor",
			Subsystem: "wasm",
			Name:      "exec_duration_seconds",
			Help:      "WASM policy execution duration.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"policy_id"},
	)

	WASMExecErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "wasm",
			Name:      "exec_errors_total",
			Help:      "WASM execution errors.",
		},
		[]string{"policy_id"},
	)

	EventsProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "events",
			Name:      "processed_total",
			Help:      "Events processed from ring buffer by type.",
		},
		[]string{"event_type"},
	)

	EventsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "events",
			Name:      "dropped_total",
			Help:      "Events dropped due to processing backpressure.",
		},
	)

	MapEntries = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "warmor",
			Subsystem: "ebpf",
			Name:      "map_entries",
			Help:      "Number of entries in BPF maps.",
		},
		[]string{"map_name"},
	)
)

// Outcomes of syncing a userspace decision into the kernel policy map.
const (
	SyncSynced = "synced"
	// SyncFailed: the map write failed (e.g. map full, EPERM).
	SyncFailed = "failed"
	// SyncSkippedUnmatchable: the kernel programs cannot match the decision
	// exactly (ErrNotKernelMatchable), so it stays in userspace by design.
	SyncSkippedUnmatchable = "skipped_unmatchable"
	// SyncSkippedUnsound: the decision depends on fields outside the kernel
	// key (or the policy declared nothing), so syncing it would apply it to
	// other events.
	SyncSkippedUnsound = "skipped_unsound"
	// SyncSkippedStale: the deciding policy was replaced by a reload.
	SyncSkippedStale = "skipped_stale"
)

// PolicyMapSyncs counts kernel policy map sync attempts by outcome.
var PolicyMapSyncs = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "warmor",
		Subsystem: "policy_map",
		Name:      "syncs_total",
		Help:      "Userspace decisions synced to the kernel policy map, by result (synced, failed, skipped_unmatchable, skipped_unsound, skipped_stale).",
	},
	[]string{"result"},
)

// RecordPolicyMapSync counts one kernel policy map sync outcome.
func RecordPolicyMapSync(result string) {
	PolicyMapSyncs.WithLabelValues(result).Inc()
}

func init() {
	prometheus.MustRegister(
		HookDecisions,
		HookLatency,
		PolicyLoads,
		PolicyVersion,
		AgentHeartbeats,
		AgentRegistrations,
		WASMExecDuration,
		WASMExecErrors,
		EventsProcessed,
		EventsDropped,
		MapEntries,
		PolicyMapSyncs,
	)
}

func Handler() http.Handler {
	return promhttp.Handler()
}

func ListenAndServe(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return http.ListenAndServe(addr, mux)
}
