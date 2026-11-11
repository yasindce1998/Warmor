package metrics

import (
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics below are all updated by real code paths; a metric that nothing
// can produce must not be exported (dashboards and alerts would silently
// show nothing). See the Record*/Set* helpers for where each is fed.
var (
	// HookDecisions counts LSM hook outcomes the kernel reports to
	// userspace (internal/platform): action="deny" for a policy_map deny
	// hit (blocked, or logged in audit mode), action="pass" for an event
	// sent up for userspace evaluation (map miss or audit-flagged allow).
	// Map allow hits are decided in the kernel without an event.
	HookDecisions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "lsm",
			Name:      "decisions_total",
			Help:      "LSM hook outcomes reported by the kernel, by hook and action (deny = policy_map deny hit, pass = sent to userspace).",
		},
		[]string{"hook", "action"},
	)

	// PolicyLoads counts policy loads at startup and on reload.
	PolicyLoads = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "policy",
			Name:      "loads_total",
			Help:      "Policy load attempts by policy and status (success, error).",
		},
		[]string{"policy_id", "status"},
	)

	// AgentHeartbeats counts heartbeats sent to the policy server.
	AgentHeartbeats = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "agent",
			Name:      "heartbeats_total",
			Help:      "Heartbeats sent to the policy server, by status (success, error).",
		},
		[]string{"status"},
	)

	// AgentLastHeartbeat is the Unix time of the last successful heartbeat.
	// Only present on agents connected to a policy server.
	AgentLastHeartbeat = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "warmor",
			Subsystem: "agent",
			Name:      "last_heartbeat_timestamp",
			Help:      "Unix time of the last successful heartbeat to the policy server.",
		},
		[]string{"agent_id"},
	)

	// AgentRegistrations counts registration attempts with the policy server.
	AgentRegistrations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "agent",
			Name:      "registrations_total",
			Help:      "Registration attempts with the policy server, by status (success, error).",
		},
		[]string{"status"},
	)

	// WASMExecDuration observes each WASM policy evaluation (cache misses).
	WASMExecDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "warmor",
			Subsystem: "wasm",
			Name:      "exec_duration_seconds",
			Help:      "WASM policy evaluation duration.",
			Buckets:   []float64{.00001, .000025, .00005, .0001, .00025, .0005, .001, .0025, .005, .01, .025, .05, .1},
		},
		[]string{"policy_id"},
	)

	// WASMExecErrors counts failed evaluations (each denied, fail closed).
	WASMExecErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "wasm",
			Name:      "exec_errors_total",
			Help:      "Failed WASM policy evaluations (denied, fail closed), by policy and kind (timeout, error).",
		},
		[]string{"policy_id", "kind"},
	)

	// EventsProcessed counts events handled by the enforcer by event type.
	EventsProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "events",
			Name:      "processed_total",
			Help:      "Events processed by the enforcer, by event type.",
		},
		[]string{"event_type"},
	)

	// EventsDropped counts events a platform monitor discarded because the
	// enforcer's event channel was full (Windows eBPF and ETW consumers;
	// the Linux readers block instead of dropping).
	EventsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "events",
			Name:      "dropped_total",
			Help:      "Events discarded by the platform monitor because the enforcer could not keep up.",
		},
	)

	// MapEntries is the number of entries in a kernel map, refreshed
	// periodically by the enforcer.
	MapEntries = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "warmor",
			Subsystem: "ebpf",
			Name:      "map_entries",
			Help:      "Number of entries in kernel BPF maps.",
		},
		[]string{"map_name"},
	)

	// EBPFLoaderStatus is 1 when the platform's kernel monitor loaded with
	// the requested enforcement, 0 when it runs degraded (kernel LSM
	// enforcement was requested but is not active).
	EBPFLoaderStatus = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "warmor",
			Subsystem: "ebpf",
			Name:      "loader_status",
			Help:      "1 if the kernel monitor loaded with the requested enforcement, 0 if degraded (e.g. LSM enforcement requested but unavailable).",
		},
	)

	// DefaultDeny is 1 when the event type's domain is marked kernel
	// default-deny (a policy-map miss is denied), 0 when misses stay
	// allowed (not requested, or the policy is not a complete allowlist).
	DefaultDeny = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "warmor",
			Subsystem: "kernel",
			Name:      "default_deny_active",
			Help:      "1 if the event type's policy-map misses are denied in-kernel (complete allowlist), 0 if misses stay allowed.",
		},
		[]string{"event_type"},
	)

	// AttackGraph reports the MITRE attack graph built from correlated
	// events (--attack-graph). Updated by the enforcer's metrics loop.
	AttackGraphContainers = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "warmor",
			Subsystem: "attack_graph",
			Name:      "containers",
			Help:      "Containers with correlated attack behavior.",
		},
	)
	AttackGraphTechniques = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "warmor",
			Subsystem: "attack_graph",
			Name:      "techniques",
			Help:      "Distinct MITRE techniques observed across containers.",
		},
	)
	AttackGraphTacticCoverage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "warmor",
			Subsystem: "attack_graph",
			Name:      "tactic_coverage",
			Help:      "Technique nodes observed per MITRE tactic.",
		},
		[]string{"tactic"},
	)
	AttackGraphProgression = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "warmor",
			Subsystem: "attack_graph",
			Name:      "progression",
			Help:      "Deepest kill-chain stage reached by any container (0-6, initial-access to exfiltration).",
		},
	)

	// BlastRadiusReachable is the number of containers reachable from a
	// given cgroup in the container-relationship graph.
	BlastRadiusReachable = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "warmor",
			Subsystem: "blast_radius",
			Name:      "reachable",
			Help:      "Containers reachable from the labeled cgroup in the relationship graph (network/mount edges).",
		},
		[]string{"cgroup"},
	)

	// Fleet drift, computed by the policy server from fingerprints in
	// agent heartbeats. Unlabeled totals on purpose: the per-image (and
	// per-agent) breakdown is agent-influenced data and belongs behind the
	// authenticated admin API (/api/v1/admin/drift), not on a metrics
	// endpoint where it would invite label-cardinality abuse.
	DriftTrackedImages = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "warmor",
			Subsystem: "drift",
			Name:      "tracked_images",
			Help:      "Image groups with live agent fingerprints (fleet drift detection).",
		},
	)
	DriftAnomalies = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "warmor",
			Subsystem: "drift",
			Name:      "anomalies",
			Help:      "Behavioral drift anomalies currently detected across the fleet (z-score outliers and unique patterns).",
		},
	)
)

// Status label values.
const (
	StatusSuccess = "success"
	StatusError   = "error"
)

func status(err error) string {
	if err != nil {
		return StatusError
	}
	return StatusSuccess
}

// LSMEventsDropped counts LSM events the kernel could not queue because the
// ring buffer was full. Each is an operation userspace never evaluated.
var LSMEventsDropped = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "warmor",
		Subsystem: "lsm",
		Name:      "events_dropped_total",
		Help:      "LSM events dropped because the kernel ring buffer was full (operations never evaluated), by hook.",
	},
	[]string{"hook"},
)

// RecordLSMEventsDropped adds n kernel-reported drops for hook.
func RecordLSMEventsDropped(hook string, n uint64) {
	LSMEventsDropped.WithLabelValues(hook).Add(float64(n))
}

// RecordLSMDecision counts one kernel-reported LSM hook outcome.
func RecordLSMDecision(hook, action string) {
	HookDecisions.WithLabelValues(hook, action).Inc()
}

// RecordPolicyLoad counts one policy load attempt.
func RecordPolicyLoad(policyID string, err error) {
	PolicyLoads.WithLabelValues(policyID, status(err)).Inc()
}

// RecordHeartbeat counts one heartbeat and, on success, records its time.
func RecordHeartbeat(agentID string, err error) {
	AgentHeartbeats.WithLabelValues(status(err)).Inc()
	if err == nil {
		AgentLastHeartbeat.WithLabelValues(agentID).SetToCurrentTime()
	}
}

// RecordRegistration counts one registration attempt.
func RecordRegistration(err error) {
	AgentRegistrations.WithLabelValues(status(err)).Inc()
}

// RecordWASMExec records one policy evaluation. timedOut distinguishes
// deadline failures from other errors.
func RecordWASMExec(policyID string, seconds float64, err error, timedOut bool) {
	WASMExecDuration.WithLabelValues(policyID).Observe(seconds)
	if err != nil {
		kind := "error"
		if timedOut {
			kind = "timeout"
		}
		WASMExecErrors.WithLabelValues(policyID, kind).Inc()
	}
}

// RecordEventProcessed counts one event handled by the enforcer.
func RecordEventProcessed(eventType string) {
	EventsProcessed.WithLabelValues(eventType).Inc()
}

// RecordEventDropped counts one event discarded under backpressure.
func RecordEventDropped() {
	EventsDropped.Inc()
}

// SetDefaultDeny reports whether the event type's domain is marked kernel
// default-deny.
func SetDefaultDeny(eventType string, active bool) {
	v := 0.0
	if active {
		v = 1
	}
	DefaultDeny.WithLabelValues(eventType).Set(v)
}

// SetMapEntries sets the entry count of a kernel map.
func SetMapEntries(mapName string, n int) {
	MapEntries.WithLabelValues(mapName).Set(float64(n))
}

// SetEBPFLoaderStatus records whether the kernel monitor is fully loaded.
func SetEBPFLoaderStatus(ok bool) {
	if ok {
		EBPFLoaderStatus.Set(1)
	} else {
		EBPFLoaderStatus.Set(0)
	}
}

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
		PolicyLoads,
		AgentHeartbeats,
		AgentLastHeartbeat,
		AgentRegistrations,
		WASMExecDuration,
		WASMExecErrors,
		EventsProcessed,
		EventsDropped,
		MapEntries,
		EBPFLoaderStatus,
		PolicyMapSyncs,
		LSMEventsDropped,
		DefaultDeny,
		AttackGraphContainers,
		AttackGraphTechniques,
		AttackGraphTacticCoverage,
		AttackGraphProgression,
		BlastRadiusReachable,
		DriftTrackedImages,
		DriftAnomalies,
	)
}

// lastTacticSeries remembers which tactic series were set last, so a
// tactic whose count dropped to zero can be deleted instead of sticking
// at its old value.
var lastTacticSeries = map[string]bool{}

// SetAttackGraph publishes the attack graph summary gauges.
func SetAttackGraph(containers, techniques, progression int, tacticCoverage map[string]int) {
	AttackGraphContainers.Set(float64(containers))
	AttackGraphTechniques.Set(float64(techniques))
	AttackGraphProgression.Set(float64(progression))
	for tactic := range lastTacticSeries {
		if _, ok := tacticCoverage[tactic]; !ok {
			AttackGraphTacticCoverage.DeleteLabelValues(tactic)
			delete(lastTacticSeries, tactic)
		}
	}
	for tactic, n := range tacticCoverage {
		AttackGraphTacticCoverage.WithLabelValues(tactic).Set(float64(n))
		lastTacticSeries[tactic] = true
	}
}

// SetBlastRadius sets the reachable-container count for one cgroup.
func SetBlastRadius(cgroupID uint64, reachable int) {
	BlastRadiusReachable.WithLabelValues(strconv.FormatUint(cgroupID, 10)).Set(float64(reachable))
}

// ResetBlastRadius clears every blast-radius series (e.g. when the graph
// was rebuilt empty).
func ResetBlastRadius() {
	BlastRadiusReachable.Reset()
}

// SetDrift publishes the fleet drift totals (policy server side).
func SetDrift(trackedImages, anomalies int) {
	DriftTrackedImages.Set(float64(trackedImages))
	DriftAnomalies.Set(float64(anomalies))
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
