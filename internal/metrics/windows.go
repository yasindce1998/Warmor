//go:build windows

package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yasindce1998/warmor/pkg/api"
)

var (
	// WindowsBackendHealth is 1 while an event type is actively monitored
	// and 0 once its backend degraded or failed. It is distinct from the
	// liveness /health endpoint: a healthy process can be unmonitored.
	WindowsBackendHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "warmor",
			Subsystem: "windows",
			Name:      "backend_health",
			Help:      "1 if the Windows backend for this event type is monitoring, 0 if degraded or unmonitored.",
		},
		[]string{"event_type"},
	)

	// WindowsBackendTransitions counts backend changes (e.g. ebpf -> none
	// when a kernel reader dies), so an operator can alert on degradation.
	WindowsBackendTransitions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "windows",
			Name:      "backend_transitions_total",
			Help:      "Windows backend changes per event type, labelled by from/to backend.",
		},
		[]string{"event_type", "from", "to"},
	)

	// WindowsUnresolvedProcesses counts events whose producing PID could not
	// be resolved. Such events cannot be matched on comm/path, so policies
	// for them are effectively inert.
	WindowsUnresolvedProcesses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "windows",
			Name:      "unresolved_process_events_total",
			Help:      "Events from a PID whose process identity could not be resolved (policy matching is degraded).",
		},
	)
)

func init() {
	prometheus.MustRegister(
		WindowsBackendHealth,
		WindowsBackendTransitions,
		WindowsUnresolvedProcesses,
	)
}

func eventTypeLabel(t api.EventType) string { return strings.ToLower(t.String()) }

// SetWindowsBackendHealth publishes whether an event type is being monitored.
func SetWindowsBackendHealth(t api.EventType, healthy bool) {
	v := 0.0
	if healthy {
		v = 1
	}
	WindowsBackendHealth.WithLabelValues(eventTypeLabel(t)).Set(v)
}

// RecordWindowsBackendTransition counts a backend change for an event type.
func RecordWindowsBackendTransition(t api.EventType, from, to string) {
	WindowsBackendTransitions.WithLabelValues(eventTypeLabel(t), from, to).Inc()
}

// RecordWindowsUnresolvedProcess counts one event from an unresolved PID.
func RecordWindowsUnresolvedProcess() {
	WindowsUnresolvedProcesses.Inc()
}
