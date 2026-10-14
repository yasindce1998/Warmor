package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// EscapeAlertsTotal counts container escape pattern matches.
	EscapeAlertsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "warmor_escape_alerts_total",
			Help: "Container escape pattern matches, by MITRE technique",
		},
		[]string{"technique"},
	)

	// IntegrityViolationsTotal counts execs whose SHA-256 was not allowlisted.
	IntegrityViolationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "warmor_integrity_violations_total",
			Help: "Execs refused (enforce) or reported (audit) by the integrity check",
		},
		[]string{"mode"},
	)
)

// RecordEscapeAlert counts an escape pattern match.
func RecordEscapeAlert(technique string) {
	EscapeAlertsTotal.WithLabelValues(technique).Inc()
}

// RecordIntegrityViolation counts an integrity violation; enforced is true
// when the kernel refused the exec.
func RecordIntegrityViolation(enforced bool) {
	mode := "audit"
	if enforced {
		mode = "enforce"
	}
	IntegrityViolationsTotal.WithLabelValues(mode).Inc()
}
