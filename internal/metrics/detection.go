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
)

// RecordEscapeAlert counts an escape pattern match.
func RecordEscapeAlert(technique string) {
	EscapeAlertsTotal.WithLabelValues(technique).Inc()
}
