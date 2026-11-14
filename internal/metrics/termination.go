package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// attempted = succeeded + failed once complete; refused means no termination
// syscall, including unverifiable identity, unsupported pidfds, or exited PIDs.
// Success is an accepted asynchronous request, not evidence of prevention.
var TerminationsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "warmor_process_terminations_total",
		Help: "Process termination requests by outcome (attempted, succeeded, failed, refused); success means accepted termination, not syscall prevention",
	},
	[]string{"outcome"},
)
