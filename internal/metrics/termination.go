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

// TerminationRefusals breaks down the "refused" outcome by a bounded reason
// category. It is a separate series so the existing outcome semantics of
// warmor_process_terminations_total stay intact. Reason values come from a
// fixed set classified in the enforcer; "unknown" absorbs any unrecognized
// error text so label cardinality cannot grow with error detail.
var TerminationRefusals = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "warmor_process_termination_refusals_total",
		Help: "Safety refusals before any termination syscall, by bounded reason category",
	},
	[]string{"reason"},
)

// TerminationLatency measures wall time from the DENY enforcement decision to
// acceptance of the pidfd SIGKILL (a successful signal). It is deliberately
// not evidence that the target process actually exited: an accepted signal is
// asynchronous and the process may still be winding down.
var TerminationLatency = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Name:    "warmor_process_termination_latency_seconds",
		Help:    "Seconds from DENY decision to pidfd SIGKILL acceptance (successful signals only; not proof of observed exit)",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5},
	},
)
