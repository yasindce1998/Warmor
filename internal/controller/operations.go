package controller

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// operations describes this process's reconcile loop, never node activation.
// It intentionally contains no policy operands, resource names or API errors.
type operations struct {
	mu          sync.RWMutex
	lastSuccess time.Time
	lastOK      bool
	stopped     bool
	successes   uint64
	failures    uint64
	duration    time.Duration
}

func (o *operations) record(now time.Time, duration time.Duration, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.duration = duration
	o.lastOK = err == nil
	if err == nil {
		o.lastSuccess = now
		o.successes++
	} else {
		o.failures++
	}
}

func (o *operations) stop() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.stopped = true
}

// ReadinessCheck reports a recent successful local reconciliation, including
// successful retention of last-known-good sources after invalid desired edits.
// It does not acknowledge loading, evaluation, enforcement or desired generations
// on any node. A stalled API body/compile eventually ages this signal out.
func (c *Controller) ReadinessCheck() error {
	c.operations.mu.RLock()
	defer c.operations.mu.RUnlock()
	if c.operations.stopped || !c.operations.lastOK || c.operations.lastSuccess.IsZero() {
		return fmt.Errorf("controller has no successful current reconciliation")
	}
	maxAge := max(c.opts.ResyncPeriod, 2*time.Minute) + c.opts.CompileTimeout + time.Minute
	if c.now().Sub(c.operations.lastSuccess) > maxAge {
		return fmt.Errorf("controller reconciliation is stale")
	}
	return nil
}

// Handler exposes process liveness, local reconciliation readiness and metrics
// on a separate controller listener. The daemon metrics Service must not select
// this port. A private registry avoids sharing daemon or other controller state.
func (c *Controller) Handler() http.Handler {
	registry := prometheus.NewRegistry()
	registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "warmor_controller_ready", Help: "Recent successful local reconciliation; not node application.",
	}, func() float64 {
		if c.ReadinessCheck() == nil {
			return 1
		}
		return 0
	}))
	for _, result := range []string{"success", "error"} {
		registry.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "warmor_controller_reconciliations_total", Help: "Completed local reconciliations by result.",
			ConstLabels: prometheus.Labels{"result": result},
		}, func() float64 {
			c.operations.mu.RLock()
			defer c.operations.mu.RUnlock()
			if result == "success" {
				return float64(c.operations.successes)
			}
			return float64(c.operations.failures)
		}))
	}
	registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "warmor_controller_last_success_timestamp_seconds", Help: "Last successful local reconciliation, or zero before success.",
	}, func() float64 {
		c.operations.mu.RLock()
		defer c.operations.mu.RUnlock()
		if c.operations.lastSuccess.IsZero() {
			return 0
		}
		return float64(c.operations.lastSuccess.Unix())
	}))
	registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "warmor_controller_last_reconcile_duration_seconds", Help: "Duration of the last completed local reconciliation.",
	}, func() float64 {
		c.operations.mu.RLock()
		defer c.operations.mu.RUnlock()
		return c.operations.duration.Seconds()
	}))
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK\n"))
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		if err := c.ReadinessCheck(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("RECONCILED (not node application)\n"))
	})
	return mux
}
