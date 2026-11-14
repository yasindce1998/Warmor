package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"time"
)

var (
	cgroupReconciliations = promauto.NewCounterVec(prometheus.CounterOpts{Name: "warmor_cgroup_reconciliations_total", Help: "Exact cgroup scope reconciliations by bounded result (success or error)."}, []string{"result"})
	cgroupScopeSize       = promauto.NewGauge(prometheus.GaugeOpts{Name: "warmor_cgroup_scope_ids", Help: "Exact IDs in the last successfully accepted userspace scope (capacity 1023)."})
	cgroupLastSync        = promauto.NewGauge(prometheus.GaugeOpts{Name: "warmor_cgroup_last_success_timestamp_seconds", Help: "Unix time of last successful exact cgroup scope reconciliation."})
)

// RecordCgroupReconciliation never labels by path, ID or error text.
func RecordCgroupReconciliation(size int, err error) {
	if err != nil {
		cgroupReconciliations.WithLabelValues("error").Inc()
		return
	}
	cgroupReconciliations.WithLabelValues("success").Inc()
	cgroupScopeSize.Set(float64(size))
	cgroupLastSync.Set(float64(time.Now().Unix()))
}
