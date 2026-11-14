package metrics

import (
	"errors"
	"testing"
)

func TestCgroupFailureRetainsLastAcceptedMetrics(t *testing.T) {
	RecordCgroupReconciliation(7, nil)
	last := getGaugeValue(cgroupLastSync)
	if getGaugeValue(cgroupScopeSize) != 7 || last <= 0 {
		t.Fatal("successful scope not published")
	}
	RecordCgroupReconciliation(9999, errors.New("capacity"))
	if getGaugeValue(cgroupScopeSize) != 7 || getGaugeValue(cgroupLastSync) != last {
		t.Fatal("failed scope replaced last successful metrics")
	}
}
