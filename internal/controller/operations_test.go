package controller

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestControllerProbesReportLocalReconciliationNotApplication(t *testing.T) {
	_, restore := stubCompile(t)
	defer restore()
	api := newFakeAPI()
	cr := testCR("alpha", nil)
	api.addCR(cr)
	ctl := newTestController(t, api, Options{ResyncPeriod: time.Minute})
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	ctl.now = func() time.Time { return now }
	handler := ctl.Handler()
	check := func(path string, want int, contains string) {
		t.Helper()
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != want || !strings.Contains(recorder.Body.String(), contains) {
			t.Fatalf("%s = %d %s, want %d containing %q", path, recorder.Code, recorder.Body, want, contains)
		}
	}
	check("/health", http.StatusOK, "OK")
	check("/ready", http.StatusServiceUnavailable, "no successful")
	check("/metrics", http.StatusOK, "warmor_controller_last_success_timestamp_seconds 0")
	reconcile(t, ctl)
	check("/ready", http.StatusOK, "not node application")
	check("/metrics", http.StatusOK, `warmor_controller_reconciliations_total{result="success"} 1`)
	requireCondition(t, cr.Status, "Applied", "Unknown", "NoNodeAcknowledgements")
	requireCondition(t, cr.Status, "Ready", "False", "AwaitingNodeAcknowledgement")
	// Successful LKG reconciliation is operationally ready even when the
	// desired edit is invalid; CR readiness continues to describe that edit.
	cr.Metadata.Generation++
	cr.Spec.Rules[0].Event = "invalid"
	reconcile(t, ctl)
	check("/ready", http.StatusOK, "not node application")
	requireCondition(t, cr.Status, "Published", "True", "LastKnownGoodPublished")
	cr.Spec.Rules[0].Event = "process"
	cr.Spec.DefaultAction = "deny"
	api.configMapWriteError = http.StatusForbidden
	if _, err := ctl.Reconcile(context.Background()); err == nil {
		t.Fatal("expected publication failure")
	}
	check("/health", http.StatusOK, "OK")
	check("/ready", http.StatusServiceUnavailable, "no successful")
	check("/metrics", http.StatusOK, `warmor_controller_reconciliations_total{result="error"} 1`)
	api.configMapWriteError = 0
	reconcile(t, ctl)
	check("/ready", http.StatusOK, "RECONCILED")
	now = now.Add(6 * time.Minute)
	check("/ready", http.StatusServiceUnavailable, "stale")
	check("/health", http.StatusOK, "OK")
	check("/metrics", http.StatusOK, "warmor_controller_ready 0")
	reconcile(t, ctl)
	ctl.operations.stop()
	check("/ready", http.StatusServiceUnavailable, "no successful")
}

func TestControllerOperationsConcurrentMetricsAndUpdates(t *testing.T) {
	ctl := New(nil, Options{})
	handler := ctl.Handler()
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 50 {
				ctl.operations.record(time.Now(), time.Millisecond, nil)
				ctl.operations.record(time.Now(), time.Millisecond, errors.New("private policy operand"))
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
				body := recorder.Body.String()
				if strings.Contains(body, "private policy operand") || strings.Contains(body, "nodes_applied") {
					t.Error("metrics leaked source details or invented node application")
				}
				_ = ctl.ReadinessCheck()
			}
		})
	}
	wg.Wait()
}
