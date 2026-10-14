package policyserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/yasindce1998/warmor/internal/metrics"
)

func TestClient_RecordsRegistrationAndHeartbeatMetrics(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
	defer srv.Close()
	c := NewClient(ClientConfig{ServerURL: srv.URL, AgentID: "metrics-agent"})
	ctx := context.Background()

	regOK := testutil.ToFloat64(metrics.AgentRegistrations.WithLabelValues(metrics.StatusSuccess))
	regErr := testutil.ToFloat64(metrics.AgentRegistrations.WithLabelValues(metrics.StatusError))
	hbOK := testutil.ToFloat64(metrics.AgentHeartbeats.WithLabelValues(metrics.StatusSuccess))
	hbErr := testutil.ToFloat64(metrics.AgentHeartbeats.WithLabelValues(metrics.StatusError))

	if err := c.Register(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.SendHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	if ts := testutil.ToFloat64(metrics.AgentLastHeartbeat.WithLabelValues("metrics-agent")); ts < 1e9 {
		t.Errorf("last heartbeat timestamp = %v", ts)
	}
	status = http.StatusInternalServerError
	_ = c.Register(ctx)
	_ = c.SendHeartbeat(ctx)

	for name, d := range map[string]float64{
		"registrations success": testutil.ToFloat64(metrics.AgentRegistrations.WithLabelValues(metrics.StatusSuccess)) - regOK,
		"registrations error":   testutil.ToFloat64(metrics.AgentRegistrations.WithLabelValues(metrics.StatusError)) - regErr,
		"heartbeats success":    testutil.ToFloat64(metrics.AgentHeartbeats.WithLabelValues(metrics.StatusSuccess)) - hbOK,
		"heartbeats error":      testutil.ToFloat64(metrics.AgentHeartbeats.WithLabelValues(metrics.StatusError)) - hbErr,
	} {
		if d != 1 {
			t.Errorf("%s: +%v, want +1", name, d)
		}
	}
}
