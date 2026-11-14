package streaming

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestRedactedWebhookQueueRetryAndLossAccounting(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		batchSize   int
		wantPIDs    []uint32
		wantDrops   uint64
		writeErrors uint64
		closeError  bool
		losses      map[string]float64
	}{
		{"retry succeeds on close", http.StatusOK, 1, []uint32{1, 1, 2, 3}, 0, 1, false, nil},
		{"attempt and shutdown losses", http.StatusServiceUnavailable, 1, []uint32{1, 1}, 3, 1, true, map[string]float64{"webhook_attempts": 1, "webhook_shutdown": 2}},
		{"permanent rejection", http.StatusBadRequest, 3, []uint32{1, 2, 3}, 3, 1, false, map[string]float64{"webhook_rejected": 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := make(map[string]float64)
			for reason := range tc.losses {
				before[reason] = testutil.ToFloat64(metrics.StreamingLosses.WithLabelValues(reason, "webhook"))
			}
			var mu sync.Mutex
			var posted []SecurityEvent
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if strings.Contains(string(data), "secret-token") || strings.Contains(string(data), `"policy_input":`) {
					t.Error("retry exported sensitive policy_input")
				}
				var events []SecurityEvent
				if err := json.Unmarshal(data, &events); err != nil {
					t.Error(err)
				}
				mu.Lock()
				first := len(posted) == 0
				posted = append(posted, events...)
				mu.Unlock()
				if first && tc.status != http.StatusBadRequest {
					w.WriteHeader(http.StatusServiceUnavailable)
				} else {
					w.WriteHeader(tc.status)
				}
			}))
			defer server.Close()
			webhook := NewWebhookSink(WebhookConfig{URL: server.URL, BatchSize: tc.batchSize, FlushEvery: time.Hour, MaxAttempts: 2})
			full := &mockSink{}
			p := NewPipeline(PipelineConfig{Sinks: []Sink{webhook, full}, BufferSize: 3, SinkBufferSize: 3, FlushInterval: time.Hour})
			t.Cleanup(func() { _ = p.Close() })
			for i := uint32(1); i <= 3; i++ {
				p.Emit(&api.Event{PID: i, Process: &api.ProcessEvent{Filename: "/tool", Args: []string{"tool", "secret-token"}}}, &api.ActionResult{Action: api.ActionDeny, EnforcementAttempted: i != 1, Enforced: i == 3, EnforcementError: "recorded outcome"})
			}
			if err := p.Close(); (err != nil) != tc.closeError {
				t.Fatalf("Close = %v, want error %t", err, tc.closeError)
			}
			stats := p.Stats()
			sink := stats.Sinks[0]
			if stats.EventsDropped != 0 || sink.Queued != 3 || sink.Pending != 0 || sink.QueueDropped != 0 || sink.ShutdownDropped != 0 || sink.WriteErrors != tc.writeErrors || sink.DeliveryDropped != tc.wantDrops || webhook.Dropped() != tc.wantDrops {
				t.Fatalf("redacted webhook loss accounting: %+v", stats)
			}
			for reason, count := range tc.losses {
				if got := testutil.ToFloat64(metrics.StreamingLosses.WithLabelValues(reason, "webhook")) - before[reason]; got != count {
					t.Errorf("%s losses = %v, want %v", reason, got, count)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			var pids []uint32
			for _, event := range posted {
				pids = append(pids, event.PID)
				marked := false
				for _, issue := range event.InputIssues {
					marked = marked || (issue.Field == "policy_input" && issue.State == "redacted")
				}
				if !marked || event.PolicyInput != nil || event.Enforced != (event.PID == 3) || event.EnforcementAttempted != (event.PID != 1) || event.EnforcementError != "recorded outcome" {
					t.Fatalf("redaction/retry changed actual outcome: %+v", event)
				}
			}
			if !reflect.DeepEqual(pids, tc.wantPIDs) {
				t.Fatalf("retry FIFO = %v, want %v", pids, tc.wantPIDs)
			}
			if full.count() != 3 {
				t.Fatal("webhook failure prevented independent delivery")
			}
			for _, event := range full.events {
				if event.PolicyInput == nil || event.PolicyInput.Process.Args[1] != "secret-token" {
					t.Fatal("webhook redaction mutated full input in another worker")
				}
			}
			// Repeated worker/sink shutdown must not count any event twice.
			_ = webhook.CloseContext(context.Background())
			if webhook.Dropped() != tc.wantDrops {
				t.Fatal("repeated close double-counted redacted webhook losses")
			}
		})
	}
}
