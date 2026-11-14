package streaming

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/yasindce1998/warmor/internal/metrics"
)

func TestWebhookRetryAttemptAndAgeBudgets(t *testing.T) {
	rec := &webhookRecorder{status: http.StatusServiceUnavailable}
	ts := httptest.NewServer(rec.handler(t))
	defer ts.Close()
	s := NewWebhookSink(WebhookConfig{URL: ts.URL, BatchSize: 1, MaxAttempts: 2, FlushEvery: time.Hour})
	if err := s.Write(context.Background(), sampleEvent(1)); err == nil {
		t.Fatal("expected 503")
	}
	if err := s.Flush(context.Background()); err == nil {
		t.Fatal("expected second 503")
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if batches, _ := rec.snapshot(); len(batches) != 2 {
		t.Errorf("POST attempts = %d, want 2", len(batches))
	}
	if s.Dropped() != 1 {
		t.Errorf("attempt drops = %d, want 1", s.Dropped())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = NewWebhookSink(WebhookConfig{URL: ts.URL, BatchSize: 10, MaxAge: time.Second})
	if err := s.Write(context.Background(), sampleEvent(2)); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.queuedAt[0] = time.Now().Add(-time.Hour)
	s.mu.Unlock()
	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("expired event should not POST: %v", err)
	}
	if s.Dropped() != 1 {
		t.Errorf("age drops = %d, want 1", s.Dropped())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWebhookExplicitSmallPendingBoundRespected(t *testing.T) {
	s := NewWebhookSink(WebhookConfig{URL: "http://example.invalid", BatchSize: 10, MaxPending: 2, FlushEvery: time.Hour})
	for i := 1; i <= 5; i++ {
		if err := s.Write(context.Background(), sampleEvent(uint32(i))); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.batch) != 2 || s.batch[0].PID != 4 || s.batch[1].PID != 5 || s.Dropped() != 3 {
		t.Fatalf("explicit MaxPending ignored: pending=%d dropped=%d", len(s.batch), s.Dropped())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = s.CloseContext(ctx)
	if s.Dropped() != 5 {
		t.Fatalf("shutdown did not count remaining bounded backlog: %d", s.Dropped())
	}
}

func TestWebhookConcurrentFlushPreservesRetryOrderingAndBatchLimit(t *testing.T) {
	firstStarted, release := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var batches [][]uint32
	var active, maximum atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); a > old && !maximum.CompareAndSwap(old, a); old = maximum.Load() {
		}
		var events []*SecurityEvent
		if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
			t.Error(err)
		}
		var pids []uint32
		for _, event := range events {
			pids = append(pids, event.PID)
		}
		mu.Lock()
		batches = append(batches, pids)
		n := len(batches)
		mu.Unlock()
		if n == 1 {
			close(firstStarted)
			<-release
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer ts.Close()
	s := NewWebhookSink(WebhookConfig{URL: ts.URL, BatchSize: 2, FlushEvery: time.Hour})
	ctx := context.Background()
	if err := s.Write(ctx, sampleEvent(1)); err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() { firstDone <- s.Write(ctx, sampleEvent(2)) }()
	<-firstStarted
	if err := s.Write(ctx, sampleEvent(3)); err != nil {
		t.Fatal(err)
	}
	secondDone := make(chan error, 1)
	go func() { secondDone <- s.Flush(ctx) }()
	close(release)
	if err := <-firstDone; err == nil {
		t.Fatal("expected transient first failure")
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if maximum.Load() != 1 {
		t.Errorf("concurrent POSTs = %d", maximum.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if want := [][]uint32{{1, 2}, {1, 2}, {3}}; !reflect.DeepEqual(batches, want) {
		t.Fatalf("batches = %v, want %v", batches, want)
	}
}

func TestWebhookCloseIsBoundedCountsPendingAndIsIdempotent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body); <-r.Context().Done() }))
	defer ts.Close()
	s := NewWebhookSink(WebhookConfig{URL: ts.URL, BatchSize: 10, Timeout: 30 * time.Millisecond})
	if err := s.Write(context.Background(), sampleEvent(1)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := s.Close(); err == nil {
		t.Fatal("expected close timeout")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close took %v", elapsed)
	}
	if s.Dropped() != 1 {
		t.Errorf("close drops = %d", s.Dropped())
	}
	if err := s.Close(); err == nil {
		t.Fatal("idempotent Close should preserve error")
	}
	if s.Dropped() != 1 {
		t.Errorf("Close double counted loss: %d", s.Dropped())
	}
	if len(s.batch) != 0 {
		t.Error("Close retained pending events")
	}
}

func TestWebhookConcurrentCloseCancelsActiveRequest(t *testing.T) {
	started := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
	}))
	defer ts.Close()
	s := NewWebhookSink(WebhookConfig{URL: ts.URL, BatchSize: 1, Timeout: time.Hour})
	done := make(chan error, 1)
	go func() { done <- s.Write(context.Background(), sampleEvent(1)) }()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.CloseContext(ctx); err != nil {
		t.Fatalf("close after canceled request: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Error("expected canceled Write")
		}
	case <-ctx.Done():
		t.Fatal("active webhook Write leaked")
	}
	if s.Dropped() != 1 {
		t.Errorf("concurrent close drops = %d", s.Dropped())
	}
}

func TestWebhookConcurrentCloseWaitRespectsCallerContext(t *testing.T) {
	started := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
	}))
	defer ts.Close()
	s := NewWebhookSink(WebhookConfig{URL: ts.URL, BatchSize: 10, Timeout: time.Hour})
	if err := s.Write(context.Background(), sampleEvent(1)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.CloseContext(ctx) }()
	<-started // first caller is in its final POST, not ordinary Write
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if err := s.CloseContext(canceled); err != context.Canceled {
		t.Errorf("concurrent close wait: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("expected interrupted final POST")
		}
	case <-time.After(time.Second):
		t.Fatal("first CloseContext leaked")
	}
	if s.Dropped() != 1 {
		t.Errorf("shutdown drops = %d", s.Dropped())
	}
}

func TestWebhookResponseBodyReadIsBounded(t *testing.T) {
	for _, mode := range []string{"stall", "large"} {
		t.Run(mode, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				if mode == "stall" {
					<-r.Context().Done()
					return
				}
				data := make([]byte, 4096)
				for {
					if _, err := w.Write(data); err != nil {
						return
					}
					w.(http.Flusher).Flush()
				}
			}))
			defer ts.Close()
			s := NewWebhookSink(WebhookConfig{URL: ts.URL, BatchSize: 1, Timeout: 40 * time.Millisecond})
			err := s.Write(context.Background(), sampleEvent(1))
			if mode == "stall" && err == nil {
				t.Fatal("expected response read timeout")
			}
			if mode == "large" && err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_ = s.CloseContext(ctx)
		})
	}
}

func TestStreamingLossMetricsUseBoundedSinkClasses(t *testing.T) {
	before := testutil.ToFloat64(metrics.StreamingLosses.WithLabelValues("webhook_rejected", "webhook"))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadRequest) }))
	defer ts.Close()
	s := NewWebhookSink(WebhookConfig{URL: ts.URL + "/private-token", BatchSize: 1})
	if err := s.Write(context.Background(), sampleEvent(1)); err == nil {
		t.Fatal("expected permanent rejection")
	}
	if got := testutil.ToFloat64(metrics.StreamingLosses.WithLabelValues("webhook_rejected", "webhook")); got != before+1 {
		t.Errorf("rejection metric = %v, want %v", got, before+1)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	p := NewPipeline(PipelineConfig{})
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	before = testutil.ToFloat64(metrics.StreamingLosses.WithLabelValues("ingress_closed", "none"))
	p.Emit(nil, nil)
	if got := testutil.ToFloat64(metrics.StreamingLosses.WithLabelValues("ingress_closed", "none")); got != before+1 {
		t.Errorf("closed ingress metric = %v, want %v", got, before+1)
	}
}
