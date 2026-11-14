package streaming

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

type blockingEnricher struct{ started, release chan struct{} }

func (e *blockingEnricher) Enrich(*SecurityEvent) { e.started <- struct{}{}; <-e.release }

func waitFor(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for condition")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPipelineIndependentBoundedSinkQueues(t *testing.T) {
	slow, good := newBlockingSink(), &mockSink{}
	p := NewPipeline(PipelineConfig{Sinks: []Sink{slow, good}, BufferSize: 16, SinkBufferSize: 1, WriteTimeout: time.Second})
	p.Emit(&api.Event{PID: 1}, nil)
	<-slow.started
	waitFor(t, func() bool { return good.count() == 1 })
	// The stalled sink can retain only event 2; it drops newest 3..6.
	for i := 2; i <= 6; i++ {
		p.Emit(&api.Event{PID: uint32(i)}, nil)
		waitFor(t, func() bool { return good.count() == i })
	}
	s := p.Stats()
	if s.EventsEmitted != 6 || s.EventsDropped != 0 || s.Sinks[0].QueueDropped != 4 {
		t.Fatalf("unexpected stalled stats: %+v", s)
	}
	close(slow.release)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if slow.count() != 2 || slow.events[0].PID != 1 || slow.events[1].PID != 2 {
		t.Fatalf("slow sink surviving FIFO = %+v", slow.events)
	}
	for i, ev := range good.events {
		if ev.PID != uint32(i+1) {
			t.Fatalf("healthy sink reordered events: %+v", good.events)
		}
	}
}

func TestPipelineSharedShutdownBudgetAndConcurrentClose(t *testing.T) {
	sinks := make([]Sink, 4)
	for i := range sinks {
		sinks[i] = newBlockingSink()
	}
	p := NewPipeline(PipelineConfig{Sinks: sinks, SinkBufferSize: 8, WriteTimeout: time.Hour, ShutdownTimeout: 40 * time.Millisecond})
	p.Emit(&api.Event{PID: 1}, nil)
	for _, s := range sinks {
		<-s.(*blockingSink).started
	}
	for i := 2; i <= 6; i++ {
		p.Emit(&api.Event{PID: uint32(i)}, nil)
	}
	waitFor(t, func() bool { return p.Stats().EventsEmitted == 6 })
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.Close(); !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("close: %v", err)
			}
		}()
	}
	wg.Wait()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("shutdown took %v", elapsed)
	}
	for _, s := range p.Stats().Sinks {
		if s.ShutdownDropped != 5 || s.DeliveryDropped != 1 || s.Pending != 0 {
			t.Errorf("shutdown accounting: %+v", s)
		}
	}
	// Close joins every worker. These sinks are never released, so completion
	// also catches workers abandoned in unbounded calls on shutdown.
	select {
	case <-p.doneCh:
	default:
		t.Fatal("workers not joined")
	}
}

type flushBlockingSink struct {
	mockSink
	started chan struct{}
	active  atomic.Int64
}

func (s *flushBlockingSink) Flush(ctx context.Context) error {
	s.active.Add(1)
	defer s.active.Add(-1)
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestPipelinePeriodicFlushIsolationAndCancellation(t *testing.T) {
	slow, good := &flushBlockingSink{started: make(chan struct{}, 1)}, &mockSink{}
	p := NewPipeline(PipelineConfig{Sinks: []Sink{slow, good}, FlushInterval: 5 * time.Millisecond, WriteTimeout: time.Hour, ShutdownTimeout: 30 * time.Millisecond})
	<-slow.started
	p.Emit(&api.Event{PID: 1}, nil)
	waitFor(t, func() bool { return good.count() == 1 })
	if err := p.Close(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close: %v", err)
	}
	if slow.active.Load() != 0 {
		t.Fatal("flush survived shutdown")
	}
}

func TestSyslogWriteDeadlineCancellationAndClose(t *testing.T) {
	for _, mode := range []string{"timeout", "cancel", "close"} {
		t.Run(mode, func(t *testing.T) {
			writer, reader := net.Pipe() // reader deliberately never reads
			defer reader.Close()
			s := &SyslogSink{conn: writer, timeout: 50 * time.Millisecond}
			defer s.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- s.Write(ctx, sampleEvent(1)) }()
			if mode == "cancel" {
				cancel()
			}
			if mode == "close" {
				_ = s.Close()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("expected interrupted write")
				}
			case <-time.After(time.Second):
				t.Fatal("blocked syslog write leaked")
			}
			if s.Dropped() != 1 {
				t.Errorf("drops = %d", s.Dropped())
			}
		})
	}
}

func TestPipelineStalledSyslogDoesNotBlockHealthySinkOrShutdown(t *testing.T) {
	writer, reader := net.Pipe()
	defer reader.Close()
	syslog := &SyslogSink{conn: writer, timeout: time.Hour}
	good := &mockSink{}
	p := NewPipeline(PipelineConfig{Sinks: []Sink{syslog, good}, WriteTimeout: time.Hour, ShutdownTimeout: 40 * time.Millisecond})
	p.Emit(&api.Event{PID: 1}, nil)
	waitFor(t, func() bool { return good.count() == 1 })
	if err := p.Close(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close: %v", err)
	}
	if syslog.Dropped() != 1 {
		t.Errorf("syslog drops = %d", syslog.Dropped())
	}
}

func TestPipelineStalledWebhookIsolatedAndShutdownLossCounted(t *testing.T) {
	started, ended := make(chan struct{}), make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
		close(ended)
	}))
	defer ts.Close()
	webhook := NewWebhookSink(WebhookConfig{URL: ts.URL, BatchSize: 1, Timeout: time.Hour})
	good := &mockSink{}
	p := NewPipeline(PipelineConfig{Sinks: []Sink{webhook, good}, WriteTimeout: time.Hour, ShutdownTimeout: 40 * time.Millisecond})
	p.Emit(&api.Event{PID: 1}, nil)
	<-started
	for i := 2; i <= 5; i++ {
		p.Emit(&api.Event{PID: uint32(i)}, nil)
	}
	waitFor(t, func() bool { return good.count() == 5 })
	if err := p.Close(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("HTTP request survived Close")
	}
	s := p.Stats().Sinks[0]
	if s.ShutdownDropped != 4 || s.DeliveryDropped != 1 || webhook.Dropped() != 1 {
		t.Fatalf("webhook shutdown loss: %+v", s)
	}
	if err := webhook.Write(context.Background(), sampleEvent(6)); err == nil {
		t.Error("write after close succeeded")
	}
}
