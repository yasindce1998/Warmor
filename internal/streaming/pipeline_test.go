package streaming

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

type mockSink struct {
	mu     sync.Mutex
	events []*SecurityEvent
}

func (m *mockSink) Write(_ context.Context, event *SecurityEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}
func (m *mockSink) Flush(_ context.Context) error { return nil }
func (m *mockSink) Close() error                  { return nil }
func (m *mockSink) Name() string                  { return "mock" }

func (m *mockSink) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

func TestPipelineEmit(t *testing.T) {
	sink := &mockSink{}
	p := NewPipeline(PipelineConfig{
		Sinks: []Sink{sink},
	})
	defer p.Close()

	ev := &api.Event{
		PID:       1234,
		Comm:      "test-bin",
		Filename:  "/usr/bin/test",
		Timestamp: time.Now(),
		Type:      api.EventTypeProcess,
		Process: &api.ProcessEvent{
			BaseEvent: api.BaseEvent{Type: api.EventTypeProcess, PID: 1234, Comm: "test-bin"},
			Filename:  "/usr/bin/test",
		},
	}
	result := &api.ActionResult{
		Action:  api.ActionDeny,
		Reason:  "blocked by policy",
		Latency: 150 * time.Microsecond,
	}

	p.Emit(ev, result)

	// Wait for async processing
	time.Sleep(50 * time.Millisecond)

	if sink.count() != 1 {
		t.Fatalf("expected 1 event in sink, got %d", sink.count())
	}

	got := sink.events[0]
	if got.EventType != "exec" {
		t.Errorf("expected event_type=exec, got %s", got.EventType)
	}
	if got.Decision != "deny" {
		t.Errorf("expected decision=deny, got %s", got.Decision)
	}
	if got.PID != 1234 {
		t.Errorf("expected pid=1234, got %d", got.PID)
	}
	if got.Filename != "/usr/bin/test" {
		t.Errorf("expected filename=/usr/bin/test, got %s", got.Filename)
	}
	if !got.Enforced {
		t.Error("expected enforced=true for deny without audit")
	}
	if got.LatencyUS != 150 {
		t.Errorf("expected latency_us=150, got %d", got.LatencyUS)
	}

	stats := p.Stats()
	if stats.EventsReceived != 1 {
		t.Errorf("expected EventsReceived=1, got %d", stats.EventsReceived)
	}
	if stats.EventsEmitted != 1 {
		t.Errorf("expected EventsEmitted=1, got %d", stats.EventsEmitted)
	}
}

func TestPipelineDropsWhenFull(t *testing.T) {
	sink := &mockSink{}
	p := NewPipeline(PipelineConfig{
		BufferSize: 1,
		Sinks:      []Sink{sink},
	})
	defer p.Close()

	// Flood the buffer
	for i := 0; i < 100; i++ {
		p.Emit(&api.Event{PID: uint32(i), Comm: "flood"}, &api.ActionResult{Action: api.ActionAllow})
	}

	time.Sleep(100 * time.Millisecond)

	stats := p.Stats()
	if stats.EventsDropped == 0 {
		t.Error("expected some events to be dropped")
	}
	if stats.EventsReceived != 100 {
		t.Errorf("expected EventsReceived=100, got %d", stats.EventsReceived)
	}
}

func TestPipelineNetworkEvent(t *testing.T) {
	sink := &mockSink{}
	p := NewPipeline(PipelineConfig{
		Sinks:  []Sink{sink},
		Labels: map[string]string{"env": "test"},
	})
	defer p.Close()

	ev := &api.Event{
		PID:  5678,
		Comm: "curl",
		Type: api.EventTypeNetwork,
		Network: &api.NetworkEvent{
			BaseEvent:  api.BaseEvent{Type: api.EventTypeNetwork, PID: 5678, Comm: "curl"},
			RemoteAddr: "10.0.0.1",
			RemotePort: 443,
			Protocol:   "tcp",
		},
	}
	p.Emit(ev, &api.ActionResult{Action: api.ActionAllow, Cached: true})

	time.Sleep(50 * time.Millisecond)

	if sink.count() != 1 {
		t.Fatalf("expected 1 event, got %d", sink.count())
	}
	got := sink.events[0]
	if got.EventType != "network" {
		t.Errorf("expected event_type=network, got %s", got.EventType)
	}
	if got.RemoteAddr != "10.0.0.1" {
		t.Errorf("expected remote_addr=10.0.0.1, got %s", got.RemoteAddr)
	}
	if got.Labels["env"] != "test" {
		t.Errorf("expected label env=test, got %v", got.Labels)
	}
}

// blockingSink blocks inside Write until release is closed, signalling
// started once per Write call. Used to exercise backpressure deterministically.
type blockingSink struct {
	mockSink
	started chan struct{}
	release chan struct{}
}

func newBlockingSink() *blockingSink {
	return &blockingSink{started: make(chan struct{}, 16), release: make(chan struct{})}
}

func (b *blockingSink) Write(ctx context.Context, event *SecurityEvent) error {
	b.started <- struct{}{}
	<-b.release
	return b.mockSink.Write(ctx, event)
}

type errSink struct {
	mockSink
	writeErr, flushErr, closeErr error
	flushes, closes              int
}

func (e *errSink) Write(ctx context.Context, ev *SecurityEvent) error {
	_ = e.mockSink.Write(ctx, ev)
	return e.writeErr
}
func (e *errSink) Flush(context.Context) error {
	e.mu.Lock()
	e.flushes++
	e.mu.Unlock()
	return e.flushErr
}
func (e *errSink) Close() error {
	e.mu.Lock()
	e.closes++
	e.mu.Unlock()
	return e.closeErr
}
func (e *errSink) Name() string { return "err" }

type labelEnricher struct{ key, value string }

func (l labelEnricher) Enrich(ev *SecurityEvent) {
	ev.Labels = map[string]string{l.key: l.value}
	ev.PolicyRule = "enriched"
}

func TestPipelineBackpressureDropsDeterministically(t *testing.T) {
	sink := newBlockingSink()
	p := NewPipeline(PipelineConfig{BufferSize: 1, Sinks: []Sink{sink}})

	allow := &api.ActionResult{Action: api.ActionAllow}
	p.Emit(&api.Event{PID: 1}, allow)
	<-sink.started // worker is now blocked inside Write with event 1

	p.Emit(&api.Event{PID: 2}, allow) // fills the 1-slot buffer
	p.Emit(&api.Event{PID: 3}, allow) // buffer full -> dropped
	p.Emit(&api.Event{PID: 4}, allow) // dropped

	stats := p.Stats()
	if stats.EventsReceived != 4 || stats.EventsDropped != 2 {
		t.Fatalf("expected received=4 dropped=2, got %+v", stats)
	}

	close(sink.release)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	stats = p.Stats()
	if stats.EventsEmitted != 2 {
		t.Errorf("expected 2 emitted, got %d", stats.EventsEmitted)
	}
	if sink.count() != 2 {
		t.Fatalf("expected 2 events delivered, got %d", sink.count())
	}
	if sink.events[0].PID != 1 || sink.events[1].PID != 2 {
		t.Errorf("unexpected delivery order: %d, %d", sink.events[0].PID, sink.events[1].PID)
	}
}

func TestPipelineCloseDrainsBuffer(t *testing.T) {
	sink := &mockSink{}
	p := NewPipeline(PipelineConfig{BufferSize: 64, Sinks: []Sink{sink}})
	for i := 0; i < 50; i++ {
		p.Emit(&api.Event{PID: uint32(i)}, &api.ActionResult{Action: api.ActionAllow})
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if sink.count() != 50 {
		t.Fatalf("expected Close to drain all 50 buffered events, got %d", sink.count())
	}
	if s := p.Stats(); s.EventsEmitted != 50 || s.EventsDropped != 0 {
		t.Errorf("unexpected stats: %+v", s)
	}
}

func TestPipelineEmitAfterCloseIgnored(t *testing.T) {
	sink := &mockSink{}
	p := NewPipeline(PipelineConfig{Sinks: []Sink{sink}})
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	// Must not panic (send on closed channel) and must not count.
	p.Emit(&api.Event{PID: 1}, &api.ActionResult{})
	if s := p.Stats(); s.EventsReceived != 0 {
		t.Errorf("expected emit after close to be ignored, got %+v", s)
	}
	// Second close is a no-op.
	if err := p.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}
	select {
	case <-p.doneCh:
	default:
		t.Error("expected doneCh to be closed after Close")
	}
}

func TestPipelineSinkWriteErrors(t *testing.T) {
	bad := &errSink{writeErr: errors.New("boom")}
	good := &mockSink{}
	p := NewPipeline(PipelineConfig{Sinks: []Sink{bad, good}})
	p.Emit(&api.Event{PID: 1}, &api.ActionResult{Action: api.ActionDeny})
	p.Emit(&api.Event{PID: 2}, &api.ActionResult{Action: api.ActionDeny})
	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s := p.Stats()
	if s.SinkErrors != 2 {
		t.Errorf("expected 2 sink errors, got %d", s.SinkErrors)
	}
	if s.EventsEmitted != 2 {
		t.Errorf("expected events still counted as emitted, got %d", s.EventsEmitted)
	}
	// A failing sink must not prevent delivery to other sinks.
	if good.count() != 2 {
		t.Errorf("expected healthy sink to receive 2 events, got %d", good.count())
	}
}

func TestPipelineCloseAggregatesFlushAndCloseErrors(t *testing.T) {
	a := &errSink{flushErr: errors.New("flush-a")}
	b := &errSink{closeErr: errors.New("close-b")}
	p := NewPipeline(PipelineConfig{Sinks: []Sink{a, b}})
	err := p.Close()
	if err == nil {
		t.Fatal("expected aggregated close error")
	}
	for _, want := range []string{"flush-a", "close-b"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected error to mention %q, got %v", want, err)
		}
	}
	// Every sink is flushed and closed even when an earlier one fails.
	if a.flushes != 1 || a.closes != 1 || b.flushes != 1 || b.closes != 1 {
		t.Errorf("expected each sink flushed+closed once: a=%d/%d b=%d/%d",
			a.flushes, a.closes, b.flushes, b.closes)
	}
}

func TestPipelineEnrichers(t *testing.T) {
	sink := &mockSink{}
	p := NewPipeline(PipelineConfig{
		Sinks:     []Sink{sink},
		Enrichers: []Enricher{labelEnricher{"team", "sec"}},
	})
	p.Emit(&api.Event{PID: 1}, &api.ActionResult{Action: api.ActionAllow})
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if sink.count() != 1 {
		t.Fatalf("expected 1 event, got %d", sink.count())
	}
	got := sink.events[0]
	if got.Labels["team"] != "sec" || got.PolicyRule != "enriched" {
		t.Errorf("enricher not applied: %+v", got)
	}
}

func TestPipelineDefaultBufferSize(t *testing.T) {
	p := NewPipeline(PipelineConfig{BufferSize: -5})
	defer p.Close()
	if cap(p.eventCh) != 4096 {
		t.Errorf("expected default buffer 4096, got %d", cap(p.eventCh))
	}
	if host, _ := os.Hostname(); p.hostname != host {
		t.Errorf("expected hostname %q, got %q", host, p.hostname)
	}
}

func TestPipelineTransform(t *testing.T) {
	p := &Pipeline{hostname: "h1", labels: map[string]string{"k": "v"}}
	ts := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		event  *api.Event
		result *api.ActionResult
		check  func(t *testing.T, se *SecurityEvent)
	}{
		{
			name: "file event allow",
			event: &api.Event{
				PID: 10, UID: 1000, GID: 1000, Comm: "cat", CgroupID: 77, Timestamp: ts,
				Type: api.EventTypeFile,
				File: &api.FileEvent{Path: "/etc/passwd", Operation: "open"},
			},
			result: &api.ActionResult{Action: api.ActionAllow, Cached: true, Latency: 2 * time.Millisecond},
			check: func(t *testing.T, se *SecurityEvent) {
				if se.EventType != "file" || se.Filename != "/etc/passwd" {
					t.Errorf("bad file mapping: %+v", se)
				}
				if se.Decision != "allow" || se.Enforced || !se.Cached || se.LatencyUS != 2000 {
					t.Errorf("bad decision mapping: %+v", se)
				}
				if se.UID != 1000 || se.GID != 1000 || se.CgroupID != 77 || se.Hostname != "h1" {
					t.Errorf("bad base fields: %+v", se)
				}
				if !se.Timestamp.Equal(ts) {
					t.Errorf("expected timestamp preserved, got %v", se.Timestamp)
				}
				if se.Labels["k"] != "v" {
					t.Errorf("labels not propagated: %v", se.Labels)
				}
			},
		},
		{
			name:   "file event without payload keeps legacy filename",
			event:  &api.Event{Type: api.EventTypeFile, Filename: "/legacy"},
			result: &api.ActionResult{Action: api.ActionLog},
			check: func(t *testing.T, se *SecurityEvent) {
				if se.EventType != "file" || se.Filename != "/legacy" || se.Decision != "log" {
					t.Errorf("unexpected: %+v", se)
				}
			},
		},
		{
			name:   "audit-mode deny is not enforced",
			event:  &api.Event{Type: api.EventTypeProcess},
			result: &api.ActionResult{Action: api.ActionDeny, Audit: true, Reason: "audit"},
			check: func(t *testing.T, se *SecurityEvent) {
				if se.Decision != "deny" || se.Enforced || !se.AuditOnly || se.Reason != "audit" {
					t.Errorf("unexpected audit mapping: %+v", se)
				}
			},
		},
		{
			name:   "nil result and zero timestamp",
			event:  &api.Event{Comm: "legacy", Filename: "/bin/sh"},
			result: nil,
			check: func(t *testing.T, se *SecurityEvent) {
				if se.EventType != "exec" {
					t.Errorf("expected legacy event to default to exec, got %s", se.EventType)
				}
				if se.Decision != "" || se.Enforced {
					t.Errorf("expected empty decision with nil result: %+v", se)
				}
				if se.Timestamp.IsZero() {
					t.Error("expected zero timestamp to be replaced with now")
				}
			},
		},
		{
			name:   "unknown action leaves decision empty",
			event:  &api.Event{Type: api.EventTypeNetwork},
			result: &api.ActionResult{Action: api.Action(99)},
			check: func(t *testing.T, se *SecurityEvent) {
				if se.EventType != "network" || se.Decision != "" || se.RemoteAddr != "" {
					t.Errorf("unexpected: %+v", se)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			se := p.transform(tc.event, tc.result)
			if len(se.ID) != 16 {
				t.Errorf("expected 16-char hex id, got %q", se.ID)
			}
			tc.check(t, se)
		})
	}
}

func TestGenerateIDUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := generateID()
		if seen[id] {
			t.Fatalf("duplicate id %s", id)
		}
		seen[id] = true
	}
}

// TestPipelineEmitCloseRace stresses Emit racing with Close. Before the
// send was serialised against close(eventCh), this panicked with "send on
// closed channel" (and -race reported the conflicting accesses).
func TestPipelineEmitCloseRace(t *testing.T) {
	for iter := 0; iter < 200; iter++ {
		p := NewPipeline(PipelineConfig{BufferSize: 8, Sinks: []Sink{&mockSink{}}})
		start := make(chan struct{})
		var wg sync.WaitGroup
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for i := 0; i < 50; i++ {
					p.Emit(&api.Event{PID: uint32(i)}, &api.ActionResult{})
				}
			}()
		}
		close(start)
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		s := p.Stats()
		if s.EventsReceived != s.EventsEmitted+s.EventsDropped {
			t.Fatalf("iter %d: received %d != emitted %d + dropped %d",
				iter, s.EventsReceived, s.EventsEmitted, s.EventsDropped)
		}
	}
}

// labelMutatingEnricher writes into the event's existing labels map.
type labelMutatingEnricher struct{}

func (labelMutatingEnricher) Enrich(ev *SecurityEvent) {
	ev.Labels["pid"] = string(rune('0' + ev.PID))
}

func TestPipelineLabelsCopiedPerEvent(t *testing.T) {
	sink := &mockSink{}
	cfgLabels := map[string]string{"env": "test"}
	p := NewPipeline(PipelineConfig{
		Sinks:     []Sink{sink},
		Labels:    cfgLabels,
		Enrichers: []Enricher{labelMutatingEnricher{}},
	})
	p.Emit(&api.Event{PID: 1}, &api.ActionResult{})
	p.Emit(&api.Event{PID: 2}, &api.ActionResult{})
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	if len(sink.events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(sink.events))
	}
	if got := sink.events[0].Labels["pid"]; got != "1" {
		t.Errorf("first event's labels were overwritten by a later event: pid=%q", got)
	}
	if got := sink.events[1].Labels["pid"]; got != "2" {
		t.Errorf("second event pid label = %q, want 2", got)
	}
	if _, ok := cfgLabels["pid"]; ok || len(cfgLabels) != 1 {
		t.Errorf("pipeline config labels were mutated: %v", cfgLabels)
	}
	if sink.events[0].Labels["env"] != "test" {
		t.Errorf("configured labels not propagated: %v", sink.events[0].Labels)
	}
}

func TestPipelineTransformNilLabels(t *testing.T) {
	p := &Pipeline{hostname: "h"}
	if se := p.transform(&api.Event{}, nil); se.Labels != nil {
		t.Errorf("expected nil labels when none configured, got %v", se.Labels)
	}
}
