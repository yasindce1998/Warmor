package streaming

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"maps"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

// Pipeline consumes api.Event + ActionResult pairs, enriches them into
// SecurityEvents, and fans out to all registered sinks.
type Pipeline struct {
	sinks    []Sink
	hostname string
	labels   map[string]string

	enrichers []Enricher

	eventCh chan eventPair
	doneCh  chan struct{}
	wg      sync.WaitGroup
	closed  atomic.Bool
	// sendMu orders Emit's send against Close's close(eventCh): Emit holds
	// it shared while checking closed and sending, Close holds it
	// exclusively while closing, so a send can never hit a closed channel.
	sendMu sync.RWMutex

	stats pipelineCounters
}

type eventPair struct {
	event  *api.Event
	result *api.ActionResult
}

// PipelineStats is a snapshot of streaming metrics (all plain values).
type PipelineStats struct {
	EventsReceived uint64
	EventsEmitted  uint64
	EventsDropped  uint64
	SinkErrors     uint64
}

type pipelineCounters struct {
	eventsReceived atomic.Uint64
	eventsEmitted  atomic.Uint64
	eventsDropped  atomic.Uint64
	sinkErrors     atomic.Uint64
}

// Enricher adds context to a SecurityEvent before it's sent to sinks.
type Enricher interface {
	Enrich(event *SecurityEvent)
}

// PipelineConfig configures the streaming pipeline.
type PipelineConfig struct {
	BufferSize int
	Sinks      []Sink
	Labels     map[string]string
	Enrichers  []Enricher
}

// NewPipeline creates a streaming pipeline with the given sinks.
func NewPipeline(cfg PipelineConfig) *Pipeline {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 4096
	}
	hostname, _ := os.Hostname()
	p := &Pipeline{
		sinks:     cfg.Sinks,
		hostname:  hostname,
		labels:    cfg.Labels,
		enrichers: cfg.Enrichers,
		eventCh:   make(chan eventPair, cfg.BufferSize),
		doneCh:    make(chan struct{}),
	}
	p.wg.Add(1)
	go p.loop()
	return p
}

// Emit sends an event+decision into the pipeline for async processing.
// Non-blocking; drops the event if the buffer is full.
func (p *Pipeline) Emit(event *api.Event, result *api.ActionResult) {
	p.sendMu.RLock()
	defer p.sendMu.RUnlock()
	if p.closed.Load() {
		return
	}
	p.stats.eventsReceived.Add(1)
	select {
	case p.eventCh <- eventPair{event: event, result: result}:
	default:
		p.stats.eventsDropped.Add(1)
	}
}

// Stats returns a snapshot of pipeline metrics.
func (p *Pipeline) Stats() PipelineStats {
	return PipelineStats{
		EventsReceived: p.stats.eventsReceived.Load(),
		EventsEmitted:  p.stats.eventsEmitted.Load(),
		EventsDropped:  p.stats.eventsDropped.Load(),
		SinkErrors:     p.stats.sinkErrors.Load(),
	}
}

// Close shuts down the pipeline, flushing all sinks.
func (p *Pipeline) Close() error {
	p.sendMu.Lock()
	if p.closed.Swap(true) {
		p.sendMu.Unlock()
		return nil
	}
	close(p.eventCh)
	p.sendMu.Unlock()
	p.wg.Wait()

	var errs []error
	for _, sink := range p.sinks {
		if err := sink.Flush(context.Background()); err != nil {
			errs = append(errs, err)
		}
		if err := sink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	close(p.doneCh)
	if len(errs) > 0 {
		return fmt.Errorf("pipeline close: %v", errs)
	}
	return nil
}

func (p *Pipeline) loop() {
	defer p.wg.Done()

	flushTicker := time.NewTicker(5 * time.Second)
	defer flushTicker.Stop()

	for {
		select {
		case pair, ok := <-p.eventCh:
			if !ok {
				return
			}
			p.process(pair)
		case <-flushTicker.C:
			for _, sink := range p.sinks {
				if err := sink.Flush(context.Background()); err != nil {
					p.stats.sinkErrors.Add(1)
					log.Printf("streaming: flush %s: %v", sink.Name(), err)
				}
			}
		}
	}
}

func (p *Pipeline) process(pair eventPair) {
	se := p.transform(pair.event, pair.result)

	for _, enricher := range p.enrichers {
		enricher.Enrich(se)
	}

	ctx := context.Background()
	for _, sink := range p.sinks {
		if err := sink.Write(ctx, se); err != nil {
			p.stats.sinkErrors.Add(1)
			log.Printf("streaming: write %s: %v", sink.Name(), err)
		}
	}
	p.stats.eventsEmitted.Add(1)
}

func (p *Pipeline) transform(event *api.Event, result *api.ActionResult) *SecurityEvent {
	se := &SecurityEvent{
		ID:        generateID(),
		Timestamp: event.Timestamp,
		Hostname:  p.hostname,
		PID:       event.PID,
		UID:       event.UID,
		GID:       event.GID,
		Comm:      event.Comm,
		CgroupID:  event.CgroupID,
		Filename:  event.Filename,
		// Each event gets its own copy so enrichers or sinks mutating one
		// event's labels cannot affect other events or the pipeline config.
		Labels: maps.Clone(p.labels),
	}

	if se.Timestamp.IsZero() {
		se.Timestamp = time.Now()
	}

	// Event type + specifics
	switch event.GetType() {
	case api.EventTypeProcess:
		se.EventType = "exec"
		if event.Process != nil {
			se.Filename = event.Process.Filename
		}
	case api.EventTypeFile:
		se.EventType = "file"
		if event.File != nil {
			se.Filename = event.File.Path
		}
	case api.EventTypeNetwork:
		se.EventType = "network"
		if event.Network != nil {
			se.RemoteAddr = event.Network.RemoteAddr
			se.RemotePort = event.Network.RemotePort
			se.LocalPort = event.Network.LocalPort
			se.Protocol = event.Network.Protocol
		}
	}

	// Decision
	if result != nil {
		switch result.Action {
		case api.ActionAllow:
			se.Decision = "allow"
		case api.ActionDeny:
			se.Decision = "deny"
		case api.ActionLog:
			se.Decision = "log"
		}
		se.Reason = result.Reason
		se.Cached = result.Cached
		se.AuditOnly = result.Audit
		se.Enforced = result.Action == api.ActionDeny && !result.Audit
		se.LatencyUS = result.Latency.Microseconds()
	}

	return se
}

func generateID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
