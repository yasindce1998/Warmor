package streaming

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/yasindce1998/warmor/pkg/api"
)

// Pipeline consumes api.Event + ActionResult pairs, enriches them into
// SecurityEvents, and fans out to all registered sinks.
type Pipeline struct {
	workers  []*sinkWorker
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
	sendMu          sync.RWMutex
	ctx             context.Context
	cancel          context.CancelFunc
	shutdownTimeout time.Duration
	closeErr        error // published by closing doneCh

	stats pipelineCounters
}

type eventPair struct {
	event  *api.Event
	result *api.ActionResult
}

// PipelineStats is a snapshot of streaming metrics (all plain values).
type PipelineStats struct {
	EventsReceived uint64
	// EventsEmitted counts enriched events offered to sink queues, not
	// delivery acknowledgements. EventsDropped covers ingress only.
	EventsEmitted   uint64
	EventsDropped   uint64
	EventsRejected  uint64 // Emit calls after shutdown started
	ShutdownDropped uint64 // subset of EventsDropped discarded on shutdown
	SinkErrors      uint64
	Sinks           []SinkStats // registration order, including duplicate names
}

type pipelineCounters struct {
	eventsReceived  atomic.Uint64
	eventsEmitted   atomic.Uint64
	eventsDropped   atomic.Uint64
	eventsRejected  atomic.Uint64
	shutdownDropped atomic.Uint64
	sinkErrors      atomic.Uint64
}

// Enricher adds context to a SecurityEvent before it's sent to sinks.
type Enricher interface {
	// Enrich must return promptly; it runs serially in ingestion order.
	Enrich(event *SecurityEvent)
}

// PipelineConfig configures the streaming pipeline.
type PipelineConfig struct {
	BufferSize int
	Sinks      []Sink
	Labels     map[string]string
	Enrichers  []Enricher
	// SinkBufferSize is a separate drop-newest FIFO per sink (default 4096).
	SinkBufferSize int
	// WriteTimeout bounds each write or periodic/final flush (default 5s).
	WriteTimeout  time.Duration
	FlushInterval time.Duration // default 5s
	// ShutdownTimeout is one total drain budget shared by every worker
	// (default 5s), not a fresh timeout per queued event or sink.
	ShutdownTimeout time.Duration
}

// NewPipeline creates a streaming pipeline with the given sinks.
func NewPipeline(cfg PipelineConfig) *Pipeline {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 4096
	}
	if cfg.SinkBufferSize <= 0 {
		cfg.SinkBufferSize = 4096
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 5 * time.Second
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 5 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	hostname, _ := os.Hostname()
	p := &Pipeline{
		hostname:  hostname,
		labels:    cfg.Labels,
		enrichers: cfg.Enrichers,
		eventCh:   make(chan eventPair, cfg.BufferSize),
		doneCh:    make(chan struct{}),
		ctx:       ctx, cancel: cancel, shutdownTimeout: cfg.ShutdownTimeout,
	}
	for _, sink := range cfg.Sinks {
		w := newSinkWorker(p, sink, cfg)
		p.workers = append(p.workers, w)
		p.wg.Add(1)
		go w.run()
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
		p.stats.eventsRejected.Add(1)
		recordLoss("ingress_closed", "none", 1)
		return
	}
	p.stats.eventsReceived.Add(1)
	select {
	case p.eventCh <- eventPair{event: event, result: result}:
	default:
		p.stats.eventsDropped.Add(1)
		recordLoss("ingress_full", "none", 1)
	}
}

// Stats returns a snapshot of pipeline metrics.
func (p *Pipeline) Stats() PipelineStats {
	s := PipelineStats{
		EventsReceived:  p.stats.eventsReceived.Load(),
		EventsEmitted:   p.stats.eventsEmitted.Load(),
		EventsDropped:   p.stats.eventsDropped.Load(),
		EventsRejected:  p.stats.eventsRejected.Load(),
		ShutdownDropped: p.stats.shutdownDropped.Load(),
		SinkErrors:      p.stats.sinkErrors.Load(),
	}
	for _, w := range p.workers {
		s.Sinks = append(s.Sinks, w.snapshot())
	}
	return s
}

// Close stops ingress, drains and closes independent workers within one shared
// shutdown budget. Sinks must honor cancellation/close contracts; Go cannot
// safely terminate arbitrary non-cancelable callbacks. Concurrent callers wait
// for the same completed shutdown and receive its error.
func (p *Pipeline) Close() error {
	p.sendMu.Lock()
	if p.closed.Swap(true) {
		p.sendMu.Unlock()
		<-p.doneCh
		return p.closeErr
	}
	close(p.eventCh)
	p.sendMu.Unlock()
	timer := time.AfterFunc(p.shutdownTimeout, p.cancel)
	p.wg.Wait()
	timer.Stop()

	var errs []error
	if p.ctx.Err() != nil {
		errs = append(errs, fmt.Errorf("shutdown budget exhausted: %w", context.DeadlineExceeded))
	}
	for _, w := range p.workers {
		if w.closeErr != nil {
			errs = append(errs, w.closeErr)
		}
	}
	p.cancel()
	p.closeErr = errors.Join(errs...)
	close(p.doneCh)
	return p.closeErr
}

func (p *Pipeline) loop() {
	defer p.wg.Done()
	defer func() {
		for _, w := range p.workers {
			close(w.queue)
		}
	}()
	for pair := range p.eventCh {
		if p.ctx.Err() != nil {
			p.stats.eventsDropped.Add(1)
			p.stats.shutdownDropped.Add(1)
			recordLoss("ingress_shutdown", "none", 1)
			continue
		}
		p.process(pair)
	}
}

func (p *Pipeline) process(pair eventPair) {
	se := p.transform(pair.event, pair.result)

	for _, enricher := range p.enrichers {
		enricher.Enrich(se)
	}

	for _, w := range p.workers {
		w.enqueue(se)
	}
	p.stats.eventsEmitted.Add(1)
}

func (p *Pipeline) transform(event *api.Event, result *api.ActionResult) *SecurityEvent {
	se := FromAPIEvent(event, result)
	se.ID = generateID()
	se.Hostname = p.hostname
	// Each event gets its own copy so enrichers or sinks mutating one
	// event's labels cannot affect other events or the pipeline config.
	se.Labels = maps.Clone(p.labels)
	return se
}

// FromAPIEvent converts an enforcer event and its decision to the streaming
// form (without pipeline-assigned ID, hostname or labels). Detectors that
// run outside the pipeline use it to see events exactly as sinks do.
func FromAPIEvent(event *api.Event, result *api.ActionResult) *SecurityEvent {
	// Own the snapshot, including mutable payloads, before handing it to sinks.
	input := *event
	// Live dispatch ownership is not policy input. Custom sinks receive this
	// snapshot too: never let recording/export retain or complete a generation
	// lease, or signal an internal reader fence. The numeric capture ID remains.
	input.GenerationContext = nil
	input.DispatchBarrier = nil
	if event.Process != nil {
		process := *event.Process
		process.Args = slices.Clone(event.Process.Args)
		input.Process = &process
	}
	if event.File != nil {
		file := *event.File
		input.File = &file
	}
	if event.Network != nil {
		network := *event.Network
		input.Network = &network
	}
	se := &SecurityEvent{
		SchemaVersion: EventSchemaVersion,
		PolicyInput:   &input,
		PPID:          event.PPID,
		Timestamp:     event.Timestamp,
		PID:           event.PID,
		UID:           event.UID,
		GID:           event.GID,
		Comm:          event.Comm,
		CgroupID:      event.CgroupID,
		Filename:      event.Filename,

		ContainerStart: event.ContainerStart,
	}
	if event.Timestamp.IsZero() {
		se.InputIssues = append(se.InputIssues, InputIssue{"timestamp", "unknown"})
	}
	if event.ContainerStart.IsZero() {
		se.InputIssues = append(se.InputIssues, InputIssue{"container_start", "unknown"})
	}
	if event.GetType() == api.EventTypeProcess {
		if event.Process == nil || event.Process.Args == nil {
			se.InputIssues = append(se.InputIssues, InputIssue{"process.args", "unknown"})
		}
		if event.ParentComm == "" {
			se.InputIssues = append(se.InputIssues, InputIssue{"parent_comm", "unknown"})
		}
	}
	// JSON replaces invalid UTF-8 with U+FFFD. Mark loss before serialization.
	values := map[string]string{"comm": event.Comm, "filename": event.Filename, "parent_comm": event.ParentComm, "hook": event.Hook, "mount_source": event.MountSource}
	if event.Process != nil {
		values["process.filename"] = event.Process.Filename
		for _, arg := range event.Process.Args {
			if !utf8.ValidString(arg) {
				se.InputIssues = append(se.InputIssues, InputIssue{"process.args", "unknown"})
				break
			}
		}
	}
	if event.File != nil {
		values["file.path"], values["file.operation"] = event.File.Path, event.File.Operation
	}
	if event.Network != nil {
		values["network.remote_addr"], values["network.local_addr"] = event.Network.RemoteAddr, event.Network.LocalAddr
		values["network.operation"], values["network.protocol"] = event.Network.Operation, event.Network.Protocol
	}
	for field, value := range values {
		if !utf8.ValidString(value) {
			se.InputIssues = append(se.InputIssues, InputIssue{field, "unknown"})
		}
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

	// LSM hooks that Type folds into exec/file/network keep their own name,
	// so consumers (escape detection, SIEM) can tell a mount from an open.
	switch event.Hook {
	case "mount":
		se.EventType = "mount"
		se.MountType = event.Filename
		se.MountSource = event.MountSource
	case "ptrace":
		se.EventType = "ptrace"
		se.PtraceComm = event.Filename
		se.PtraceTargetCgroup = event.TargetCgroupID
	case "bind", "listen", "connect_unix":
		se.EventType = event.Hook
		if event.Hook == "connect_unix" {
			se.Filename = event.Filename
		}
	}
	se.IntegrityViolation = event.IntegrityViolation
	se.KernelEnforced = event.KernelDenied

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
		se.Enforced = result.Enforced
		se.EnforcementAttempted = result.EnforcementAttempted
		se.EnforcementError = result.EnforcementError
		se.LatencyUS = result.Latency.Microseconds()
	}

	return se
}

func generateID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
