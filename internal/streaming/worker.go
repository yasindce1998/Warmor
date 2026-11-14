package streaming

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/yasindce1998/warmor/internal/metrics"
)

// SinkStats separates queue admission, Write acceptance, and actual loss.
// Written is not a delivery guarantee: a batching sink can retain an event after
// Write returns. Errors count failed operations, not necessarily lost events.
type SinkStats struct {
	Name                                  string
	Queued, Written                       uint64
	QueueDropped, ShutdownDropped         uint64
	WriteErrors, FlushErrors, CloseErrors uint64
	// DeliveryDropped includes sink-internal losses, or failed Writes for
	// unbuffered/custom sinks that do not expose Dropped().
	DeliveryDropped uint64
	Pending         int
}

type sinkWorker struct {
	p                                              *Pipeline
	sink                                           Sink
	kind                                           string
	queue                                          chan *SecurityEvent
	timeout, flushInterval                         time.Duration
	queued, written, queueDropped, shutdownDropped atomic.Uint64
	writeErrors, flushErrors, closeErrors          atomic.Uint64
	closeErr                                       error // read only after worker joins
}

func newSinkWorker(p *Pipeline, sink Sink, cfg PipelineConfig) *sinkWorker {
	return &sinkWorker{p: p, sink: sink, kind: sinkKind(sink),
		queue:   make(chan *SecurityEvent, cfg.SinkBufferSize),
		timeout: cfg.WriteTimeout, flushInterval: cfg.FlushInterval}
}

func (w *sinkWorker) enqueue(event *SecurityEvent) {
	select {
	case w.queue <- event:
		w.queued.Add(1)
	default:
		w.queueDropped.Add(1)
		recordLoss("sink_queue_full", w.kind, 1)
	}
}

func (w *sinkWorker) snapshot() SinkStats {
	s := SinkStats{Name: w.sink.Name(), Queued: w.queued.Load(), Written: w.written.Load(),
		QueueDropped: w.queueDropped.Load(), ShutdownDropped: w.shutdownDropped.Load(),
		WriteErrors: w.writeErrors.Load(), FlushErrors: w.flushErrors.Load(), CloseErrors: w.closeErrors.Load(),
		Pending: len(w.queue)}
	if d, ok := w.sink.(interface{ Dropped() uint64 }); ok {
		s.DeliveryDropped = d.Dropped()
	} else {
		s.DeliveryDropped = s.WriteErrors
	}
	return s
}

// One worker owns all calls to its sink: surviving events are offered FIFO,
// flushes never overlap writes, and sinks have no cross-sink ordering. No
// per-call goroutines are abandoned on timeouts.
func (w *sinkWorker) run() {
	defer w.p.wg.Done()
	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()
	defer w.finish()
	for {
		select {
		case event, ok := <-w.queue:
			if !ok {
				return
			}
			if w.p.ctx.Err() != nil {
				w.shutdownDropped.Add(1)
				recordLoss("sink_queue_shutdown", w.kind, 1)
				continue
			}
			ctx, cancel := context.WithTimeout(w.p.ctx, w.timeout)
			err := w.sink.Write(ctx, event)
			cancel()
			if err != nil {
				w.writeErrors.Add(1)
				w.p.stats.sinkErrors.Add(1)
				metrics.RecordStreamingError(w.kind, "write")
				if _, buffered := w.sink.(interface{ Dropped() uint64 }); !buffered {
					recordLoss("sink_write", w.kind, 1)
				}
			} else {
				w.written.Add(1)
			}
		case <-ticker.C:
			if w.p.ctx.Err() == nil {
				_ = w.flush()
			}
		}
	}
}

func (w *sinkWorker) flush() error {
	ctx, cancel := context.WithTimeout(w.p.ctx, w.timeout)
	defer cancel()
	err := w.sink.Flush(ctx)
	if err != nil {
		w.flushErrors.Add(1)
		w.p.stats.sinkErrors.Add(1)
		metrics.RecordStreamingError(w.kind, "flush")
	}
	return err
}

func (w *sinkWorker) finish() {
	var flushErr, closeErr error
	if closer, ok := w.sink.(interface{ CloseContext(context.Context) error }); ok {
		// Contextual close includes final flush; webhook retries must not get
		// another Background budget after a failed final flush.
		ctx, cancel := context.WithTimeout(w.p.ctx, w.timeout)
		closeErr = closer.CloseContext(ctx)
		cancel()
	} else {
		flushErr = w.flush()
		closeErr = w.sink.Close()
	}
	if closeErr != nil {
		w.closeErrors.Add(1)
		w.p.stats.sinkErrors.Add(1)
		metrics.RecordStreamingError(w.kind, "close")
	}
	if err := errors.Join(flushErr, closeErr); err != nil {
		w.closeErr = fmt.Errorf("%s: %w", w.sink.Name(), err)
	}
}

func recordLoss(boundary, kind string, n uint64) {
	if n != 0 {
		metrics.RecordStreamingLoss(boundary, kind, n)
	}
}

// Never label metrics with endpoint URLs, paths or arbitrary custom names.
func sinkKind(s Sink) string {
	switch s.(type) {
	case *StdoutSink:
		return "stdout"
	case *FileSink:
		return "file"
	case *WebhookSink:
		return "webhook"
	case *SyslogSink:
		return "syslog"
	case *CEFSink:
		return "cef"
	default:
		return "custom"
	}
}
