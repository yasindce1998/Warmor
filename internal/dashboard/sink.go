package dashboard

import (
	"context"

	"github.com/yasindce1998/warmor/internal/streaming"
)

// Sink adapts the dashboard handler to the streaming pipeline: every
// evaluated event is published to the SSE clients and the ring buffer.
type Sink struct {
	handler *Handler
}

// NewSink wraps h so pipeline events feed the dashboard.
func NewSink(h *Handler) *Sink {
	return &Sink{handler: h}
}

func (s *Sink) Write(_ context.Context, event *streaming.SecurityEvent) error {
	if event == nil {
		return nil
	}
	action := event.Decision
	if action == "" {
		action = "allow"
	}
	s.handler.Publish(Event{
		Time:   event.Timestamp,
		PID:    event.PID,
		Comm:   event.Comm,
		Action: action,
		Reason: event.Reason,
	})
	return nil
}

func (s *Sink) Flush(_ context.Context) error { return nil }

func (s *Sink) Close() error { return nil }

func (s *Sink) Name() string { return "dashboard" }
