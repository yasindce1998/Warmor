package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
)

func TestSink_PublishesToHandler(t *testing.T) {
	h := New(10)
	sink := NewSink(h)

	ts := time.Unix(1_700_000_000, 0)
	err := sink.Write(context.Background(), &streaming.SecurityEvent{
		Timestamp: ts,
		PID:       42,
		Comm:      "bash",
		Decision:  "deny",
		Reason:    "root shell",
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	hist := h.History()
	if len(hist) != 1 {
		t.Fatalf("history length = %d, want 1", len(hist))
	}
	got := hist[0]
	if got.Time != ts || got.PID != 42 || got.Comm != "bash" ||
		got.Action != "deny" || got.Reason != "root shell" {
		t.Errorf("event = %+v, want the written event", got)
	}
}

func TestSink_EmptyDecisionDefaultsToAllow(t *testing.T) {
	h := New(10)
	sink := NewSink(h)

	if err := sink.Write(context.Background(), &streaming.SecurityEvent{PID: 1}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := h.History()[0].Action; got != "allow" {
		t.Errorf("action = %q, want allow", got)
	}
}

func TestSink_NilEventIsNoOp(t *testing.T) {
	h := New(10)
	sink := NewSink(h)

	if err := sink.Write(context.Background(), nil); err != nil {
		t.Fatalf("Write(nil): %v", err)
	}
	if len(h.History()) != 0 {
		t.Errorf("history length = %d, want 0", len(h.History()))
	}
}
