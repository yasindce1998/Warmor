package simulator

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/internal/testutil"
)

func TestEventStoreWriteAndRead(t *testing.T) {
	dir := testutil.PhysicalTempDir(t)
	store, err := NewEventStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	now := time.Now()

	events := []*streaming.SecurityEvent{
		{Timestamp: now.Add(-2 * time.Hour), EventType: "exec", Comm: "nginx", Filename: "/usr/bin/nginx", Decision: "ALLOW"},
		{Timestamp: now.Add(-1 * time.Hour), EventType: "file", Comm: "nginx", Filename: "/etc/nginx.conf", Decision: "ALLOW"},
		{Timestamp: now, EventType: "network", Comm: "curl", RemoteAddr: "10.0.0.1", RemotePort: 443, Protocol: "tcp", Decision: "DENY"},
	}

	for _, e := range events {
		if err := store.Write(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	_ = store.Close()

	read, err := ReadEvents(dir, now.Add(-3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(read) != 3 {
		t.Fatalf("expected 3 events, got %d", len(read))
	}
}

func TestReadEventsSinceFilter(t *testing.T) {
	dir := testutil.PhysicalTempDir(t)
	store, err := NewEventStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	now := time.Now()

	events := []*streaming.SecurityEvent{
		{Timestamp: now.Add(-10 * time.Hour), EventType: "exec", Comm: "old", Decision: "ALLOW"},
		{Timestamp: now.Add(-1 * time.Hour), EventType: "exec", Comm: "recent", Decision: "ALLOW"},
	}

	for _, e := range events {
		_ = store.Write(ctx, e)
	}
	_ = store.Close()

	read, err := ReadEvents(dir, now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(read) != 1 {
		t.Fatalf("expected 1 event, got %d", len(read))
	}
	if read[0].Comm != "recent" {
		t.Errorf("expected comm=recent, got %s", read[0].Comm)
	}
}

func TestReadEventsEmptyDir(t *testing.T) {
	dir := testutil.PhysicalTempDir(t)
	events, err := ReadEvents(dir, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events, got %d", len(events))
	}
}

func TestEventStoreRotation(t *testing.T) {
	dir := testutil.PhysicalTempDir(t)
	store, err := NewEventStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	_ = store.Write(ctx, &streaming.SecurityEvent{
		Timestamp: time.Now(),
		EventType: "exec",
		Comm:      "test",
		Decision:  "ALLOW",
	})
	_ = store.Close()

	files, _ := filepath.Glob(filepath.Join(dir, "events-*.ndjson"))
	if len(files) != 1 {
		t.Fatalf("expected 1 event file, got %d", len(files))
	}
}

func TestSecurityEventToAPIEvent(t *testing.T) {
	cases := []struct {
		eventType string
	}{
		{"exec"},
		{"file"},
		{"network"},
		{"bind"},
	}

	for _, tc := range cases {
		se := &streaming.SecurityEvent{
			EventType:  tc.eventType,
			PID:        123,
			UID:        1000,
			Comm:       "test",
			Filename:   "/bin/test",
			RemoteAddr: "10.0.0.1",
			RemotePort: 80,
			Protocol:   "tcp",
		}
		apiEvent := securityEventToAPIEvent(se)
		if apiEvent.PID != 123 {
			t.Errorf("PID mismatch for %s", tc.eventType)
		}
	}
}

func TestEventStoreNameContainsDir(t *testing.T) {
	dir := testutil.PhysicalTempDir(t)
	store, err := NewEventStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if store.Name() != "event-store:"+dir {
		t.Errorf("unexpected name: %s", store.Name())
	}
}

func TestEventStoreFlush(t *testing.T) {
	dir := testutil.PhysicalTempDir(t)
	store, err := NewEventStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	_ = store.Write(ctx, &streaming.SecurityEvent{
		Timestamp: time.Now(),
		EventType: "exec",
		Comm:      "test",
		Decision:  "ALLOW",
	})

	if err := store.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	files, _ := os.ReadDir(dir)
	if len(files) == 0 {
		t.Fatal("expected event file after flush")
	}
}
