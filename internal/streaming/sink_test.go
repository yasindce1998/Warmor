package streaming

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func sampleEvent(pid uint32) *SecurityEvent {
	return &SecurityEvent{
		ID:        "evt",
		Timestamp: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Hostname:  "node-1",
		EventType: "exec",
		PID:       pid,
		Comm:      "bin",
		Decision:  "deny",
	}
}

// --- StdoutSink ---

func TestStdoutSink(t *testing.T) {
	sink := NewStdoutSink()
	if sink.enc == nil {
		t.Fatal("expected encoder to be initialized")
	}
	if sink.Name() != "stdout" {
		t.Errorf("unexpected name: %s", sink.Name())
	}

	// Redirect the encoder to a buffer to keep test output clean.
	var buf bytes.Buffer
	sink.enc = json.NewEncoder(&buf)

	if err := sink.Write(context.Background(), sampleEvent(7)); err != nil {
		t.Fatal(err)
	}
	var got SecurityEvent
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v (%q)", err, buf.String())
	}
	if got.PID != 7 {
		t.Errorf("expected pid=7, got %d", got.PID)
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Errorf("flush: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

// --- FileSink ---

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

func TestFileSinkWriteAndFlush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	sink, err := NewFileSink(path, 0) // default max size
	if err != nil {
		t.Fatal(err)
	}
	if sink.maxBytes != 100*1024*1024 {
		t.Errorf("expected default maxBytes=100MB, got %d", sink.maxBytes)
	}
	if sink.Name() != "file:"+path {
		t.Errorf("unexpected name: %s", sink.Name())
	}

	for i := uint32(1); i <= 3; i++ {
		if err := sink.Write(context.Background(), sampleEvent(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	lines := readLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	for i, line := range lines {
		var ev SecurityEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("line %d invalid JSON: %v", i, err)
		}
		if ev.PID != uint32(i+1) {
			t.Errorf("line %d: expected pid=%d, got %d", i, i+1, ev.PID)
		}
	}

	// Writing to a closed file must fail.
	if err := sink.Write(context.Background(), sampleEvent(9)); err == nil {
		t.Error("expected error writing after close")
	}
}

func TestFileSinkAppendsAndCountsExistingSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	existing := []byte("{\"pre\":\"existing\"}\n")
	if err := os.WriteFile(path, existing, 0644); err != nil {
		t.Fatal(err)
	}

	sink, err := NewFileSink(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if sink.written != int64(len(existing)) {
		t.Errorf("expected written=%d, got %d", len(existing), sink.written)
	}
	if err := sink.Write(context.Background(), sampleEvent(1)); err != nil {
		t.Fatal(err)
	}
	if lines := readLines(t, path); len(lines) != 2 {
		t.Errorf("expected 2 lines after append, got %d", len(lines))
	}
}

func TestFileSinkRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	// Tiny max size: every write after the first triggers rotation.
	sink, err := NewFileSink(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	if err := sink.Write(context.Background(), sampleEvent(1)); err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(context.Background(), sampleEvent(2)); err != nil {
		t.Fatal(err)
	}

	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("expected active file to hold 1 line after rotation, got %d", len(lines))
	}
	var ev SecurityEvent
	_ = json.Unmarshal([]byte(lines[0]), &ev)
	if ev.PID != 2 {
		t.Errorf("expected active file to contain pid=2, got %d", ev.PID)
	}

	matches, _ := filepath.Glob(path + ".*")
	if len(matches) != 1 {
		t.Fatalf("expected 1 rotated file, got %v", matches)
	}
	rotated := readLines(t, matches[0])
	if len(rotated) != 1 {
		t.Fatalf("expected rotated file to hold 1 line, got %d", len(rotated))
	}
}

func TestFileSinkRotationFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "events.jsonl")
	sink, err := NewFileSink(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(context.Background(), sampleEvent(1)); err != nil {
		t.Fatal(err)
	}

	// Remove the directory so re-opening the log during rotation fails.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(context.Background(), sampleEvent(2)); err == nil {
		t.Error("expected rotation error when log directory is gone")
	}
}

func TestFileSinkOpenError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-dir", "events.jsonl")
	if _, err := NewFileSink(path, 0); err == nil {
		t.Fatal("expected error opening file in non-existent directory")
	}
}

// --- WebhookSink ---

type webhookRecorder struct {
	mu      sync.Mutex
	batches [][]*SecurityEvent
	headers []http.Header
	status  int
}

func (r *webhookRecorder) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		var batch []*SecurityEvent
		if err := json.Unmarshal(body, &batch); err != nil {
			t.Errorf("webhook received invalid JSON: %v", err)
		}
		r.mu.Lock()
		r.batches = append(r.batches, batch)
		r.headers = append(r.headers, req.Header.Clone())
		status := r.status
		r.mu.Unlock()
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
	}
}

func (r *webhookRecorder) snapshot() ([][]*SecurityEvent, []http.Header) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]*SecurityEvent(nil), r.batches...), append([]http.Header(nil), r.headers...)
}

func TestWebhookSinkDefaults(t *testing.T) {
	s := NewWebhookSink(WebhookConfig{URL: "http://example.invalid/hook"})
	if s.batchSize != 100 {
		t.Errorf("expected default batchSize=100, got %d", s.batchSize)
	}
	if s.flushEvery != 5*time.Second {
		t.Errorf("expected default flushEvery=5s, got %v", s.flushEvery)
	}
	if s.client.Timeout != 10*time.Second {
		t.Errorf("expected default timeout=10s, got %v", s.client.Timeout)
	}
	if s.Name() != "webhook:http://example.invalid/hook" {
		t.Errorf("unexpected name: %s", s.Name())
	}
	// Empty batch flush must not touch the network.
	if err := s.Flush(context.Background()); err != nil {
		t.Errorf("empty flush: %v", err)
	}
}

func TestWebhookSinkBatchFlush(t *testing.T) {
	rec := &webhookRecorder{}
	ts := httptest.NewServer(rec.handler(t))
	defer ts.Close()

	s := NewWebhookSink(WebhookConfig{
		URL:        ts.URL,
		BatchSize:  3,
		FlushEvery: time.Hour,
		Headers:    map[string]string{"Authorization": "Bearer secret", "X-Source": "warmor"},
	})

	ctx := context.Background()
	for i := uint32(1); i <= 2; i++ {
		if err := s.Write(ctx, sampleEvent(i)); err != nil {
			t.Fatal(err)
		}
	}
	if batches, _ := rec.snapshot(); len(batches) != 0 {
		t.Fatalf("expected no flush before batch is full, got %d", len(batches))
	}

	// Third write fills the batch and triggers a synchronous flush.
	if err := s.Write(ctx, sampleEvent(3)); err != nil {
		t.Fatal(err)
	}
	batches, headers := rec.snapshot()
	if len(batches) != 1 || len(batches[0]) != 3 {
		t.Fatalf("expected 1 batch of 3, got %v", batches)
	}
	if headers[0].Get("Content-Type") != "application/json" {
		t.Errorf("expected JSON content type, got %q", headers[0].Get("Content-Type"))
	}
	if headers[0].Get("Authorization") != "Bearer secret" || headers[0].Get("X-Source") != "warmor" {
		t.Errorf("custom headers not sent: %v", headers[0])
	}

	// Close flushes any remainder.
	if err := s.Write(ctx, sampleEvent(4)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	batches, _ = rec.snapshot()
	if len(batches) != 2 || len(batches[1]) != 1 || batches[1][0].PID != 4 {
		t.Fatalf("expected Close to flush remaining event, got %v", batches)
	}
}

func TestWebhookSinkTimeBasedFlush(t *testing.T) {
	rec := &webhookRecorder{}
	ts := httptest.NewServer(rec.handler(t))
	defer ts.Close()

	s := NewWebhookSink(WebhookConfig{URL: ts.URL, BatchSize: 1000, FlushEvery: time.Nanosecond})
	if err := s.Write(context.Background(), sampleEvent(1)); err != nil {
		t.Fatal(err)
	}
	if batches, _ := rec.snapshot(); len(batches) != 1 {
		t.Fatalf("expected elapsed flush interval to trigger flush, got %d batches", len(batches))
	}
}

func TestWebhookSinkErrorStatus(t *testing.T) {
	rec := &webhookRecorder{status: http.StatusInternalServerError}
	ts := httptest.NewServer(rec.handler(t))
	defer ts.Close()

	s := NewWebhookSink(WebhookConfig{URL: ts.URL, BatchSize: 1})
	err := s.Write(context.Background(), sampleEvent(1))
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected status 500 error, got %v", err)
	}
	// The failed batch is discarded, not retried.
	if err := s.Flush(context.Background()); err != nil {
		t.Errorf("expected empty flush after failed batch, got %v", err)
	}
}

func TestWebhookSinkConnectionError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := ts.URL
	ts.Close() // nothing listening any more

	s := NewWebhookSink(WebhookConfig{URL: url, BatchSize: 1, Timeout: 2 * time.Second})
	err := s.Write(context.Background(), sampleEvent(1))
	if err == nil || !strings.Contains(err.Error(), "webhook post") {
		t.Fatalf("expected webhook post error, got %v", err)
	}
}

func TestWebhookSinkBadURL(t *testing.T) {
	s := NewWebhookSink(WebhookConfig{URL: "http://bad\x7f url", BatchSize: 1})
	if err := s.Write(context.Background(), sampleEvent(1)); err == nil {
		t.Fatal("expected request construction error for invalid URL")
	}
}

func TestWebhookSinkCancelledContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := NewWebhookSink(WebhookConfig{URL: ts.URL, BatchSize: 1})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Write(ctx, sampleEvent(1)); err == nil {
		t.Fatal("expected error with cancelled context")
	}
}
