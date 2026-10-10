package streaming

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Sink consumes SecurityEvents. Implementations must be safe for concurrent use.
type Sink interface {
	Write(ctx context.Context, event *SecurityEvent) error
	Flush(ctx context.Context) error
	Close() error
	Name() string
}

// StdoutSink writes newline-delimited JSON to stdout.
type StdoutSink struct {
	enc *json.Encoder
	mu  sync.Mutex
}

func NewStdoutSink() *StdoutSink {
	return &StdoutSink{enc: json.NewEncoder(os.Stdout)}
}

func (s *StdoutSink) Write(_ context.Context, event *SecurityEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(event)
}

func (s *StdoutSink) Flush(_ context.Context) error { return nil }
func (s *StdoutSink) Close() error                  { return nil }
func (s *StdoutSink) Name() string                  { return "stdout" }

// FileSink writes newline-delimited JSON to a file with rotation support.
type FileSink struct {
	path     string
	maxBytes int64
	file     *os.File // nil after a rotation that failed to reopen the log
	enc      *json.Encoder
	written  int64
	mu       sync.Mutex
}

func NewFileSink(path string, maxBytes int64) (*FileSink, error) {
	if maxBytes <= 0 {
		maxBytes = 100 * 1024 * 1024 // 100MB default
	}
	s := &FileSink{path: path, maxBytes: maxBytes}
	if err := s.open(); err != nil {
		return nil, fmt.Errorf("open event log: %w", err)
	}
	return s, nil
}

func (s *FileSink) Write(_ context.Context, event *SecurityEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// A previous rotation could not reopen the log; retry so the sink
	// recovers once the path is usable again instead of failing forever.
	if s.file == nil {
		if err := s.open(); err != nil {
			return err
		}
	}
	if s.written >= s.maxBytes {
		if err := s.rotate(); err != nil {
			return err
		}
	}

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	n, err := s.file.Write(data)
	s.written += int64(n)
	return err
}

func (s *FileSink) rotate() error {
	_ = s.file.Close()
	s.file = nil
	renameErr := os.Rename(s.path, s.rotatedName())
	if err := s.open(); err != nil {
		return fmt.Errorf("reopen event log after rotation: %w", err)
	}
	if renameErr != nil {
		// The full log could not be moved aside; keep appending to it and
		// retry rotation after another maxBytes rather than on every write.
		log.Printf("streaming: rotate %s: %v", s.path, renameErr)
		s.written = 0
	}
	return nil
}

// rotatedName returns a not-yet-existing name for the rotated log. Several
// rotations can happen within the same millisecond, and os.Rename would
// silently overwrite an earlier rotated file, so a sequence suffix is added
// on collision.
func (s *FileSink) rotatedName() string {
	base := fmt.Sprintf("%s.%d", s.path, time.Now().UnixMilli())
	name := base
	for i := 1; ; i++ {
		if _, err := os.Lstat(name); err != nil {
			return name
		}
		name = fmt.Sprintf("%s.%d", base, i)
	}
}

// open (re)opens the active log for appending and resets the size counter
// from the file's current size.
func (s *FileSink) open() error {
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	written := int64(0)
	if info, err := f.Stat(); err == nil {
		written = info.Size()
	}
	s.file = f
	s.enc = json.NewEncoder(f)
	s.written = written
	return nil
}

func (s *FileSink) Flush(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	return s.file.Sync()
}

func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	return s.file.Close()
}

func (s *FileSink) Name() string { return "file:" + s.path }

// WebhookSink POSTs batches of events to an HTTP endpoint. Batches that
// fail with a retryable error are kept and re-sent on the next flush, up to
// maxPending events; beyond that the oldest events are dropped and counted.
type WebhookSink struct {
	url        string
	client     *http.Client
	headers    map[string]string
	batch      []*SecurityEvent
	batchSize  int
	maxPending int
	flushEvery time.Duration
	mu         sync.Mutex
	lastFlush  time.Time
	failing    bool // last flush failed; Write waits for flushEvery before retrying
	dropped    atomic.Uint64
}

type WebhookConfig struct {
	URL        string
	Headers    map[string]string
	BatchSize  int
	FlushEvery time.Duration
	Timeout    time.Duration
	// MaxPending bounds how many events are retained for retry while the
	// endpoint is failing (default 10 * BatchSize).
	MaxPending int
}

func NewWebhookSink(cfg WebhookConfig) *WebhookSink {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = 5 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxPending < cfg.BatchSize {
		cfg.MaxPending = 10 * cfg.BatchSize
	}
	return &WebhookSink{
		url:        cfg.URL,
		client:     &http.Client{Timeout: cfg.Timeout},
		headers:    cfg.Headers,
		batchSize:  cfg.BatchSize,
		maxPending: cfg.MaxPending,
		flushEvery: cfg.FlushEvery,
		lastFlush:  time.Now(),
	}
}

func (s *WebhookSink) Write(ctx context.Context, event *SecurityEvent) error {
	s.mu.Lock()
	s.batch = append(s.batch, event)
	s.trimLocked()
	// While the endpoint is failing, a full batch alone does not trigger a
	// flush, otherwise every Write would re-POST the whole retry backlog.
	shouldFlush := (!s.failing && len(s.batch) >= s.batchSize) || time.Since(s.lastFlush) >= s.flushEvery
	s.mu.Unlock()

	if shouldFlush {
		return s.Flush(ctx)
	}
	return nil
}

func (s *WebhookSink) Flush(ctx context.Context) error {
	s.mu.Lock()
	if len(s.batch) == 0 {
		s.mu.Unlock()
		return nil
	}
	batch := s.batch
	s.batch = nil
	s.lastFlush = time.Now()
	s.mu.Unlock()

	retry, err := s.post(ctx, batch)

	s.mu.Lock()
	s.failing = err != nil
	if err != nil {
		if retry {
			// Put the failed batch back in front of anything written
			// meanwhile so ordering is preserved on the next attempt.
			s.batch = append(batch, s.batch...)
			s.trimLocked()
		} else {
			s.dropped.Add(uint64(len(batch)))
		}
	}
	s.mu.Unlock()
	return err
}

// post sends one batch. retry reports whether a failure is transient
// (transport error, 429, 5xx) and the batch should be kept for another
// attempt; other failures (bad request construction, other 4xx) would fail
// identically again.
func (s *WebhookSink) post(ctx context.Context, batch []*SecurityEvent) (retry bool, err error) {
	payload, err := json.Marshal(batch)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, strings.NewReader(string(payload)))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return true, fmt.Errorf("webhook post: %w", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return retry, fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return false, nil
}

// trimLocked drops the oldest pending events beyond maxPending. s.mu must
// be held.
func (s *WebhookSink) trimLocked() {
	if over := len(s.batch) - s.maxPending; over > 0 {
		s.dropped.Add(uint64(over))
		s.batch = append([]*SecurityEvent(nil), s.batch[over:]...)
	}
}

// Dropped returns how many events were discarded, either because the retry
// backlog exceeded MaxPending or because the endpoint rejected them with a
// non-retryable error.
func (s *WebhookSink) Dropped() uint64 { return s.dropped.Load() }

func (s *WebhookSink) Close() error {
	return s.Flush(context.Background())
}

func (s *WebhookSink) Name() string { return "webhook:" + s.url }
