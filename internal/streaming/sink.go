package streaming

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yasindce1998/warmor/internal/privatefile"
)

// Sink consumes SecurityEvents. Implementations must be safe for concurrent use,
// treat events as immutable, honor Write/Flush cancellation and return promptly
// from Close. A non-cancelable writer (including a CEF callback) can still block
// its own worker/shutdown; Go cannot safely terminate arbitrary callbacks.
type Sink interface {
	Write(ctx context.Context, event *SecurityEvent) error
	Flush(ctx context.Context) error
	Close() error
	Name() string
}

// StdoutSink writes newline-delimited JSON to stdout.
type StdoutSink struct {
	// IncludePolicyInput explicitly opts in to exporting sensitive argv/context.
	// Configure before the first Write; default exports only the SIEM summary.
	IncludePolicyInput bool
	enc                *json.Encoder
	mu                 sync.Mutex
}

func NewStdoutSink() *StdoutSink {
	return &StdoutSink{enc: json.NewEncoder(os.Stdout)}
}

func (s *StdoutSink) Write(_ context.Context, event *SecurityEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.IncludePolicyInput {
		event = event.SummaryForExport()
	}
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
	// Old versions created archives as 0644 too. Tighten recognized recording
	// archives on startup; do not follow links or chmod unrelated sibling files.
	archives, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		_ = s.file.Close()
		return nil, err
	}
	for _, entry := range archives {
		name := entry.Name()
		prefix := filepath.Base(path) + "."
		if runtime.GOOS == "windows" {
			// Discovery must not skip legacy archives merely because the
			// configured active name differs in case from the directory entry.
			// Normalize only for matching; checked opens use the actual name.
			name, prefix = strings.ToUpper(name), strings.ToUpper(prefix)
		}
		if !strings.HasPrefix(name, prefix) || !recordingArchiveSuffix(strings.TrimPrefix(name, prefix)) {
			continue
		}
		archive := filepath.Join(filepath.Dir(path), entry.Name())
		f, err := privatefile.OpenAppend(archive, false, false)
		if err != nil {
			_ = s.file.Close()
			return nil, fmt.Errorf("secure existing event archive: %w", err)
		}
		if err := f.Close(); err != nil {
			_ = s.file.Close()
			return nil, err
		}
	}
	return s, nil
}

func recordingArchiveSuffix(suffix string) bool {
	parts := strings.Split(suffix, ".")
	if len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		if _, err := strconv.ParseUint(part, 10, 64); err != nil {
			return false
		}
	}
	return true
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
	renameErr := privatefile.Rotate(s.path, s.rotatedName(), s.file)
	_ = s.file.Close()
	s.file = nil
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
	f, err := privatefile.OpenAppend(s.path, false, false)
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

// WebhookSink POSTs FIFO batches with at most one request in flight. Transient
// failures retain the head batch subject to count, age and attempt budgets.
// Delivery is best effort, with possible duplicates after ambiguous transport
// errors; it is not durable or exactly-once delivery.
type WebhookSink struct {
	includePolicyInput bool
	url                string
	client             *http.Client
	headers            map[string]string
	batch              []*SecurityEvent
	attempts           []int
	queuedAt           []time.Time
	batchSize          int
	maxPending         int
	flushEvery         time.Duration
	mu                 sync.Mutex
	lastFlush          time.Time
	failing            bool // last flush failed; Write waits for flushEvery before retrying
	dropped            atomic.Uint64
	maxAttempts        int
	maxAge             time.Duration
	flushGate          chan struct{}
	lifetime           context.Context
	cancel             context.CancelFunc
	closed             bool
	closeDone          chan struct{}
	closeErr           error // published by closeDone
}

type WebhookConfig struct {
	// IncludePolicyInput opts in to sending sensitive evaluator inputs (argv).
	IncludePolicyInput bool
	URL                string
	Headers            map[string]string
	BatchSize          int
	FlushEvery         time.Duration
	Timeout            time.Duration
	// MaxPending bounds how many events are retained for retry while the
	// endpoint is failing (default 10 * BatchSize), plus at most BatchSize
	// detached events in an in-flight request.
	MaxPending int
	// MaxAttempts includes the first POST (default 3); MaxAge bounds retained
	// retry age (default 5m). Expiry is checked on Write, Flush and Close.
	MaxAttempts int
	MaxAge      time.Duration
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
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = 10 * cfg.BatchSize
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 5 * time.Minute
	}
	lifetime, cancel := context.WithCancel(context.Background())
	// Own the pool so closing this sink cannot affect unrelated clients.
	transport := http.DefaultTransport
	if defaults, ok := transport.(*http.Transport); ok {
		transport = defaults.Clone()
	}
	return &WebhookSink{
		includePolicyInput: cfg.IncludePolicyInput,
		url:                cfg.URL,
		client:             &http.Client{Timeout: cfg.Timeout, Transport: transport},
		headers:            maps.Clone(cfg.Headers),
		batchSize:          cfg.BatchSize,
		maxPending:         cfg.MaxPending,
		flushEvery:         cfg.FlushEvery,
		lastFlush:          time.Now(),
		maxAttempts:        cfg.MaxAttempts, maxAge: cfg.MaxAge,
		flushGate: make(chan struct{}, 1), lifetime: lifetime, cancel: cancel,
		closeDone: make(chan struct{}),
	}
}

func (s *WebhookSink) Write(ctx context.Context, event *SecurityEvent) error {
	if err := ctx.Err(); err != nil {
		s.drop("webhook_canceled", 1)
		return err
	}
	if !s.includePolicyInput {
		event = event.SummaryForExport()
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.drop("webhook_closed", 1)
		return errors.New("webhook closed")
	}
	s.expireLocked(time.Now())
	s.batch = append(s.batch, event)
	s.attempts = append(s.attempts, 0)
	s.queuedAt = append(s.queuedAt, time.Now())
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
	return s.flush(ctx, false)
}

func (s *WebhookSink) flush(ctx context.Context, closing bool) error {
	// One timeout covers waiting for a preceding flush AND every request in
	// this flush, not a fresh budget for every queued batch.
	ctx, cancel := context.WithTimeout(ctx, s.client.Timeout)
	defer cancel()
	if !closing {
		stop := context.AfterFunc(s.lifetime, cancel)
		defer stop()
	}
	select {
	case s.flushGate <- struct{}{}:
		defer func() { <-s.flushGate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	s.mu.Lock()
	remaining := len(s.batch) // concurrent writes wait until a later flush
	s.mu.Unlock()
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		s.mu.Lock()
		s.expireLocked(time.Now())
		n := min(len(s.batch), s.batchSize, remaining)
		if n == 0 {
			// Expiry may have removed a previously failing head. Do not
			// suppress full-batch writes after the backlog has disappeared.
			s.failing = false
			s.mu.Unlock()
			return nil
		}
		batch, attempts, queuedAt := s.batch[:n:n], s.attempts[:n:n], s.queuedAt[:n:n]
		s.batch, s.attempts, s.queuedAt = s.batch[n:], s.attempts[n:], s.queuedAt[n:]
		s.lastFlush = time.Now()
		s.mu.Unlock()
		for i := range attempts {
			attempts[i]++
		}
		retry, err := s.post(ctx, batch)
		s.mu.Lock()
		s.failing = err != nil
		if err != nil {
			if s.closed && !closing {
				s.drop("webhook_shutdown", uint64(n))
			} else if retry {
				// Restore failed events still within budget ahead of newer
				// writes. Serialized requests cannot overtake this head.
				var retained []*SecurityEvent
				var tries []int
				var ages []time.Time
				for i, event := range batch {
					switch {
					case attempts[i] >= s.maxAttempts:
						s.drop("webhook_attempts", 1)
					case time.Since(queuedAt[i]) >= s.maxAge:
						s.drop("webhook_expired", 1)
					default:
						retained = append(retained, event)
						tries = append(tries, attempts[i])
						ages = append(ages, queuedAt[i])
					}
				}
				s.batch = append(retained, s.batch...)
				s.attempts = append(tries, s.attempts...)
				s.queuedAt = append(ages, s.queuedAt...)
				s.trimLocked()
			} else {
				s.drop("webhook_rejected", uint64(n))
			}
		}
		clear(batch) // release delivered pointers in the backing array
		s.mu.Unlock()
		if err != nil {
			return err
		}
		remaining -= n
	}
	return nil
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
	// Bound work even if the collector streams a huge/unending response.
	_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()

	if resp.StatusCode >= 400 {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return retry, fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	if readErr != nil {
		return true, fmt.Errorf("webhook response: %w", readErr)
	}
	return false, nil
}

// trimLocked drops the oldest pending events beyond maxPending. s.mu must
// be held.
func (s *WebhookSink) trimLocked() {
	if over := len(s.batch) - s.maxPending; over > 0 {
		s.drop("webhook_overflow", uint64(over))
		s.batch = append([]*SecurityEvent(nil), s.batch[over:]...)
		s.attempts = append([]int(nil), s.attempts[over:]...)
		s.queuedAt = append([]time.Time(nil), s.queuedAt[over:]...)
	}
}

// Dropped returns how many events were discarded, either because the retry
// backlog exceeded MaxPending, retry age/attempt budgets expired, shutdown
// abandoned retries, or the endpoint rejected them permanently.
func (s *WebhookSink) Dropped() uint64 { return s.dropped.Load() }

func (s *WebhookSink) expireLocked(now time.Time) {
	n := 0
	for n < len(s.batch) && now.Sub(s.queuedAt[n]) >= s.maxAge {
		n++
	}
	if n > 0 {
		s.drop("webhook_expired", uint64(n))
		clear(s.batch[:n])
		s.batch, s.attempts, s.queuedAt = s.batch[n:], s.attempts[n:], s.queuedAt[n:]
	}
}

func (s *WebhookSink) drop(reason string, n uint64) {
	s.dropped.Add(n)
	recordLoss(reason, "webhook", n)
}

func (s *WebhookSink) Close() error { return s.CloseContext(context.Background()) }

// CloseContext cancels an active request, attempts one bounded final flush,
// then explicitly counts/discards retained retries. Concurrent callers respect
// their own wait context without creating another shutdown goroutine.
func (s *WebhookSink) CloseContext(ctx context.Context) error {
	s.mu.Lock()
	first := !s.closed
	if first {
		s.closed = true
	}
	s.mu.Unlock()
	if first {
		s.cancel()
		s.closeErr = s.flush(ctx, true)
		// Detached requests outliving this budget see closed and count their
		// own shutdown loss instead of requeueing after cleanup.
		s.mu.Lock()
		s.drop("webhook_shutdown", uint64(len(s.batch)))
		s.batch, s.attempts, s.queuedAt = nil, nil, nil
		s.mu.Unlock()
		s.client.CloseIdleConnections()
		close(s.closeDone)
	}
	select {
	case <-s.closeDone:
		return s.closeErr
	default:
	}
	select {
	case <-s.closeDone:
		return s.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *WebhookSink) Name() string { return "webhook:" + s.url }
