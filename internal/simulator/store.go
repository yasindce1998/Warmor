package simulator

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/privatefile"
	"github.com/yasindce1998/warmor/internal/streaming"
)

// EventStore is an append-only ndjson event store that implements streaming.Sink.
// Events are stored in daily-rotated files for replay.
type EventStore struct {
	dir        string
	file       *os.File
	enc        *json.Encoder
	mu         sync.Mutex
	curDate    string
	createDirs bool // only initial setup may create directories; rotation must not recreate a removed store
}

// NewEventStore creates or opens an event store in the given directory.
func NewEventStore(dir string) (*EventStore, error) {
	s := &EventStore{dir: dir, createDirs: true}
	if err := s.rotateIfNeeded(); err != nil {
		return nil, err
	}
	s.createDirs = false
	// Secure older daily recordings too; protecting only today's file would
	// leave previously captured credentials exposed after an upgrade.
	entries, err := os.ReadDir(dir)
	if err != nil {
		_ = s.file.Close()
		return nil, err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "events-") || !strings.HasSuffix(entry.Name(), ".ndjson") {
			continue
		}
		if _, err := time.Parse("2006-01-02", strings.TrimSuffix(strings.TrimPrefix(entry.Name(), "events-"), ".ndjson")); err != nil {
			continue
		}
		f, err := privatefile.OpenAppend(filepath.Join(dir, entry.Name()), true, false)
		if err != nil {
			_ = s.file.Close()
			return nil, fmt.Errorf("secure existing event recording: %w", err)
		}
		if err := f.Close(); err != nil {
			_ = s.file.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *EventStore) rotateIfNeeded() error {
	today := time.Now().UTC().Format("2006-01-02")
	if today == s.curDate && s.file != nil {
		return nil
	}

	if s.file != nil {
		_ = s.file.Close()
		s.file = nil
		s.enc = nil
	}

	path := filepath.Join(s.dir, fmt.Sprintf("events-%s.ndjson", today))
	f, err := privatefile.OpenAppend(path, true, s.createDirs)
	if err != nil {
		return fmt.Errorf("open event file: %w", err)
	}
	s.file = f
	s.enc = json.NewEncoder(f)
	s.curDate = today
	return nil
}

func (s *EventStore) Write(_ context.Context, event *streaming.SecurityEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.rotateIfNeeded(); err != nil {
		return err
	}
	return s.enc.Encode(event)
}

func (s *EventStore) Flush(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		return s.file.Sync()
	}
	return nil
}

func (s *EventStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

func (s *EventStore) Name() string { return "event-store:" + s.dir }

// ReadEvents reads all events from the store directory that fall within
// the given time range.
func ReadEvents(dir string, since time.Time) ([]*streaming.SecurityEvent, error) {
	pattern := filepath.Join(dir, "events-*.ndjson")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("glob event files: %w", err)
	}

	var events []*streaming.SecurityEvent
	for _, path := range files {
		fileEvents, err := readEventFile(path, since)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		events = append(events, fileEvents...)
	}
	return events, nil
}

func readEventFile(path string, since time.Time) ([]*streaming.SecurityEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []*streaming.SecurityEvent
	var malformed, oversized int
	r := bufio.NewReader(f)
	for {
		line, tooLong, err := readBoundedLine(r, maxEventLineBytes)
		if err != nil && err != io.EOF {
			return nil, err
		}
		switch {
		case tooLong:
			// Like malformed lines, an oversized line is skipped rather
			// than failing the whole replay.
			oversized++
		case len(bytes.TrimSpace(line)) == 0:
			// Blank line.
		default:
			var event streaming.SecurityEvent
			if jerr := json.Unmarshal(line, &event); jerr != nil {
				malformed++
			} else if !event.Timestamp.Before(since) {
				events = append(events, &event)
			}
		}
		if err == io.EOF {
			break
		}
	}
	if malformed > 0 || oversized > 0 {
		log.Printf("simulator: %s: skipped %d malformed and %d oversized (>%d bytes) lines",
			path, malformed, oversized, maxEventLineBytes)
	}
	return events, nil
}

// maxEventLineBytes caps the size of a single ndjson record in the store.
const maxEventLineBytes = 1024 * 1024

// readBoundedLine reads one '\n'-terminated line (terminator included) from
// r. If the line exceeds max bytes it is consumed and discarded without
// being buffered, and tooLong is reported. err is io.EOF on the final line.
func readBoundedLine(r *bufio.Reader, max int) (line []byte, tooLong bool, err error) {
	for {
		chunk, err := r.ReadSlice('\n')
		if !tooLong {
			line = append(line, chunk...)
			if len(bytes.TrimRight(line, "\r\n")) > max {
				tooLong, line = true, nil
			}
		}
		if err != bufio.ErrBufferFull {
			return line, tooLong, err
		}
	}
}
