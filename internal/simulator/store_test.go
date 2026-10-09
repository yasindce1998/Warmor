package simulator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
)

func TestNewEventStore_CreatesNestedDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b", "c")
	store, err := NewEventStore(dir)
	if err != nil {
		t.Fatalf("NewEventStore: %v", err)
	}
	defer store.Close()

	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("expected directory %s to exist: %v", dir, err)
	}
	want := filepath.Join(dir, "events-"+time.Now().UTC().Format("2006-01-02")+".ndjson")
	if _, err := os.Stat(want); err != nil {
		t.Errorf("expected event file %s: %v", want, err)
	}
}

func TestNewEventStore_DirIsFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEventStore(f); err == nil {
		t.Fatal("expected error when dir path is a regular file")
	}
	if _, err := NewEventStore(filepath.Join(f, "sub")); err == nil {
		t.Fatal("expected error when parent path is a regular file")
	}
}

func TestNewEventStore_EventFileIsDir(t *testing.T) {
	dir := t.TempDir()
	// Occupy today's event file path with a directory so OpenFile fails.
	name := "events-" + time.Now().UTC().Format("2006-01-02") + ".ndjson"
	if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := NewEventStore(dir)
	if err == nil {
		t.Fatal("expected error when event file path is a directory")
	}
	if !strings.Contains(err.Error(), "open event file") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEventStore_RotatesOnDateChange(t *testing.T) {
	dir := t.TempDir()
	store, err := NewEventStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Pretend the store was opened on an earlier day; the next Write must rotate.
	store.mu.Lock()
	oldFile := store.file
	store.curDate = "2000-01-01"
	store.mu.Unlock()

	ctx := context.Background()
	if err := store.Write(ctx, &streaming.SecurityEvent{Timestamp: time.Now(), EventType: "exec", Comm: "x"}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	store.mu.Lock()
	rotated := store.file != oldFile
	curDate := store.curDate
	store.mu.Unlock()

	if !rotated {
		t.Error("expected a new file handle after date change")
	}
	if curDate != time.Now().UTC().Format("2006-01-02") {
		t.Errorf("curDate = %q, want today", curDate)
	}
	// The old handle must have been closed.
	if _, err := oldFile.Write([]byte("x")); err == nil {
		t.Error("expected write to old (closed) file to fail")
	}
}

func TestEventStore_WriteRotateError(t *testing.T) {
	dir := t.TempDir()
	store, err := NewEventStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Force rotation into a directory that no longer exists.
	store.mu.Lock()
	store.dir = filepath.Join(dir, "missing")
	store.curDate = ""
	store.mu.Unlock()

	if err := store.Write(context.Background(), &streaming.SecurityEvent{}); err == nil {
		t.Fatal("expected Write to fail when rotation cannot open a file")
	}
}

func TestEventStore_FlushCloseNilFile(t *testing.T) {
	s := &EventStore{dir: t.TempDir()}
	if err := s.Flush(context.Background()); err != nil {
		t.Errorf("Flush with nil file: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close with nil file: %v", err)
	}
}

func TestEventStore_ConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	store, err := NewEventStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = store.Write(ctx, &streaming.SecurityEvent{Timestamp: time.Now(), EventType: "exec", Comm: "c"})
		}()
	}
	wg.Wait()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	events, err := ReadEvents(dir, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != n {
		t.Errorf("read %d events, want %d", len(events), n)
	}
}

func TestReadEvents_SkipsMalformedLinesAndMergesFiles(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC).Format(time.RFC3339)

	day1 := `{"timestamp":"` + ts + `","event_type":"exec","comm":"a"}` + "\n" +
		"not json\n" +
		"\n" +
		`{"timestamp":"` + ts + `","event_type":"file","comm":"b"}` + "\n"
	day2 := `{"timestamp":"` + ts + `","event_type":"network","comm":"c"}` + "\n"

	if err := os.WriteFile(filepath.Join(dir, "events-2024-01-02.ndjson"), []byte(day1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events-2024-01-03.ndjson"), []byte(day2), 0o644); err != nil {
		t.Fatal(err)
	}
	// Files not matching the pattern are ignored.
	if err := os.WriteFile(filepath.Join(dir, "other.ndjson"), []byte(day2), 0o644); err != nil {
		t.Fatal(err)
	}

	events, err := ReadEvents(dir, time.Time{})
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}
	got := events[0].Comm + events[1].Comm + events[2].Comm
	if got != "abc" {
		t.Errorf("event order = %q, want %q", got, "abc")
	}
}

func TestReadEvents_SinceIsInclusive(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	line := `{"timestamp":"` + ts.Format(time.RFC3339) + `","comm":"edge"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "events-x.ndjson"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	events, err := ReadEvents(dir, ts)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Errorf("expected event at exactly 'since' to be included, got %d", len(events))
	}
}

func TestReadEvents_BadGlobPattern(t *testing.T) {
	if _, err := ReadEvents("[", time.Time{}); err == nil {
		t.Fatal("expected glob error for malformed pattern")
	}
}

func TestReadEvents_UnreadableEntry(t *testing.T) {
	dir := t.TempDir()
	// A directory matching the glob pattern causes the read to fail.
	if err := os.Mkdir(filepath.Join(dir, "events-dir.ndjson"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEvents(dir, time.Time{}); err == nil {
		t.Fatal("expected error reading a directory as an event file")
	}
}

func TestReadEventFile_Missing(t *testing.T) {
	if _, err := readEventFile(filepath.Join(t.TempDir(), "nope.ndjson"), time.Time{}); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestReadEventFile_LineTooLong(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events-big.ndjson")
	big := strings.Repeat("x", 1024*1024+10)
	if err := os.WriteFile(path, []byte(big+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readEventFile(path, time.Time{}); err == nil {
		t.Fatal("expected scanner error for line exceeding buffer")
	}
}
