//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package streaming

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/testutil"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Umask is process-global: only mutate it in a child, never the test runner.
func TestFileRecordingPermissionsUmask022(t *testing.T) {
	if os.Getenv("WARMOR_PRIVATE_FILE_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFileRecordingPermissionsUmask022$")
		cmd.Env = append(os.Environ(), "WARMOR_PRIVATE_FILE_CHILD=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child: %v\n%s", err, output)
		}
		return
	}
	syscall.Umask(0022)
	dir := testutil.PhysicalTempDir(t)
	path := filepath.Join(dir, "events.ndjson")
	// Tighten a legacy world-readable file before appending argv.
	if err := os.WriteFile(path, []byte("legacy\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".1234", []byte("old secret"), 0644); err != nil {
		t.Fatal(err)
	}
	sink, err := NewFileSink(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	event := FromAPIEvent(&api.Event{Process: &api.ProcessEvent{Args: []string{"app", "--password", "secret-token"}}}, nil)
	for i := 0; i < 3; i++ {
		if err := sink.Write(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(path + "*")
	if len(files) < 3 {
		t.Fatalf("rotation not exercised: %v", files)
	}
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("unsafe recording %s: %v %v", file, info, err)
		}
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "secret-token") {
		t.Fatal("private recording lost replay inputs")
	}
	// New path, independently of the tightened legacy path.
	fresh, err := NewFileSink(filepath.Join(dir, "fresh"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fresh.Close() }()
	info, _ := os.Stat(filepath.Join(dir, "fresh"))
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	// Symlinks, hardlinks, and symlink parent components are never followed.
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if s, err := NewFileSink(link, 0); err == nil {
		_ = s.Close()
		t.Fatal("followed symlink")
	}
	hard := filepath.Join(dir, "hard")
	if err := os.Link(target, hard); err != nil {
		t.Fatal(err)
	}
	if s, err := NewFileSink(hard, 0); err == nil {
		_ = s.Close()
		t.Fatal("accepted hardlink")
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if s, err := NewFileSink(filepath.Join(alias, "new"), 0); err == nil {
		_ = s.Close()
		t.Fatal("followed symlink directory")
	}
	shared := filepath.Join(dir, "shared")
	if err := os.Mkdir(shared, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0777); err != nil {
		t.Fatal(err)
	}
	if s, err := NewFileSink(filepath.Join(shared, "new"), 0); err == nil {
		_ = s.Close()
		t.Fatal("accepted other-user-writable parent")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := NewFileSink(fifo, 0); err == nil {
		_ = s.Close()
		t.Fatal("accepted nonregular recording")
	}
	archiveLog := filepath.Join(dir, "archive-log")
	if err := os.Symlink(target, archiveLog+".1234"); err != nil {
		t.Fatal(err)
	}
	if s, err := NewFileSink(archiveLog, 0); err == nil {
		_ = s.Close()
		t.Fatal("followed legacy archive symlink")
	}
	// A swapped active path must not redirect rotation/reopening into a target.
	rotating, err := NewFileSink(filepath.Join(dir, "rotate"), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rotating.Close() }()
	if err := rotating.Write(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "rotate")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "rotate")); err != nil {
		t.Fatal(err)
	}
	if err := rotating.Write(context.Background(), event); err == nil {
		t.Fatal("rotation followed swapped symlink")
	}
	data, _ = os.ReadFile(target)
	info, _ = os.Stat(target)
	if string(data) != "unchanged" || info.Mode().Perm() != 0644 {
		t.Fatal("unsafe target modified")
	}
}

func TestPrivateRecordingQueueDrainsAndCloses(t *testing.T) {
	if os.Getenv("WARMOR_PRIVATE_QUEUE_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestPrivateRecordingQueueDrainsAndCloses$")
		cmd.Env = append(os.Environ(), "WARMOR_PRIVATE_QUEUE_CHILD=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child: %v\n%s", err, output)
		}
		return
	}
	syscall.Umask(0022)
	dir := testutil.PhysicalTempDir(t)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "events.ndjson")
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	file, err := NewFileSink(path, 1) // Rotate on every write after the first.
	if err != nil {
		t.Fatal(err)
	}
	var public bytes.Buffer
	stdout := NewStdoutSink()
	stdout.enc = json.NewEncoder(&public)
	results := []api.ActionResult{
		{Action: api.ActionDeny, EnforcementError: "identity unavailable"},
		{Action: api.ActionDeny, EnforcementAttempted: true, EnforcementError: "permission denied"},
		{Action: api.ActionDeny, EnforcementAttempted: true, Enforced: true},
		{Action: api.ActionDeny, Enforced: true},
		{Action: api.ActionDeny, Audit: true},
	}
	p := NewPipeline(PipelineConfig{Sinks: []Sink{file, stdout}, BufferSize: len(results), SinkBufferSize: len(results)})
	t.Cleanup(func() { _ = p.Close() })
	for i := range results {
		p.Emit(&api.Event{PID: uint32(i + 1), KernelDenied: i == 3, Process: &api.ProcessEvent{Filename: "/tool", Args: []string{"tool", "--password", "secret-token"}}}, &results[i])
	}
	// Every caller must wait for both independent workers to flush and close.
	var callers sync.WaitGroup
	for range 3 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			if err := p.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	callers.Wait()
	stats := p.Stats()
	if stats.EventsEmitted != uint64(len(results)) || stats.EventsDropped != 0 || stats.SinkErrors != 0 {
		t.Fatalf("pipeline did not drain: %+v", stats)
	}
	for _, sink := range stats.Sinks {
		if sink.Written != uint64(len(results)) || sink.Pending != 0 || sink.QueueDropped != 0 || sink.ShutdownDropped != 0 || sink.DeliveryDropped != 0 {
			t.Fatalf("worker did not drain: %+v", sink)
		}
	}
	if _, err := file.file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Close returned before recording descriptor closed: %v", err)
	}
	files, err := filepath.Glob(path + "*")
	if err != nil || len(files) != len(results) {
		t.Fatalf("rotation files = %v, err %v", files, err)
	}
	seen := make(map[uint32]bool)
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("unsafe queued recording %s: %v %v", path, info, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var event SecurityEvent
		if err := json.Unmarshal(bytes.TrimSpace(data), &event); err != nil {
			t.Fatal(err)
		}
		if event.PID < 1 || event.PID > uint32(len(results)) || seen[event.PID] {
			t.Fatalf("missing/duplicated queued event: %+v", event)
		}
		seen[event.PID] = true
		result := results[event.PID-1]
		if event.PolicyInput == nil || event.PolicyInput.Process.Args[2] != "secret-token" || event.Enforced != result.Enforced || event.EnforcementAttempted != result.EnforcementAttempted || event.EnforcementError != result.EnforcementError || event.AuditOnly != result.Audit || event.KernelEnforced != (event.PID == 4) {
			t.Fatalf("worker lost private input or actual outcome: %+v", event)
		}
	}
	if strings.Contains(public.String(), "secret-token") || bytes.Count(public.Bytes(), []byte(`"redacted"`)) != len(results) {
		t.Fatalf("independent export was not redacted: %s", public.String())
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("worker chmodded shared parent: %v %v", info, err)
	}
	// Do not allow a later call to restart the closed recording worker.
	p.Emit(&api.Event{Timestamp: time.Now()}, nil)
	if p.Stats().EventsRejected != 1 {
		t.Fatal("closed pipeline accepted another private recording")
	}
}
