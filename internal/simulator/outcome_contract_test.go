package simulator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestPipelineRecordReplayPreservesActionOutcomes(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	store, err := NewEventStore(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "events.ndjson")
	file, err := streaming.NewFileSink(logPath, 0)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	pipeline := streaming.NewPipeline(streaming.PipelineConfig{Sinks: []streaming.Sink{store, file}})
	t.Cleanup(func() { _ = pipeline.Close() })
	start := time.Unix(1700000000, 0).UTC()
	results := []api.ActionResult{
		{Action: api.ActionDeny, EnforcementError: "identity unavailable"},
		{Action: api.ActionDeny, EnforcementAttempted: true, EnforcementError: "permission denied"},
		{Action: api.ActionDeny, EnforcementAttempted: true, Enforced: true},
		{Action: api.ActionDeny, Enforced: true}, // kernel refusal, no signal attempt
		{Action: api.ActionDeny, Audit: true},
		{Action: api.ActionAllow, Cached: true},
	}
	want := make([]*streaming.SecurityEvent, 0, len(results))
	for i := range results {
		input := &api.Event{
			PID: 100, UID: 1000, Comm: "cat", Filename: "/bin/cat", PPID: 99, ParentComm: "parent",
			Timestamp: start.Add(time.Minute), ContainerStart: start, KernelDenied: i == 3,
			Process: &api.ProcessEvent{Filename: "/bin/cat", Args: []string{"cat", "--secret"}},
		}
		if i == len(results)-1 {
			input.UID, input.Comm, input.Filename = 0, "bash", "/bin/bash"
			input.Process = &api.ProcessEvent{Filename: "/bin/bash", Args: []string{"bash"}}
		}
		want = append(want, streaming.FromAPIEvent(input, &results[i]))
		pipeline.Emit(input, &results[i])
	}
	if err := pipeline.Close(); err != nil {
		t.Fatal(err)
	}
	if stats := pipeline.Stats(); stats.EventsDropped != 0 || stats.SinkErrors != 0 {
		t.Fatalf("recording failed: %+v", stats)
	}
	stored, err := ReadEvents(storeDir, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	logged, err := readEventFile(logPath, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for name, events := range map[string][]*streaming.SecurityEvent{"store": stored, "file": logged} {
		if len(events) != len(want) {
			t.Fatalf("%s recorded %d events, want %d", name, len(events), len(want))
		}
		for i, got := range events {
			if got.Enforced != results[i].Enforced || got.EnforcementAttempted != results[i].EnforcementAttempted || got.EnforcementError != results[i].EnforcementError || got.AuditOnly != results[i].Audit || got.Cached != results[i].Cached {
				t.Fatalf("%s outcome %d changed: %+v", name, i, got)
			}
			if got.Decision != want[i].Decision || got.KernelEnforced != want[i].KernelEnforced || !reflect.DeepEqual(got.PolicyInput, want[i].PolicyInput) {
				t.Fatalf("%s input/decision %d changed: %+v", name, i, got)
			}
		}
		before, err := json.Marshal(events)
		if err != nil {
			t.Fatal(err)
		}
		res, err := Replay(ctx, events, newTestEvaluator(t))
		if err != nil {
			t.Fatal(err)
		}
		// Compare policy decisions, not whether a real action succeeded. Replay
		// must not reinterpret refused, failed, or audit denials as prior allows.
		if res.WouldAllow != 5 || res.WouldDeny != 1 || res.IncompleteEvents != 0 || res.EvaluationErrors != 0 || len(res.UniqueNewAllows) != 1 || res.UniqueNewAllows[0].Count != 5 || len(res.UniqueNewDenials) != 1 || res.UniqueNewDenials[0].Count != 1 {
			t.Fatalf("%s replay conflated outcomes and decisions: %+v", name, res)
		}
		after, err := json.Marshal(events)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Fatalf("%s replay mutated the historical outcomes", name)
		}
	}
	info, err := os.Stat(logPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("recording is not private: %v %v", info, err)
	}
}
