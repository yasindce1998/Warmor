package policyserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/telemetry"
)

func TestTelemetryDurablePublicationFailureStages(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprintf("replacement-committed=%t", committed), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "telemetry.json")
			store, err := OpenTelemetryStore(path, testTelemetryConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			now := time.Now()
			store.clock = func() time.Time { return now }
			if err := store.ConfigureGeneration("r", "g"); err != nil {
				t.Fatal(err)
			}
			snapshot, ack := telemetryTestSource(t, store, now, "agent", true)
			if _, err := store.ingest("agent", ack, snapshot); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			failure := errors.New("snapshot publication failed")
			calls := 0
			store.publish = func(from, to string) (bool, error) {
				calls++
				if committed {
					// Model replacement succeeding before its durability barrier
					// fails; the disk view may differ from the unpublished memory.
					if _, err := publishSnapshot(from, to); err != nil {
						return false, fmt.Errorf("fixture replacement: %w", err)
					}
				}
				return committed, failure
			}
			now = now.Add(time.Second)
			ack.LastHeartbeat = now
			snapshot.Sequence++
			snapshot.Total = 10
			if _, err := store.ingest("agent", ack, snapshot); !errors.Is(err, ErrStatePersistence) {
				t.Fatalf("publication failure not surfaced: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(before, after) == committed || calls != 1 {
				t.Fatal("fixture did not fail at the expected publication stage")
			}
			if src := store.state.Sources["agent"]; src.Cursor.Sequence != 1 || src.Cursor.Total != 0 || store.Report("r").Canary.Total != 0 {
				t.Fatal("failed publication exposed a partial cursor/contribution")
			}
			if committed {
				if !errors.Is(store.fault, failure) || store.Report("r").Verdict != "pending" || store.Report("r").Reason != "unavailable-generation" {
					t.Fatal("ambiguous durability did not poison reports")
				}
				if _, err := store.ingest("agent", ack, snapshot); !errors.Is(err, ErrStatePersistence) || calls != 1 {
					t.Fatal("poisoned writer attempted another publication", err)
				}
			} else {
				if store.fault != nil {
					t.Fatal("definite precommit failure poisoned ordinary telemetry write")
				}
				store.publish = publishSnapshot
				if result, err := store.ingest("agent", ack, snapshot); err != nil || result.Total != 10 {
					t.Fatalf("precommit retry did not contribute exactly once: %+v %v", result, err)
				}
				if result, err := store.ingest("agent", ack, snapshot); err != nil || result.Status != "duplicate" || store.Report("r").Canary.Total != 10 {
					t.Fatalf("retry duplicated evidence: %+v %v", result, err)
				}
			}
		})
	}
}

func TestTelemetryDurableReplacementPreservesPrivateSnapshot(t *testing.T) {
	dir := t.TempDir()
	preparePrivateSnapshotDir(t, dir)
	path := filepath.Join(dir, "telemetry.json")
	store, err := OpenTelemetryStore(path, testTelemetryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	assertSnapshot := func() {
		t.Helper()
		assertPrivateSnapshot(t, path)
		assertPrivateSnapshot(t, path+".lock")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want, err := json.Marshal(store.state)
		if err != nil || !bytes.Equal(data, want) {
			t.Fatalf("successful publication differs from memory: %v", err)
		}
		leftovers, err := filepath.Glob(filepath.Join(dir, ".telemetry-*"))
		if err != nil || len(leftovers) != 0 {
			t.Fatalf("publication left temporary snapshots: %v %v", leftovers, err)
		}
	}
	assertSnapshot() // creation
	if err := store.ConfigureGeneration("r", "g"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthorizeSession("agent"); err != nil {
		t.Fatal(err)
	}
	assertSnapshot() // repeated replacement of an existing file
	oldEpoch := store.state.Epoch
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenTelemetryStore(path, testTelemetryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	store = reopened
	assertSnapshot() // restart durably replaces the epoch before returning
	if store.state.Epoch == oldEpoch || len(store.state.Sources) != 0 || store.Report("r").Verdict != "pending" {
		t.Fatal("restart retained evidence or failed to rotate epoch")
	}
}

func TestTelemetryDurableFailureLeavesCursorAndSnapshotUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenTelemetryStore(path, testTelemetryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now()
	store.clock = func() time.Time { return now }
	if err := store.ConfigureGeneration("r", "g"); err != nil {
		t.Fatal(err)
	}
	s, ack := telemetryTestSource(t, store, now, "agent", true)
	if _, err := store.ingest("agent", ack, s); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store.path = filepath.Join(t.TempDir(), "missing", "state.json")
	now = now.Add(time.Second)
	ack.LastHeartbeat = now
	s.Sequence++
	s.Total = 10
	if _, err := store.ingest("agent", ack, s); err == nil {
		t.Fatal("write failure returned success")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("failure changed durable state: %v", err)
	}
	if source := store.state.Sources["agent"]; source.Cursor.Sequence != 1 || source.Cursor.Total != 0 || store.Report("r").Canary.Total != 0 {
		t.Fatal("failure advanced cursor or aggregate")
	}
	store.path = path
	if r, err := store.ingest("agent", ack, s); err != nil || r.Total != 10 {
		t.Fatalf("retry did not commit once: %+v %v", r, err)
	}
	// A report cannot renew an expired session; reauthorization revokes and
	// bootstraps instead of admitting the cumulative offline backlog.
	now = now.Add(2 * time.Hour)
	ack.LastHeartbeat = now
	s.Sequence++
	if _, err := store.ingest("agent", ack, s); err == nil {
		t.Fatal("expired lease admitted report")
	}
}

func TestTelemetryActivationAToBToANeverReusesIdentity(t *testing.T) {
	store, _ := NewTelemetryStore(testTelemetryConfig())
	now := time.Now()
	store.clock = func() time.Time { return now }
	if err := store.ConfigureGeneration("r", "g"); err != nil {
		t.Fatal(err)
	}
	a, ack := telemetryTestSource(t, store, now, "agent", true)
	if _, err := store.ingest("agent", ack, a); err != nil {
		t.Fatal(err)
	}
	old := a
	for _, version := range []int64{2, 1} {
		now = now.Add(time.Second)
		ack.LastHeartbeat = now
		b := *store.state.Sources["agent"].Desired
		b.Revision.PolicyVersion = version
		b.AssignmentKey += "next"
		assignment, err := store.issueAssignment("agent", a.Session, b)
		if err != nil {
			t.Fatal(err)
		}
		a.Revision.PolicyVersion, a.Revision.AssignmentRevision = version, assignment.AssignmentRevision
		a.Revision.ActivationID += "next"
		a.Sequence++
		a.Total, a.Denied = 500, 400
		ack.PolicyVersion = version
		if result, err := store.ingest("agent", ack, a); err != nil || result.Status != "bootstrap" || result.Total != 0 {
			t.Fatalf("activation bootstrap: %+v %v", result, err)
		}
	}
	old.Sequence = a.Sequence + 1
	if _, err := store.ingest("agent", ack, old); err == nil {
		t.Fatal("old A switched active cursor back")
	}
	if r := store.Report("r"); r.Canary.Total != 0 {
		t.Fatalf("unknown prehistory counted: %+v", r)
	}
}

func TestTelemetryAcknowledgementQualityClockAndOverflow(t *testing.T) {
	store, _ := NewTelemetryStore(testTelemetryConfig())
	now := time.Now()
	store.clock = func() time.Time { return now }
	if err := store.ConfigureGeneration("r", "g"); err != nil {
		t.Fatal(err)
	}
	s, ack := telemetryTestSource(t, store, now, "a", true)
	for _, change := range []func(*Agent){
		func(a *Agent) { a.PolicyID = "other-policy-same-version" },
		func(a *Agent) { a.PolicyHash = "wrong-hash" },
		func(a *Agent) { a.ActivationError = "failed" },
		func(a *Agent) { a.LastHeartbeat = now.Add(-time.Minute) },
	} {
		bad := *ack
		change(&bad)
		if _, err := store.ingest("a", &bad, s); err == nil {
			t.Fatalf("unacknowledged revision accepted: %+v", bad)
		}
	}
	if _, err := store.ingest("a", ack, s); err != nil {
		t.Fatal(err)
	}
	now = now.Add(-time.Second)
	ack.LastHeartbeat = now
	s.Sequence++
	if _, err := store.ingest("a", ack, s); err == nil {
		t.Fatal("clock reversal advanced cursor")
	}
	now = now.Add(2 * time.Second)
	ack.LastHeartbeat = now
	s.Total = math.MaxUint64
	if _, err := store.ingest("a", ack, s); err != nil {
		t.Fatal(err)
	}
	// A second source summing beyond uint64 never produces a partial verdict.
	second, secondAck := telemetryTestSource(t, store, now, "b", true)
	if _, err := store.ingest("b", secondAck, second); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	secondAck.LastHeartbeat = now
	second.Sequence++
	second.Total = 1
	if _, err := store.ingest("b", secondAck, second); err != nil {
		t.Fatal(err)
	}
	if r := store.Report("r"); r.Verdict != "pending" || r.Reason != "unreliable-or-overflow" || r.Canary.Total != 0 {
		t.Fatalf("unchecked aggregate overflow: %+v", r)
	}
	// A saturated source sequence cannot wrap to one, even after activation.
	store.state.Sources["a"].Cursor.Sequence = math.MaxUint64
	wrapped := s
	wrapped.Sequence = 1
	if result, err := store.ingest("a", ack, wrapped); err != nil || result.Status != "stale" {
		t.Fatalf("wrapped sequence: %+v %v", result, err)
	}
	// The wire count types remain uint64, never platform int.
	var _ uint64 = telemetry.Snapshot{}.Total
}

func TestTelemetryIdleTimeDoesNotSatisfyWarmup(t *testing.T) {
	store, _ := NewTelemetryStore(testTelemetryConfig())
	now := time.Now()
	store.clock = func() time.Time { return now }
	if err := store.ConfigureGeneration("r", "g"); err != nil {
		t.Fatal(err)
	}
	var reports []telemetry.Snapshot
	var acks []*Agent
	for _, id := range []string{"base", "canary"} {
		s, ack := telemetryTestSource(t, store, now, id, id == "canary")
		if _, err := store.ingest(id, ack, s); err != nil {
			t.Fatal(err)
		}
		reports, acks = append(reports, s), append(acks, ack)
	}
	for i := 0; i < 4; i++ {
		now = now.Add(time.Second)
		for j := range reports {
			reports[j].Sequence++
			acks[j].LastHeartbeat = now
			if _, err := store.ingest(acks[j].ID, acks[j], reports[j]); err != nil {
				t.Fatal(err)
			}
		}
	}
	for j := range reports {
		reports[j].Sequence++
		reports[j].Total++
		if _, err := store.ingest(acks[j].ID, acks[j], reports[j]); err != nil {
			t.Fatal(err)
		}
	}
	if r := store.Report("r"); r.Verdict != "pending" || r.ObservedFor != 0 {
		t.Fatalf("idle bootstrap counted as observation: %+v", r)
	}
	now = now.Add(time.Second)
	if r := store.Report("r"); r.Verdict != "healthy" {
		t.Fatalf("fresh warmup not observed: %+v", r)
	}
}
