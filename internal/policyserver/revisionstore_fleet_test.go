package policyserver

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFleetRevisionAcknowledgementSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenStore(path, StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterAgentChecked(&RegisterRequest{ID: "agent"}); err != nil {
		t.Fatal(err)
	}
	req := HeartbeatRequest{AgentID: "agent", PolicyID: "accepted-policy", PolicyVersion: 7,
		PolicyHash: "exact-active-digest", ActivationError: "replacement failed to load"}
	if err := s.HeartbeatRevision(req); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTestStore(t, path, StoreOptions{})
	a, ok := s.GetAgent("agent")
	if !ok || a.PolicyID != req.PolicyID || a.PolicyVersion != req.PolicyVersion ||
		a.PolicyHash != req.PolicyHash || a.ActivationError != req.ActivationError {
		t.Fatalf("restart lost active acknowledgement: %+v", a)
	}
}

func TestFleetRevisionAcknowledgementWriteFailureRollsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := openTestStore(t, path, StoreOptions{})
	if _, err := s.RegisterAgentChecked(&RegisterRequest{ID: "agent"}); err != nil {
		t.Fatal(err)
	}
	if err := s.HeartbeatRevision(HeartbeatRequest{AgentID: "agent", PolicyID: "old", PolicyVersion: 1, PolicyHash: "old-digest"}); err != nil {
		t.Fatal(err)
	}
	// A nonempty directory cannot be replaced by the snapshot's file rename.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "block-rename"), []byte("failure injection"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.HeartbeatRevision(HeartbeatRequest{AgentID: "agent", PolicyID: "new", PolicyVersion: 2, PolicyHash: "new-digest"}); err == nil {
		t.Fatal("unpersisted revision acknowledged")
	}
	a, _ := s.GetAgent("agent")
	if a.PolicyID != "old" || a.PolicyVersion != 1 || a.PolicyHash != "old-digest" {
		t.Fatalf("failed snapshot leaked acknowledgement: %+v", a)
	}
	if _, err := s.RegisterAgentChecked(&RegisterRequest{ID: "other"}); err == nil {
		t.Fatal("registration discarded persistence error")
	}
	if _, ok := s.GetAgent("other"); ok {
		t.Fatal("failed registration leaked")
	}
}

func TestFleetRevisionClosedStoreRejectsAcknowledgement(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "state.json"), StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterAgentChecked(&RegisterRequest{ID: "agent"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.HeartbeatRevision(HeartbeatRequest{AgentID: "agent", PolicyVersion: 2}); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("closed store accepted heartbeat: %v", err)
	}
	if _, err := s.RegisterAgentChecked(&RegisterRequest{ID: "other"}); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("closed store accepted registration: %v", err)
	}
}
