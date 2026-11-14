package policyserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestClientSameVersionReassignmentAndActivationRetry(t *testing.T) {
	srv, ts, _ := setupClientEnv(t)
	ctx := context.Background()
	fail, calls := false, 0
	c := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: "a", Labels: map[string]string{"env": "prod"},
		OnUpdate: func(*PolicyAssignment, []byte) error {
			calls++
			if fail {
				return errors.New("injected disk/load failure")
			}
			return nil
		},
	})
	if err := c.Register(ctx); err != nil {
		t.Fatal(err)
	}
	c.poll(ctx)
	oldHash := c.policyHash
	if err := srv.Store().CreatePolicy(&Policy{ID: "replacement", Priority: 100},
		writeWASM(t, t.TempDir(), "other.wasm", "other module")); err != nil {
		t.Fatal(err)
	}
	fail = true
	c.poll(ctx)
	if err := c.SendHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := srv.Store().GetAgent("a")
	if a.PolicyID != "prod-policy" || a.PolicyVersion != 1 || a.PolicyHash != oldHash || a.ActivationError == "" {
		t.Fatalf("failed activation incorrectly acknowledged: %+v", a)
	}
	fail = false
	c.poll(ctx)
	if err := c.SendHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ = srv.Store().GetAgent("a")
	if calls != 3 || a.PolicyID != "replacement" || a.PolicyVersion != 1 || a.PolicyHash == oldHash || a.ActivationError != "" {
		t.Fatalf("same-version replacement not retried/acknowledged: calls=%d agent=%+v", calls, a)
	}
	c.poll(ctx)
	if calls != 3 {
		t.Fatal("unchanged full identity was reactivated")
	}
}

func TestClientRejectsDownloadDigestMismatch(t *testing.T) {
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filepath.Base(r.URL.Path) == "wasm" {
			_, _ = w.Write([]byte("tampered"))
			return
		}
		sum := sha256.Sum256([]byte("assigned"))
		writeJSON(w, http.StatusOK, PolicyAssignment{PolicyID: "p", Version: 1, WASMHash: hex.EncodeToString(sum[:])})
	}))
	defer ts.Close()
	c := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: "a", OnUpdate: func(*PolicyAssignment, []byte) error { calls++; return nil }})
	c.poll(context.Background())
	c.poll(context.Background())
	if calls != 0 || c.policyVersion != 0 || c.activationError == "" {
		t.Fatalf("digest mismatch accepted: calls=%d version=%d error=%s", calls, c.policyVersion, c.activationError)
	}
}

func TestClientSameIDVersionDifferentDigest(t *testing.T) {
	var revision atomic.Int32
	revision.Store(1)
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := []byte("first")
		if revision.Load() == 2 {
			data = []byte("second")
		}
		if filepath.Base(r.URL.Path) == "wasm" {
			_, _ = w.Write(data)
			return
		}
		sum := sha256.Sum256(data)
		writeJSON(w, http.StatusOK, PolicyAssignment{PolicyID: "p", Version: 1, WASMHash: hex.EncodeToString(sum[:])})
	}))
	defer ts.Close()
	c := NewClient(ClientConfig{ServerURL: ts.URL, OnUpdate: func(*PolicyAssignment, []byte) error { calls++; return nil }})
	c.poll(context.Background())
	revision.Store(2)
	c.poll(context.Background())
	if calls != 2 {
		t.Fatalf("digest identity change skipped: %d activations", calls)
	}
}

func TestClientLegacy304FetchesUnconditionalIdentity(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if filepath.Base(r.URL.Path) == "wasm" {
			_, _ = w.Write([]byte("module"))
			return
		}
		if r.URL.Query().Get("if_version") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		sum := sha256.Sum256([]byte("module"))
		writeJSON(w, http.StatusOK, PolicyAssignment{PolicyID: "replacement", Version: 1, WASMHash: hex.EncodeToString(sum[:])})
	}))
	defer ts.Close()
	c := NewClient(ClientConfig{ServerURL: ts.URL, OnUpdate: func(*PolicyAssignment, []byte) error { return nil }})
	c.policyID, c.policyVersion = "old", 1
	c.poll(context.Background())
	if c.policyID != "replacement" || calls.Load() != 3 {
		t.Fatalf("trusted ambiguous legacy 304: identity=%s requests=%d", c.policyID, calls.Load())
	}
}

func TestClientDoesNotAcknowledgeBeforeActivationReturns(t *testing.T) {
	srv, ts, _ := setupClientEnv(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	c := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: "a", Labels: map[string]string{"env": "prod"},
		OnUpdate: func(*PolicyAssignment, []byte) error { close(entered); <-release; return nil },
	})
	ctx := context.Background()
	if err := c.Register(ctx); err != nil {
		t.Fatal(err)
	}
	go func() { c.poll(ctx); close(done) }()
	<-entered
	if err := c.SendHeartbeat(ctx); err != nil {
		close(release)
		<-done
		t.Fatal(err)
	}
	a, _ := srv.Store().GetAgent("a")
	close(release)
	<-done
	if a.PolicyVersion != 0 || a.PolicyID != "" || a.PolicyHash != "" {
		t.Fatalf("download/staging incorrectly acknowledged: %+v", a)
	}
}
