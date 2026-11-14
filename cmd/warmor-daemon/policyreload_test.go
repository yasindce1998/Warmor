package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/enforcer"
	"github.com/yasindce1998/warmor/internal/policyserver"
)

func TestLocalReloadStandalonePropagatesOutcome(t *testing.T) {
	for _, want := range []error{nil, errors.New("precommit validation failed"), enforcer.ErrActivationPending} {
		calls := 0
		err := reloadLocalPolicy(false, func() error { calls++; return want })
		if !errors.Is(err, want) || calls != 1 {
			t.Fatalf("standalone reload: err=%v want=%v calls=%d", err, want, calls)
		}
	}
}

// This is the explicit prohibition alternative to letting SIGHUP publish B and
// trying to repair fleet identity afterward. A queued local B must never reach
// live commit/drain at all; A's subsequent acknowledgement and 304 remain true.
func TestFleetLocalReloadCannotPublishUntrackedGeneration(t *testing.T) {
	t.Setenv(serverTokenEnv, "")
	ctx := context.Background()
	srv := policyserver.NewServer(policyserver.ServerConfig{Insecure: true})
	dataA := []byte("fleet revision A")
	upload := writeFile(t, filepath.Join(t.TempDir(), "a.wasm"), string(dataA))
	if err := srv.Store().CreatePolicy(&policyserver.Policy{ID: "A"}, upload); err != nil {
		t.Fatal(err)
	}
	var notModified atomic.Int32
	handler := srv.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/policy" {
			handler.ServeHTTP(w, r)
			return
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, r)
		for name, values := range response.Header() {
			w.Header()[name] = values
		}
		w.WriteHeader(response.Code)
		_, _ = w.Write(response.Body.Bytes())
		if response.Code == http.StatusNotModified {
			notModified.Add(1)
		}
	}))
	defer ts.Close()
	var live atomic.Value
	live.Store("")
	var updates atomic.Int32
	c, err := newPolicyClient(policyClientConfig{ServerURL: ts.URL, AgentID: "node"}, func(a *policyserver.PolicyAssignment, data []byte) error {
		if a.PolicyID != "A" || string(data) != string(dataA) {
			t.Error("unexpected fleet assignment")
		}
		live.Store(string(data))
		updates.Add(1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Register(ctx); err != nil {
		t.Fatal(err)
	}
	pollCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); c.PollLoop(pollCtx, time.Millisecond) }()
	defer func() { cancel(); <-done }()
	wait := func(ready func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !ready() {
			if time.Now().After(deadline) {
				t.Fatal("timed out waiting for fleet reconciliation")
			}
			time.Sleep(time.Millisecond)
		}
	}
	wait(func() bool {
		if err := c.SendHeartbeat(ctx); err != nil {
			t.Fatal(err)
		}
		a, ok := srv.Store().GetAgent("node")
		return ok && a.PolicyID == "A" && a.PolicyVersion == 1 && a.PolicyHash != "" && a.ActivationError == ""
	})
	before, _ := srv.Store().GetAgent("node")
	// Model the reported trigger: an external local writer installs B, and
	// the reload callback would commit it live before failing old-gen drain.
	local := writeFile(t, filepath.Join(t.TempDir(), "policy.wasm"), "local revision B")
	called := false
	err = reloadLocalPolicy(true, func() error {
		called = true
		data, err := os.ReadFile(local)
		if err != nil {
			return err
		}
		live.Store(string(data))
		return enforcer.ErrActivationPending
	})
	if !errors.Is(err, errFleetLocalReload) || called {
		t.Fatalf("fleet SIGHUP reached untracked live commit: err=%v called=%v", err, called)
	}
	conditionalBefore := notModified.Load()
	wait(func() bool { return notModified.Load() > conditionalBefore })
	if err := c.SendHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	after, _ := srv.Store().GetAgent("node")
	if live.Load() != string(dataA) || updates.Load() != 1 || after.PolicyID != before.PolicyID || after.PolicyVersion != before.PolicyVersion || after.PolicyHash != before.PolicyHash || after.ActivationError != "" {
		t.Fatalf("rejected local reload changed live/acknowledged A: live=%v updates=%d agent=%+v", live.Load(), updates.Load(), after)
	}
}
