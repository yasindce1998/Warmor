//go:build linux && integration && generation_daemon_vm

package generationvm

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

func TestProfileGuardRejectsHostAndContainer(t *testing.T) {
	for _, tc := range []struct {
		init  string
		ports []string
		valid bool
	}{
		{"/usr/lib/systemd/systemd", []string{"ctrl", "stdio"}, false},
		{"/usr/bin/tini", []string{"ctrl", "stdio"}, false},
		{"/usr/bin/vimto", nil, false},
		{"/usr/bin/vimto", []string{"ctrl\n", "stdio\n"}, true},
	} {
		if err := ValidateGuard(tc.init, tc.ports); (err == nil) != tc.valid {
			t.Fatalf("guard(%q,%v)=%v", tc.init, tc.ports, err)
		}
	}
}

// These are safe fake-control oracles, not bypasses available to a daemon.
// Only test code can assign the private profile state without Init's guard.
func TestProfileFaultStagesAndHeldEventCancellation(t *testing.T) {
	dir := t.TempDir()
	profile.Lock()
	profile.dir, profile.active, profile.attempts = dir, 2, map[string]int{}
	profile.Unlock()
	t.Cleanup(func() {
		profile.Lock()
		defer profile.Unlock()
		profile.dir = ""
		profile.active = 0
		profile.attempts = nil
	})
	set := func(c control) {
		t.Helper()
		data, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "control.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	set(control{FailDurable: true, FailDrain: true})
	for _, stage := range []string{"durable-sync", "before-drain"} {
		if err := Checkpoint(context.Background(), stage, 2, nil); err == nil {
			t.Fatal("fault stage falsely succeeded", stage)
		}
	}
	set(control{})
	if err := Checkpoint(context.Background(), "durable-sync", 2, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "durable-sync-2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var status struct{ Attempt int }
	if err := json.Unmarshal(data, &status); err != nil || status.Attempt != 2 {
		t.Fatalf("recovery did not retry same named stage: %s %v", data, err)
	}
	set(control{HoldID: 1, HoldPath: "/fixture"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err = Checkpoint(ctx, "event", 1, &api.Event{LSMEvent: true, Hook: "exec", Filename: "/fixture"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("held worker ignored cancellation", err)
	}
}
