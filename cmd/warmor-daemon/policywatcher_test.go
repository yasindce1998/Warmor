package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testWatchInterval is the shortened poll interval for watcher tests.
const testWatchInterval = 10 * time.Millisecond

// touchFuture sets the file's mtime strictly in the future so a change is
// detected regardless of filesystem timestamp granularity.
func touchFuture(t *testing.T, path string) {
	t.Helper()
	future := time.Now().Add(10 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyWatcher_ReloadsOnChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.wasm")
	if err := os.WriteFile(path, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}

	reloadCh := make(chan struct{}, 1)
	stop := watchPolicyFile(path, reloadCh, testWatchInterval)
	defer stop()

	// Give the watcher goroutine time to record the initial mtime before
	// the test changes it, otherwise the change can race the first stat.
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(path, []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reloadCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no reload signal after the policy file changed")
	}
}

func TestPolicyWatcher_FileAppearingLater(t *testing.T) {
	// The watched path does not exist yet (e.g. the policy has not been
	// downloaded); the watcher must tolerate that and pick the file up
	// once it appears.
	path := filepath.Join(t.TempDir(), "policy.wasm")
	reloadCh := make(chan struct{}, 1)
	stop := watchPolicyFile(path, reloadCh, testWatchInterval)
	defer stop()

	// Wait for the watcher's initial (failing) stat before creating the
	// file, otherwise the baseline can race the creation.
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(path, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	touchFuture(t, path)
	select {
	case <-reloadCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no reload signal after the policy file appeared")
	}
}

func TestPolicyWatcher_StopIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.wasm")
	if err := os.WriteFile(path, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	stop := watchPolicyFile(path, make(chan struct{}, 1), testWatchInterval)
	stop()
	stop() // must not panic or block
}

func TestSeedPolicyFile(t *testing.T) {
	dir := t.TempDir()
	fallback := filepath.Join(dir, "fallback.wasm")
	if err := os.WriteFile(fallback, []byte("baked policy"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("seeds a missing policy", func(t *testing.T) {
		target := filepath.Join(dir, "state", "policy.wasm")
		if err := seedPolicyFile(target, fallback, false); err != nil {
			t.Fatalf("seed: %v", err)
		}
		data, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "baked policy" {
			t.Errorf("seeded policy = %q, want the fallback contents", data)
		}
	})

	t.Run("never overwrites an existing policy", func(t *testing.T) {
		target := filepath.Join(dir, "existing.wasm")
		if err := os.WriteFile(target, []byte("downloaded"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := seedPolicyFile(target, fallback, false); err != nil {
			t.Fatalf("seed: %v", err)
		}
		data, _ := os.ReadFile(target)
		if string(data) != "downloaded" {
			t.Errorf("policy = %q, want the existing one untouched", data)
		}
	})

	t.Run("no fallback is a no-op", func(t *testing.T) {
		if err := seedPolicyFile(filepath.Join(dir, "x.wasm"), "", false); err != nil {
			t.Errorf("seed without fallback: %v", err)
		}
	})

	t.Run("refused with signature verification", func(t *testing.T) {
		target := filepath.Join(dir, "signed.wasm")
		err := seedPolicyFile(target, fallback, true)
		if err == nil {
			t.Fatal("seeding with --verify-key must be refused")
		}
		if _, statErr := os.Stat(target); statErr == nil {
			t.Error("refused seeding still wrote the policy file")
		}
	})

	t.Run("missing fallback is an error", func(t *testing.T) {
		if err := seedPolicyFile(filepath.Join(dir, "y.wasm"), filepath.Join(dir, "nope.wasm"), false); err == nil {
			t.Fatal("seeding from a missing fallback must fail")
		}
	})
}
