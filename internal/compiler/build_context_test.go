package compiler

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestBuildContextBoundsToolchainAndCleansFailedCrates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake toolchain uses POSIX shell executables")
	}
	for _, stage := range []string{"rustup", "cargo"} {
		t.Run(stage, func(t *testing.T) {
			bin := t.TempDir()
			work := t.TempDir()
			out := filepath.Join(t.TempDir(), "policy.wasm")
			if err := os.WriteFile(out, []byte("last known good"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin)
			t.Setenv("TMPDIR", work)
			for _, tool := range []string{"rustup", "cargo"} {
				body := "#!/bin/sh\necho wasm32-unknown-unknown\n"
				if tool == stage {
					body = "#!/bin/sh\nexec /bin/sleep 30\n"
				}
				if err := os.WriteFile(filepath.Join(bin, tool), []byte(body), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			policy := &Policy{Name: "context-test", Version: 1, DefaultAction: "deny", Rules: []Rule{{
				Name: "deny", Event: "process", Action: "deny", Conditions: Conditions{All: []Condition{{Field: "path", Operator: "eq", Value: "/bin/blocked"}}},
			}}}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			result, err := Build(policy, BuildOptions{Context: ctx, OutputPath: out})
			defer Cleanup(result)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("error = %v, want context deadline", err)
			}
			if time.Since(start) > 5*time.Second {
				t.Fatal("compilation cancellation did not terminate subprocess")
			}
			files, err := os.ReadDir(work)
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != 0 {
				t.Fatalf("failed compile leaked sources or output: %v", files)
			}
			assertArtifactContents(t, out, []byte("last known good"))
			assertOnlyOutput(t, filepath.Dir(out), "policy.wasm")
		})
	}
}

func TestBuildAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Build(&Policy{}, BuildOptions{Context: ctx}); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
}
