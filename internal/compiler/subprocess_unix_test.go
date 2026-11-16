//go:build linux || darwin

package compiler

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestBuildTimeoutKillsOwnedToolTree(t *testing.T) {
	for _, mode := range []string{"rustup-tree", "cargo-tree"} {
		t.Run(mode, func(t *testing.T) {
			fakeToolchain(t, mode)
			pidsDir := t.TempDir()
			t.Setenv("WARMOR_COMPILER_TEST_PIDS", pidsDir)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan struct{})
			var buildErr error
			go func() {
				defer close(done)
				result, err := Build(safetyPolicy(), BuildOptions{
					Context: ctx, OutputPath: filepath.Join(pidsDir, "policy.wasm"),
				})
				Cleanup(result)
				buildErr = err
			}()
			// Even on failure, cancel and join our command before test fixtures go.
			defer func() { cancel(); <-done }()
			pids := awaitToolPIDs(t, pidsDir, 3)
			if ctx.Err() != nil {
				t.Fatal("deadline elapsed before descendants were started")
			}
			for _, pid := range pids {
				if !toolTestProcessRunning(pid) {
					t.Fatalf("owned descendant %d was not alive before timeout", pid)
				}
			}
			<-done
			if !errors.Is(buildErr, context.DeadlineExceeded) {
				t.Fatalf("wanted deadline exceeded, got %v", buildErr)
			}
			assertToolPIDsStopped(t, pids)
			if _, err := os.Stat(filepath.Join(pidsDir, "policy.wasm")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("timed out build published artifact: %v", err)
			}
		})
	}
}

func TestToolParentExitStillCleansOwnedChildren(t *testing.T) {
	fakeToolchain(t, "cargo-parent-exit")
	pidsDir := t.TempDir()
	t.Setenv("WARMOR_COMPILER_TEST_PIDS", pidsDir)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := toolTestCommand(t, "cargo-parent-exit")
	if _, err := runTool(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	pids := awaitToolPIDs(t, pidsDir, 3)
	assertToolPIDsStopped(t, pids)
}

func TestToolOutputOverflowKillsOwnedChildren(t *testing.T) {
	pidsDir := t.TempDir()
	t.Setenv("WARMOR_COMPILER_TEST_PIDS", pidsDir)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := toolTestCommand(t, "cargo-tree-flood")
	if _, err := runTool(ctx, cmd); !errors.Is(err, errToolOutputLimit) {
		t.Fatalf("expected output overflow, got %v", err)
	}
	assertToolPIDsStopped(t, awaitToolPIDs(t, pidsDir, 3))
}

func TestToolCleanupDoesNotKillOtherOwnedProcess(t *testing.T) {
	// This sentinel is ours too, but deliberately outside the tool's group.
	sentinel := toolTestCommand(t, "cargo-slow")
	sentinel.Env = append(sentinel.Env, "CARGO_TARGET_DIR="+t.TempDir())
	if err := sentinel.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sentinel.Process.Kill(); _ = sentinel.Wait() }()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	cmd := toolTestCommand(t, "cargo-slow")
	cmd.Env = append(cmd.Env, "CARGO_TARGET_DIR="+t.TempDir())
	if _, err := runTool(ctx, cmd); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
	if !toolTestProcessRunning(sentinel.Process.Pid) {
		t.Fatal("cleanup killed an unrelated owned sentinel outside the tool group")
	}
}

func TestToolExitProbePreservesWaitStatus(t *testing.T) {
	cmd := toolTestCommand(t, "nonzero")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = killOwnedToolGroup(cmd.Process.Pid); _ = cmd.Wait() }()
	awaitToolExit(t, cmd.Process.Pid)
	// Probing twice must leave the child waitable and preserve its exit code.
	if exited, err := toolChildExited(cmd.Process.Pid); err != nil || !exited {
		t.Fatalf("second non-reaping exit probe: exited=%v err=%v", exited, err)
	}
	if err := killOwnedToolGroup(cmd.Process.Pid); err != nil {
		t.Fatalf("zombie-only group cleanup: %v", err)
	}
	if err := cmd.Wait(); err == nil || cmd.ProcessState.ExitCode() != 7 {
		t.Fatalf("lost exit status: %v, %v", cmd.ProcessState, err)
	}
	if _, err := toolChildExited(cmd.Process.Pid); !errors.Is(err, syscall.ECHILD) {
		t.Fatalf("reaped leader must not count as owned: %v", err)
	}
	if err := killOwnedToolGroup(cmd.Process.Pid); !errors.Is(err, syscall.ECHILD) {
		t.Fatalf("cleanup must reject externally reaped leader: %v", err)
	}
}

func awaitToolExit(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		exited, err := toolChildExited(pid)
		if err != nil {
			t.Fatal(err)
		}
		if exited {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("owned tool did not exit")
}

func awaitToolPIDs(t *testing.T, dir string, n int) []int {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		files, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		var pids []int
		for _, f := range files {
			pid, err := strconv.Atoi(f.Name())
			if err == nil && pid > 0 {
				pids = append(pids, pid)
			}
		}
		if len(pids) == n {
			return pids
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("owned subprocess tree did not report all PIDs before timeout")
	return nil
}

func assertToolPIDsStopped(t *testing.T, pids []int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		var running []int
		for _, pid := range pids {
			if toolTestProcessRunning(pid) {
				running = append(running, pid)
			}
		}
		if len(running) == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("owned subprocesses still running after cleanup: %v", pids)
}

func toolTestProcessRunning(pid int) bool {
	if runtime.GOOS == "linux" {
		// Container PID 1 may not immediately reap orphaned grandchildren. A
		// zombie cannot execute or retain output pipes and is not a survivor.
		data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
		if errors.Is(err, os.ErrNotExist) {
			return false
		}
		if err == nil {
			end := strings.LastIndex(string(data), ") ")
			if end >= 0 && len(data) > end+2 && data[end+2] == 'Z' {
				return false
			}
		}
	}
	return syscall.Kill(pid, 0) == nil
}
