//go:build linux && policyhost_phaseproof

package policyhost

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/policyhost/protocol"
	"github.com/yasindce1998/warmor/internal/testutil/loadphase"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestPhaseProofRealWorkerReleaseCancellationAndDeadline(t *testing.T) {
	base := ""
	if st, err := os.Stat("/tmp/opencode"); err == nil && st.IsDir() {
		base = "/tmp/opencode"
	}
	dir, err := os.MkdirTemp(base, "host-phase-proof-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "warmor-policy-host")
	t.Cleanup(func() { _ = os.Remove(path); _ = os.Remove(dir) })
	build := exec.Command("go", "build", "-p", "2", "-tags", "policyhost_phaseproof", "-o", path, "../../cmd/warmor-policy-host")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build tagged real host: %v %s", err, out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"release", "cancel", "total-deadline", "invalid-release"} {
		t.Run(mode, func(t *testing.T) {
			candidate := staged(t, wasmtest.InitializationLoopPolicy())
			socket := filepath.Join(dir, "phase.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			t.Setenv("WARMOR_TEST_HOST_PHASE_SOCKET", socket)
			t.Setenv("WARMOR_TEST_HOST_PHASE_DIGESTS", candidate.Digest())
			c := Config{Executable: path, ExecutableSHA256: fmt.Sprintf("%x", sha256.Sum256(data)),
				Limits:                protocol.Limits{AddressSpaceBytes: 4 << 30, CPUSeconds: 10, MemoryPages: 256, MaxRequests: 100},
				InitializationTimeout: 3 * time.Second, LoadTimeout: 100 * time.Millisecond,
				EvaluationTimeout: 500 * time.Millisecond, MaxHosts: 2}
			s := supervisor(t, c)
			good := startHost(t, s, wasmtest.ConstPolicy(0, nil))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				h, err := s.Start(ctx, candidate)
				if h != nil {
					_ = h.Close()
				}
				done <- err
			}()
			if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			conn, err := listener.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var held protocol.Control
			if err := protocol.Receive(conn, &held, protocol.MaxControl); err != nil {
				t.Fatal(err)
			}
			if held.Digest != candidate.Digest() || held.Sequence == 0 || held.Kind != "test-load-held" {
				t.Fatalf("wrong load receipt %+v", held)
			}
			result, err := good.Evaluate(context.Background(), &api.Event{})
			if err != nil || result.Action != api.ActionAllow {
				t.Fatalf("active host failed during held load: %+v %v", result, err)
			}
			completed := make(chan error, 1)
			completed <- nil
			if err := loadphase.Check(ctx, completed, func(ctx context.Context) error { return loadphase.Confirm(ctx, conn, held) }); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "release":
				release := held
				release.Kind = "test-load-release"
				if err := protocol.Send(conn, release, protocol.MaxControl); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			case "invalid-release":
				wrong := held
				wrong.Kind = "test-load-release"
				wrong.Digest = "unrelated-module"
				if err := protocol.Send(conn, wrong, protocol.MaxControl); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				want := context.DeadlineExceeded
				if mode == "cancel" {
					want = context.Canceled
				}
				if mode == "invalid-release" {
					want = ErrHost
				}
				var failure *Failure
				if !errors.Is(err, want) || !errors.As(err, &failure) || failure.Phase != "load" {
					t.Fatalf("load barrier bypassed authoritative context: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("held load ignored authoritative context")
			}
			if len(s.slots) != 1 {
				t.Fatal("held candidate did not release capacity after reaping")
			}
			var status syscall.WaitStatus
			if _, err := syscall.Wait4(int(held.Sequence), &status, syscall.WNOHANG, nil); !errors.Is(err, syscall.ECHILD) {
				t.Fatalf("candidate not reaped: %v", err)
			}
			completed <- nil
			if err := loadphase.Check(context.Background(), completed, func(ctx context.Context) error { return loadphase.Confirm(ctx, conn, held) }); err == nil {
				t.Fatal("post-rejection allow passed concurrency oracle")
			}
		})
	}
}
