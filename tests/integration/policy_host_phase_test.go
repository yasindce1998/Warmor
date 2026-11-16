//go:build linux && integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/policyhost/protocol"
	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/internal/testutil/loadphase"
)

type hostLoadPhase struct {
	conn net.Conn
	held protocol.Control
}

func hostFixtureDigest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func (f *outcomeFixture) requireAllowDuringLoad(t *testing.T, d *daemonProcess, p *hostLoadPhase, candidate string) {
	t.Helper()
	marker := candidate + "-LKG-allow"
	cmd := f.helper(t, "allowed", marker, "", 0)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()
	completed := make(chan error, 1)
	joined := make(chan struct{})
	processDone := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		select {
		case <-processDone:
		default:
			_ = cmd.Process.Kill()
		}
		<-joined
	})
	go func() {
		defer close(joined)
		err := cmd.Wait()
		close(processDone)
		if err != nil {
			completed <- err
			return
		}
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			data, err := os.ReadFile(d.events)
			if err == nil {
				for _, line := range bytes.Split(data, []byte{'\n'}) {
					var e streaming.SecurityEvent
					if json.Unmarshal(line, &e) == nil && e.PID == uint32(cmd.Process.Pid) && e.UID == 65534 &&
						e.EventType == "file" && e.Filename == filepath.Join(f.work, "markers", marker) &&
						e.Decision == "allow" && !e.Cached {
						completed <- nil
						return
					}
				}
			}
			select {
			case <-ctx.Done():
				completed <- ctx.Err()
				return
			case <-ticker.C:
			}
		}
	}()
	if err := loadphase.Check(ctx, completed, p.confirm); err != nil {
		// Kill only this fixture child for cleanup, never count it as outcome.
		cancel()
		t.Fatalf("uncached LKG ALLOW did not complete while candidate was still held in load: %v", err)
	}
	f.checkMarker(t, marker, true)
	p.retainReceipt(t, f, candidate)
}

func listenHostLoadPhase(t *testing.T, f *outcomeFixture) (*net.UnixListener, []string) {
	t.Helper()
	// Guest-local physical owned path, not a socket on the exported checkout.
	socket := "/run/warmor-outcomes/load-phase.sock"
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var digests []string
	for _, name := range []string{"compile-heavy", "init-loop"} {
		digests = append(digests, hostFixtureDigest(t, filepath.Join(f.dir, name+".wasm")))
	}
	return listener, []string{"WARMOR_TEST_HOST_PHASE_SOCKET=" + socket,
		"WARMOR_TEST_HOST_PHASE_DIGESTS=" + digests[0] + "," + digests[1]}
}

func acceptHostLoadPhase(t *testing.T, listener *net.UnixListener, digest string, old int) *hostLoadPhase {
	t.Helper()
	if err := listener.SetDeadline(time.Now().Add(outcomeTimeout)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(outcomeTimeout)); err != nil {
		t.Fatal(err)
	}
	p := &hostLoadPhase{conn: conn}
	if err := protocol.Receive(conn, &p.held, protocol.MaxControl); err != nil {
		t.Fatal(err)
	}
	if p.held.Version != protocol.Version || p.held.Kind != "test-load-held" || p.held.Digest != digest ||
		p.held.Sequence == 0 || p.held.Sequence == uint64(old) || p.held.Limits.Validate() != nil {
		t.Fatalf("candidate phase receipt not bound to expected child: %+v", p.held)
	}
	return p
}

func (p *hostLoadPhase) confirm(ctx context.Context) error {
	return loadphase.Confirm(ctx, p.conn, p.held)
}

func (p *hostLoadPhase) release(t *testing.T) {
	t.Helper()
	request := p.held
	request.Kind = "test-load-release"
	if err := protocol.Send(p.conn, request, protocol.MaxControl); err != nil {
		t.Fatal(err)
	}
}

func (p *hostLoadPhase) retainReceipt(t *testing.T, f *outcomeFixture, candidate string) {
	t.Helper()
	mustWrite(t, filepath.Join(f.dir, candidate+"-phase-proof.txt"), []byte(fmt.Sprintf(
		"candidate_digest=%s\ncandidate_pid=%d\nphase=load-held-before-compile\nhelper_completed=true\nattributed_uncached_allow=true\nconfirmed_after_completion=true\n", p.held.Digest, p.held.Sequence)), 0644)
}
