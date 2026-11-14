//go:build linux && policyhost_phaseproof

package policyhost

import (
	"context"
	"net"
	"os"
	"strings"

	"github.com/yasindce1998/warmor/internal/policyhost/protocol"
)

// This extra handshake exists ONLY in explicitly tagged test daemon/worker
// pairs. The worker acknowledges loading then parks before compiling any guest
// bytes until this owned IPC release. The original initialization context/watch
// remains authoritative throughout the barrier; no production deadline changes.
func testLoadPhase(ctx context.Context, h *Host) error {
	var held protocol.Control
	if err := protocol.Receive(h.out, &held, protocol.MaxControl); err != nil {
		return err
	}
	want := protocol.Control{Version: protocol.Version, Kind: "test-load-held", Digest: h.digest, Limits: h.config.Limits}
	if held != want {
		return protocol.ErrProtocol
	}
	if socket := os.Getenv("WARMOR_TEST_HOST_PHASE_SOCKET"); socket != "" {
		for _, digest := range strings.Split(os.Getenv("WARMOR_TEST_HOST_PHASE_DIGESTS"), ",") {
			if digest == h.digest {
				if err := h.testHoldLoad(ctx, socket, held); err != nil {
					return err
				}
				break
			}
		}
	}
	held.Kind = "test-load-release"
	return protocol.Send(h.in, held, protocol.MaxControl)
}

func (h *Host) testHoldLoad(ctx context.Context, socket string, held protocol.Control) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, ok := ctx.Deadline(); !ok {
		return protocol.ErrProtocol
	}
	// The authoritative context closes this connection. A second socket timer
	// at the same instant could race ctx.Err and misclassify deadline failure.
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(finished); _ = conn.Close() })
	defer func() {
		if !stop() {
			<-finished
		}
	}()
	// This PID is parent-owned, not supplied by an untrusted guest. Bind the
	// receipt to the actual child's digest and exact configured limits too.
	held.Sequence = uint64(h.cmd.Process.Pid)
	if err := protocol.Send(conn, held, protocol.MaxControl); err != nil {
		return err
	}
	for {
		var request protocol.Control
		if err := protocol.Receive(conn, &request, protocol.MaxControl); err != nil {
			return err
		}
		switch request.Kind {
		case "test-load-confirm", "test-load-release":
		default:
			return protocol.ErrProtocol
		}
		kind := request.Kind
		request.Kind = held.Kind
		if request != held || ctx.Err() != nil || !h.Alive() {
			return protocol.ErrProtocol
		}
		if kind == "test-load-release" {
			return nil
		}
		// The fixture requests this AFTER its attributed uncached ALLOW and
		// helper completion. Rejection/EOF before this reply is never proof.
		if err := protocol.Send(conn, held, protocol.MaxControl); err != nil {
			return err
		}
	}
}
