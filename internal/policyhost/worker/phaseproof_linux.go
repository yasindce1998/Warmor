//go:build linux && policyhost_phaseproof

package worker

import (
	"io"

	"github.com/yasindce1998/warmor/internal/policyhost/protocol"
)

// Only a test-tagged worker speaks this extra private-pipe handshake. There is
// no worker environment, filesystem mount, sleep, fake decision or mock compiler.
// The supervisor still uploads signed bytes and runs the real compiler AFTER
// release; its initialization watch kills/reaps this worker if release stalls.
func testLoadPhase(in io.Reader, out io.Writer, loading protocol.Control) error {
	loading.Kind = "test-load-held"
	if err := protocol.Send(out, loading, protocol.MaxControl); err != nil {
		return err
	}
	var release protocol.Control
	if err := protocol.Receive(in, &release, protocol.MaxControl); err != nil {
		return err
	}
	loading.Kind = "test-load-release"
	if release != loading {
		return protocol.ErrProtocol
	}
	return nil
}
