//go:build !linux || !policyhost_phaseproof

package worker

import (
	"io"

	"github.com/yasindce1998/warmor/internal/policyhost/protocol"
)

func testLoadPhase(io.Reader, io.Writer, protocol.Control) error { return nil }
