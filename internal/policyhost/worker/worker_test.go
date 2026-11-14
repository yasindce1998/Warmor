package worker

import (
	"bytes"
	"testing"

	"github.com/yasindce1998/warmor/internal/policyhost/protocol"
)

// These cases stop before applyLimits: OS limits must never affect the test
// runner. Successful worker paths are exercised through the real executable.
func TestInvalidConfigurationStopsBeforeOSLimits(t *testing.T) {
	for _, c := range []protocol.Control{
		{Version: 99, Kind: "configure"},
		{Version: protocol.Version, Kind: "unknown"},
		{Version: protocol.Version, Kind: "configure", Sequence: 1},
		{Version: protocol.Version, Kind: "configure", Digest: "unexpected"},
		{Version: protocol.Version, Kind: "configure"},
	} {
		var in, out bytes.Buffer
		if err := protocol.Send(&in, c, protocol.MaxControl); err != nil {
			t.Fatal(err)
		}
		if err := Run(&in, &out); err == nil || out.Len() != 0 {
			t.Fatal("invalid configuration acknowledged")
		}
	}
}
