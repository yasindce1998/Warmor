//go:build !policyhost_phaseproof

package policyhost

import (
	"context"
	"testing"
)

func TestProductionBuildIgnoresPhaseProofEnvironment(t *testing.T) {
	t.Setenv("WARMOR_TEST_HOST_PHASE_SOCKET", "/must/not/connect")
	t.Setenv("WARMOR_TEST_HOST_PHASE_DIGESTS", "not-a-production-control")
	// nil Host is deliberate: normal builds do not inspect a host, perform
	// extra IPC, read this environment or alter deadlines at this seam.
	if err := testLoadPhase(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}
