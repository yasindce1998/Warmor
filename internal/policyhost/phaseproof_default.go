//go:build !linux || !policyhost_phaseproof

package policyhost

import "context"

// Production builds have no phase-control protocol, environment or socket.
func testLoadPhase(context.Context, *Host) error { return nil }
