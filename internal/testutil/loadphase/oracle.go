// Package loadphase is the shared test oracle for LKG progress during a held
// candidate load. It is imported by tests only, never daemon/worker code.
package loadphase

import (
	"context"
	"net"

	"github.com/yasindce1998/warmor/internal/policyhost/protocol"
)

// Check requires completed attributed work followed by a fresh phase receipt.
// An eventual ALLOW after rejection cannot pass even if both notifications were
// already queued when Check ran. Timeouts bound failures; elapsed time is never
// used as evidence that the candidate was still loading.
func Check(ctx context.Context, completed <-chan error, confirm func(context.Context) error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-completed:
		if err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return confirm(ctx)
}

// Confirm asks the supervisor for a fresh, digest/PID/limits-bound receipt.
// EOF/timeout is failure, not evidence of a candidate still held in load.
func Confirm(ctx context.Context, conn net.Conn, held protocol.Control) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
	}
	request := held
	request.Kind = "test-load-confirm"
	if err := protocol.Send(conn, request, protocol.MaxControl); err != nil {
		return err
	}
	var reply protocol.Control
	if err := protocol.Receive(conn, &reply, protocol.MaxControl); err != nil {
		return err
	}
	if reply != held {
		return protocol.ErrProtocol
	}
	return ctx.Err()
}
