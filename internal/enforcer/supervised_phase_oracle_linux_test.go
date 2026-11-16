//go:build linux

package enforcer

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/policyhost/protocol"
	"github.com/yasindce1998/warmor/internal/testutil/loadphase"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestSupervisedConcurrencyOracleRejectsEventMuHeldUntilLoadRejection(t *testing.T) {
	for _, atomic := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "atomic"}[atomic], func(t *testing.T) {
			rejectEventMuDelayedAllow(t, atomic)
		})
	}
}

func rejectEventMuDelayedAllow(t *testing.T, atomic bool) {
	t.Helper()
	c := supervisedConfig(t)
	c.LoadTimeout = 100 * time.Millisecond
	e, _, key := supervisedEnforcer(t, wasmtest.ConstPolicy(0, nil), c, atomic)
	candidate := signedCandidate(t, key, wasmtest.InitializationLoopPolicy())
	client, phaseOwner := net.Pipe()
	defer client.Close()
	defer phaseOwner.Close()

	// Reproduce the old oracle's false-positive with the REAL eventMu, real
	// signed candidate rejection and real LKG evaluation. Only the test phase
	// receipt transport is modeled here; no kernel monitor or process action.
	e.eventMu.Lock()
	queued := make(chan struct{})
	completed := make(chan error, 1)
	go func() {
		close(queued)
		e.handleEvent(&api.Event{UID: 1000, Filename: "/phase-proof-uncached"})
		stats := e.GetStats()
		if stats.Allowed != 1 || stats.CacheHits != 0 {
			completed <- errors.New("negative probe failed to produce eventual uncached ALLOW")
			return
		}
		completed <- nil
	}()
	<-queued
	backend, rejectErr := e.candidateBackend(candidate, nil)
	if backend != nil {
		backend.close()
	}
	_ = phaseOwner.Close() // rejected load can no longer confirm ownership
	e.eventMu.Unlock()
	if !errors.Is(rejectErr, context.DeadlineExceeded) {
		t.Fatalf("real initialization load did not reject: %v", rejectErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	held := protocol.Control{Version: protocol.Version, Kind: "test-load-held", Digest: "rejected-candidate", Sequence: 42}
	confirmed := false
	err := loadphase.Check(ctx, completed, func(ctx context.Context) error {
		confirmed = true
		return loadphase.Confirm(ctx, client, held)
	})
	if err == nil || !confirmed || ctx.Err() != nil {
		t.Fatalf("must reject eventual ALLOW by phase ownership, not timeout/failed evaluation: err=%v confirmed=%t ctx=%v", err, confirmed, ctx.Err())
	}
}
