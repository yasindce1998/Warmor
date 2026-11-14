// Package worker is imported by cmd/warmor-policy-host only, never by the
// supervisor. All WASM decoding, compilation, initialization and guest calls
// take place in this separately built executable.
package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/yasindce1998/warmor/internal/policyhost/protocol"
	"github.com/yasindce1998/warmor/internal/policymeta"
	"github.com/yasindce1998/warmor/internal/wasm"
)

// Run has no flags, path inputs, inherited environment dependency, cache or
// network listener. No guest diagnostics leave the worker on failure.
func Run(in io.Reader, out io.Writer) error {
	var c protocol.Control
	if err := protocol.Receive(in, &c, protocol.MaxControl); err != nil {
		return protocol.ErrProtocol
	}
	if c.Version != protocol.Version || c.Kind != "configure" || c.Sequence != 0 || c.Digest != "" {
		return protocol.ErrProtocol
	}
	if err := c.Limits.Validate(); err != nil {
		return err
	}
	if err := applyLimits(c.Limits); err != nil {
		return err
	}
	c.Kind = "limited"
	if err := protocol.Send(out, c, protocol.MaxControl); err != nil {
		return err
	}
	data, err := protocol.Read(in, protocol.MaxModule)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	c.Kind = "loading"
	c.Digest = hex.EncodeToString(digest[:])
	if err := protocol.Send(out, c, protocol.MaxControl); err != nil {
		return err
	}
	ctx := context.Background()
	if err := testLoadPhase(in, out, c); err != nil {
		return err
	}
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{PoolSize: 1, MemoryLimitPages: c.Limits.MemoryPages, InitializationTimeout: time.Minute})
	if err != nil {
		return errors.New("runtime unavailable")
	}
	defer rt.Close(ctx)
	if err := rt.LoadPolicyBytes(ctx, data); err != nil {
		return errors.New("policy load failed")
	}
	pool, err := wasm.NewPool(ctx, rt, 1)
	if err != nil {
		return errors.New("policy initialization failed")
	}
	defer pool.Close(ctx)
	eval := wasm.NewPolicyEvaluator(pool, "")
	// Parent deadlines are authoritative and include upload, compilation,
	// callbacks, reasons, frees and IPC. These longer guest deadlines are
	// defense in depth, not a replacement goroutine/retry mechanism.
	eval.SetTimeout(time.Minute)
	c.Kind = "ready"
	c.Digest = hex.EncodeToString(digest[:])
	metadata := pool.Metadata()
	if err := metadata.Validate(c.Digest); err != nil {
		return policymeta.ErrMetadata
	}
	if err := protocol.Send(out, protocol.Ready{Control: c, Metadata: metadata}, protocol.MaxMetadata); err != nil {
		return err
	}
	for sequence := uint64(1); ; sequence++ {
		var e protocol.Event
		if err := protocol.Receive(in, &e, protocol.MaxEvent); err != nil {
			return err
		}
		if e.Version != protocol.Version || e.Sequence != sequence || sequence > c.Limits.MaxRequests {
			return protocol.ErrProtocol
		}
		event := e.API()
		if _, err := protocol.Snapshot(event); err != nil {
			return protocol.ErrProtocol
		}
		r, err := eval.Evaluate(ctx, event)
		if err != nil {
			return errors.New("policy evaluation failed")
		}
		if len(r.Reason) > protocol.MaxReason {
			return protocol.ErrProtocol
		}
		if err := protocol.Send(out, protocol.Result{Version: protocol.Version, Sequence: sequence, Action: r.Action, Audit: r.Audit, Reason: r.Reason}, protocol.MaxResult); err != nil {
			return err
		}
	}
}
