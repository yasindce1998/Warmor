// Package policyhost provides an opt-in supervised backend. It never imports
// the WASM runtime. The enforcer's experimental adapter owns its lifecycle.
package policyhost

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/policyhost/protocol"
	"github.com/yasindce1998/warmor/internal/policymeta"
	"github.com/yasindce1998/warmor/pkg/api"
)

var (
	ErrUnsupported = errors.New("supervised policy host requires Linux")
	ErrBusy        = errors.New("policy-host capacity exhausted")
	ErrHost        = errors.New("policy host failed; no decision available")
	ErrClosed      = errors.New("policy host closed")
)

// Limits describes OS and guest resource limits. See the platform limitations
// in docs/design/supervised-policy-host.md before selecting a memory budget.
type Limits = protocol.Limits

// Failure identifies a supervisor phase without exposing guest diagnostics.
// errors.Is continues to recognize context cancellation and deadlines.
type Failure struct {
	Phase string
	Cause error
}

func (e *Failure) Error() string { return "policy-host " + e.Phase + ": " + e.Cause.Error() }
func (e *Failure) Unwrap() error { return e.Cause }

// Config is administrator-owned, never policy-controlled. No PATH search,
// environment inheritance, caller-supplied flags, shared cache, or retry loop.
type Config struct {
	Executable string
	// ExecutableSHA256 pins the trusted build in addition to ownership/mode
	// checks. Required lowercase hex; calculate from the installed artifact.
	ExecutableSHA256      string
	Limits                Limits
	InitializationTimeout time.Duration
	// LoadTimeout is nested within InitializationTimeout after upload is
	// acknowledged, and bounds compilation, declarations and readiness.
	LoadTimeout       time.Duration
	EvaluationTimeout time.Duration
	MaxHosts          int
	// TrustedDeclarationDigests explicitly attests exhaustive, deterministic
	// declarations for these exact modules. A signature or trusted executable
	// alone does not establish this property. Empty disables optimizations.
	TrustedDeclarationDigests []string
}

type Supervisor struct {
	config Config
	slots  chan struct{}
}

func New(c Config) (*Supervisor, error) {
	if err := supported(); err != nil {
		return nil, err
	}
	if err := c.Limits.Validate(); err != nil {
		return nil, err
	}
	if c.InitializationTimeout <= 0 || c.InitializationTimeout > time.Minute || c.LoadTimeout <= 0 || c.LoadTimeout > c.InitializationTimeout || c.EvaluationTimeout <= 0 || c.EvaluationTimeout > 5*time.Second || c.MaxHosts < 1 || c.MaxHosts > 16 {
		return nil, errors.New("policy-host configuration out of range")
	}
	if len(c.TrustedDeclarationDigests) > 256 {
		return nil, errors.New("too many trusted declaration digests")
	}
	seen := map[string]bool{}
	for _, digest := range c.TrustedDeclarationDigests {
		if !policymeta.ValidDigest(digest) || seen[digest] {
			return nil, errors.New("invalid trusted declaration digest")
		}
		seen[digest] = true
	}
	c.TrustedDeclarationDigests = append([]string(nil), c.TrustedDeclarationDigests...)
	f, err := trustedExecutable(c.Executable, c.ExecutableSHA256)
	if err != nil {
		return nil, err
	}
	f.Close()
	return &Supervisor{config: c, slots: make(chan struct{}, c.MaxHosts)}, nil
}

// Host owns exactly one child and serializes evaluations. A failed request
// permanently retires it: callers must retain last-known-good state and choose
// their own bounded activation/replacement policy. Errors never contain guest
// diagnostics, events, signatures or child stderr.
type Host struct {
	cmd                 *exec.Cmd
	in, out             *os.File
	done                chan struct{}
	gate                chan struct{}
	stop                sync.Once
	sequence            uint64
	config              Config
	digest              string
	metadata            policymeta.Module
	declarationsTrusted bool
}

func (s *Supervisor) Start(ctx context.Context, p *StagedPolicy) (*Host, error) {
	if p == nil || len(p.data) == 0 {
		return nil, errors.New("missing staged policy")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case s.slots <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	owned := false
	defer func() {
		if !owned {
			<-s.slots
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, s.config.InitializationTimeout)
	defer cancel()
	f, err := trustedExecutable(s.config.Executable, s.config.ExecutableSHA256)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	childIn, parentIn, err := os.Pipe()
	if err != nil {
		return nil, ErrHost
	}
	defer childIn.Close()
	parentOut, childOut, err := os.Pipe()
	if err != nil {
		parentIn.Close()
		return nil, ErrHost
	}
	defer childOut.Close()
	cmd := command(f)
	// A real file avoids os/exec's background stderr-copy goroutine and
	// prevents guest/compiler output from reaching daemon logs.
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		parentIn.Close()
		parentOut.Close()
		return nil, ErrHost
	}
	defer devnull.Close()
	cmd.Stdin = childIn
	cmd.Stdout = childOut
	cmd.Stderr = devnull
	h := &Host{cmd: cmd, in: parentIn, out: parentOut, done: make(chan struct{}), gate: make(chan struct{}, 1), config: s.config, digest: p.digest}
	for _, digest := range s.config.TrustedDeclarationDigests {
		if digest == p.digest {
			h.declarationsTrusted = true
		}
	}
	if err := ctx.Err(); err != nil {
		parentIn.Close()
		parentOut.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		parentIn.Close()
		parentOut.Close()
		return nil, ErrHost
	}
	childIn.Close()
	childOut.Close()
	owned = true
	go func() { _ = cmd.Wait(); h.terminate(); <-s.slots; close(h.done) }()
	stop := h.watch(ctx)
	phase := "configure"
	err = protocol.Send(h.in, protocol.Control{Version: protocol.Version, Kind: "configure", Limits: s.config.Limits}, protocol.MaxControl)
	var reply protocol.Control
	var ready protocol.Ready
	if err == nil {
		err = protocol.Receive(h.out, &reply, protocol.MaxControl)
	}
	if err == nil && (reply.Version != protocol.Version || reply.Kind != "limited" || reply.Limits != s.config.Limits || reply.Sequence != 0 || reply.Digest != "") {
		err = protocol.ErrProtocol
	}
	if err == nil {
		phase = "upload"
		err = protocol.Write(h.in, p.data, protocol.MaxModule)
	}
	if err == nil {
		reply = protocol.Control{}
		err = protocol.Receive(h.out, &reply, protocol.MaxControl)
	}
	if err == nil && (reply.Version != protocol.Version || reply.Kind != "loading" || reply.Digest != p.digest || reply.Sequence != 0 || reply.Limits != s.config.Limits) {
		err = protocol.ErrProtocol
	}
	if err == nil {
		phase = "load"
		stop()
		var loadCancel context.CancelFunc
		ctx, loadCancel = context.WithTimeout(ctx, s.config.LoadTimeout)
		defer loadCancel()
		stop = h.watch(ctx)
		err = protocol.Receive(h.out, &ready, protocol.MaxMetadata)
	}
	if err == nil {
		err = ready.Validate(p.digest, s.config.Limits)
		if err == nil {
			h.metadata = ready.Metadata.Clone()
		}
	}
	stop()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		h.Close()
		if ctx.Err() != nil {
			return nil, &Failure{Phase: phase, Cause: ctx.Err()}
		}
		return nil, &Failure{Phase: phase, Cause: ErrHost}
	}
	return h, nil
}

// watch has no abandoned I/O goroutine: cancellation kills our child and closes
// our private pipes; synchronous I/O then unwinds. stop joins a running callback.
func (h *Host) watch(ctx context.Context) func() {
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(finished); h.terminate() })
	return func() {
		if !stop() {
			<-finished
		}
	}
}
func (h *Host) terminate() { h.stop.Do(func() { kill(h.cmd); h.in.Close(); h.out.Close() }) }

func (h *Host) Close() error   { h.terminate(); <-h.done; return nil }
func (h *Host) Digest() string { return h.digest }

// Alive reports whether the owned child has been reaped. A terminal host must
// never authorize a cached decision in an enclosing evaluator. Like any health
// snapshot it is not a promise that a child cannot exit immediately afterward.
func (h *Host) Alive() bool {
	select {
	case <-h.done:
		return false
	default:
		return true
	}
}

func (h *Host) Evaluate(ctx context.Context, event *api.Event) (*api.ActionResult, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, h.config.EvaluationTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// No unbounded internal wait queue. Callers may distribute requests over a
	// bounded collection of hosts; saturation must be handled as an error.
	select {
	case h.gate <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	defer func() { <-h.gate }()
	select {
	case <-h.done:
		return nil, ErrClosed
	default:
	}
	snapshot, err := protocol.Snapshot(event)
	if err != nil {
		return nil, err
	}
	if snapshot.Timestamp.IsZero() {
		snapshot.Timestamp = start
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if h.sequence >= h.config.Limits.MaxRequests {
		h.Close()
		return nil, ErrClosed
	}
	h.sequence++
	snapshot.Sequence = h.sequence
	stop := h.watch(ctx)
	err = protocol.Send(h.in, snapshot, protocol.MaxEvent)
	var r protocol.Result
	if err == nil {
		err = protocol.Receive(h.out, &r, protocol.MaxResult)
	}
	stop()
	if ctx.Err() != nil {
		h.Close()
		return nil, &Failure{Phase: "evaluate", Cause: ctx.Err()}
	}
	if err != nil || r.Version != protocol.Version || r.Sequence != h.sequence || r.Failed || len(r.Reason) > protocol.MaxReason || r.Action < api.ActionAllow || r.Action > api.ActionLog || (r.Audit && r.Action != api.ActionDeny) {
		h.Close()
		return nil, &Failure{Phase: "evaluate", Cause: ErrHost}
	}
	if h.sequence == h.config.Limits.MaxRequests {
		h.Close()
	}
	return &api.ActionResult{Action: r.Action, Reason: r.Reason, Audit: r.Audit, Timestamp: start, Latency: time.Since(start)}, nil
}
