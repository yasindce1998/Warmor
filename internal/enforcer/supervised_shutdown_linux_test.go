//go:build linux

package enforcer

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Real policy hosts, fake idle readers and kernel maps: no host hooks, kernel
// attachment or real process action. StopReaders and map teardown are distinct.
type supervisedShutdownPlatform struct {
	generationTestPlatform
	readerEntered chan struct{}
	readersClosed chan struct{}
	joined        chan struct{}
	once          sync.Once
	stops         atomic.Int32
	mapsClosed    atomic.Bool
	closeCheck    func()
}

func newSupervisedShutdownPlatform(k *generationKernel) *supervisedShutdownPlatform {
	return &supervisedShutdownPlatform{generationTestPlatform: generationTestPlatform{k: k},
		readerEntered: make(chan struct{}), readersClosed: make(chan struct{}), joined: make(chan struct{})}
}

func (p *supervisedShutdownPlatform) Start(context.Context, chan<- *api.Event) error {
	go func() {
		close(p.readerEntered)
		<-p.readersClosed // deliberately ignores ctx, like an idle ring read
		close(p.joined)
	}()
	return nil
}
func (p *supervisedShutdownPlatform) Stop() error {
	p.once.Do(func() { p.stops.Add(1); close(p.readersClosed) })
	<-p.joined
	return nil
}
func (p *supervisedShutdownPlatform) Close() error {
	if p.closeCheck != nil {
		p.closeCheck()
	}
	p.mapsClosed.Store(true)
	return nil
}

func startSupervisedShutdownLoop(t *testing.T, e *Enforcer, k *generationKernel) *supervisedShutdownPlatform {
	t.Helper()
	p := newSupervisedShutdownPlatform(k)
	e.platform = p
	e.eventChan = make(chan *api.Event, 8)
	if err := p.Start(e.ctx, e.eventChan); err != nil {
		t.Fatal(err)
	}
	<-p.readerEntered
	e.wg.Add(1)
	go e.eventLoop()
	return p
}

func shutdownWait(t *testing.T, done <-chan struct{}, phase string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown blocked at " + phase)
	}
}

func TestSupervisedStopJoinsIdleReaderButRetainsHostAndMapsUntilClose(t *testing.T) {
	for _, atomicMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "generations"}[atomicMode], func(t *testing.T) {
			e, k, _ := supervisedEnforcer(t, wasmtest.ConstPolicy(0, nil), supervisedConfig(t), atomicMode)
			h := supervisedHost(t, e.evaluator)
			p := startSupervisedShutdownLoop(t, e, k)
			p.closeCheck = func() {
				if h.Alive() {
					t.Error("maps/hooks detached before owned host was reaped")
				}
			}
			done := make(chan struct{})
			go func() { e.Stop(); close(done) }()
			shutdownWait(t, done, "idle Stop")
			if p.mapsClosed.Load() || !h.Alive() || p.stops.Load() != 1 {
				t.Fatal("Stop tore down host/maps or failed reader interruption")
			}
			if r, err := h.Evaluate(context.Background(), &api.Event{}); err != nil || r.Action != api.ActionAllow {
				t.Fatal("idle Stop closed evaluator before resource Close", err)
			}
			if err := e.Close(); err != nil {
				t.Fatal(err)
			}
			if h.Alive() || !p.mapsClosed.Load() || p.stops.Load() != 1 {
				t.Fatal("Close did not reap host before detaching maps")
			}
		})
	}
}

func TestSupervisedCloseCancelsGenerationDrainBeforeActivationLock(t *testing.T) {
	e, k, key := supervisedEnforcer(t, wasmtest.ConstPolicy(0, nil), supervisedConfig(t), true)
	p := startSupervisedShutdownLoop(t, e, k)
	old := supervisedHost(t, e.evaluator)
	draining := make(chan struct{})
	k.drain = func(ctx context.Context) error {
		close(draining)
		<-ctx.Done()
		return ctx.Err()
	}
	activated := make(chan error, 1)
	path := signedCandidate(t, key, wasmtest.ConstPolicy(1, nil))
	go func() { activated <- e.ActivatePolicy(path, nil) }()
	shutdownWait(t, draining, "activation drain entry")
	e.evaluatorMu.RLock()
	current := supervisedHost(t, e.evaluator)
	e.evaluatorMu.RUnlock()
	p.closeCheck = func() {
		if old.Alive() || current.Alive() {
			t.Error("map teardown preceded retained-host reaping")
		}
	}
	done := make(chan struct{})
	go func() { _ = e.Close(); close(done) }()
	shutdownWait(t, done, "Close cancellation while activation owns lock")
	if err := <-activated; !errors.Is(err, ErrActivationPending) || !errors.Is(err, context.Canceled) {
		t.Fatal("shutdown drain falsely acknowledged activation", err)
	}
	if len(k.acked) != 1 || old.Alive() || current.Alive() || !p.mapsClosed.Load() {
		t.Fatal("shutdown acknowledged old generation or leaked retained hosts/maps")
	}
}

func TestSupervisedConcurrentStopCloseWaitsActiveOutcomeLease(t *testing.T) {
	e, k, key := supervisedEnforcer(t, wasmtest.ConstPolicy(1, nil), supervisedConfig(t), true)
	p := startSupervisedShutdownLoop(t, e, k)
	old := supervisedHost(t, e.evaluator)
	e.actionHandler.auditMode = false
	entered, release, handled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	e.actionHandler.terminate = func(*api.Event) (bool, error) {
		close(entered)
		<-release
		close(handled)
		return false, errors.New("test identity refusal; no process signaled")
	}
	event := &api.Event{PID: 123, UID: 1000, Filename: "/owned-fixture"} // action uses only the fake terminate above
	if !e.captureGeneration(event) {
		t.Fatal("old lease capture refused")
	}
	e.eventChan <- event
	shutdownWait(t, entered, "active outcome")
	queued := &api.Event{UID: 1000, Filename: "/queued-lease"} // PID zero cannot invoke the fake action callback
	if !e.captureGeneration(queued) {
		t.Fatal("queued old lease capture refused")
	}
	e.eventChan <- queued
	draining := make(chan struct{})
	k.drain = func(context.Context) error { close(draining); return nil }
	activated := make(chan error, 1)
	path := signedCandidate(t, key, wasmtest.ConstPolicy(0, nil))
	go func() { activated <- e.ActivatePolicy(path, nil) }()
	shutdownWait(t, draining, "old lease drain")
	e.evaluatorMu.RLock()
	current := supervisedHost(t, e.evaluator)
	e.evaluatorMu.RUnlock()
	p.closeCheck = func() {
		if old.Alive() || current.Alive() {
			t.Error("maps closed before both retained hosts were reaped")
		}
	}
	stopDone, closeDone := make(chan struct{}), make(chan struct{})
	go func() { e.Stop(); close(stopDone) }()
	go func() { _ = e.Close(); close(closeDone) }()
	shutdownWait(t, p.readersClosed, "reader interrupt")
	if err := <-activated; !errors.Is(err, ErrActivationPending) {
		t.Fatal("canceled old-lease drain was acknowledged", err)
	}
	select {
	case <-closeDone:
		t.Fatal("Close retired evaluator while old outcome lease was active")
	default:
	}
	if !old.Alive() || !current.Alive() || p.mapsClosed.Load() || len(k.acked) != 1 {
		t.Fatal("pending action lost lifetime ownership at shutdown")
	}
	if _, err := old.Evaluate(context.Background(), &api.Event{}); err != nil {
		t.Fatal("old evaluator closed before outcome completed", err)
	}
	unblock()
	shutdownWait(t, handled, "outcome release")
	shutdownWait(t, stopDone, "concurrent Stop join")
	shutdownWait(t, closeDone, "concurrent Close/reap")
	if old.Alive() || current.Alive() || !p.mapsClosed.Load() || p.stops.Load() != 1 {
		t.Fatal("shutdown leaked child or detached before orderly close")
	}
	e.generations.mu.Lock()
	defer e.generations.mu.Unlock()
	for _, state := range e.generations.states {
		if state.refs != 0 {
			t.Fatal("shutdown leaked an evaluation lease")
		}
	}
}

func TestSupervisedCloseCancelsInFlightGuestAndReapsBeforeMaps(t *testing.T) {
	c := supervisedConfig(t)
	c.EvaluationTimeout = 5 * time.Second
	e, k, _ := supervisedEnforcer(t, wasmtest.LoopOnUIDPolicy(), c, true)
	p := startSupervisedShutdownLoop(t, e, k)
	h := supervisedHost(t, e.evaluator)
	// Wrap only to synchronize the real IPC call; no mock decision or worker.
	started := make(chan struct{})
	wrapper := &shutdownObservedEvaluator{Evaluator: e.evaluator, started: started, returned: make(chan struct{})}
	e.evaluator = wrapper
	e.backend.evaluator = wrapper
	e.generations.states[1].evaluator = wrapper
	p.closeCheck = func() {
		if h.Alive() {
			t.Error("maps detached before canceled guest host was reaped")
		}
	}
	e.eventChan <- &api.Event{UID: 0, Filename: "/guest-loop"}
	shutdownWait(t, started, "guest request entry")
	// Give the actual endless WASM request a chance to block on IPC. It must
	// not produce a decision before shutdown cancels the authoritative context.
	select {
	case <-wrapper.returned:
		t.Fatal("looping guest returned before cancellation")
	case <-time.After(20 * time.Millisecond):
	}
	done := make(chan struct{})
	go func() { _ = e.Close(); close(done) }()
	shutdownWait(t, done, "in-flight guest cancellation")
	if h.Alive() || !p.mapsClosed.Load() || e.currentDecisionCache().Stats().Size != 0 {
		t.Fatal("canceled guest leaked host/maps or cached error")
	}
}

type shutdownObservedEvaluator struct {
	Evaluator
	started  chan struct{}
	returned chan struct{}
	enter    sync.Once
}

func (e *shutdownObservedEvaluator) Evaluate(ctx context.Context, event *api.Event) (*api.ActionResult, error) {
	e.enter.Do(func() { close(e.started) })
	defer close(e.returned)
	return e.Evaluator.Evaluate(ctx, event)
}
