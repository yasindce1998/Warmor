//go:build linux

package platform

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/yasindce1998/warmor/internal/ebpf"
	"github.com/yasindce1998/warmor/pkg/api"
)

type generationRead struct {
	event *ebpf.Event
	err   error
}
type generationStream struct {
	reads    chan generationRead
	flushes  atomic.Int32
	flushErr error
	stopOnce sync.Once
	stopped  chan struct{}
}

func (s *generationStream) ReadLSMEvent() (*ebpf.Event, error) {
	select {
	case r := <-s.reads:
		return r.event, r.err
	case <-s.stopped:
		return nil, ringbuf.ErrClosed
	}
}
func (s *generationStream) FlushLSMEvents() error { s.flushes.Add(1); return s.flushErr }
func (s *generationStream) StopReaders() error {
	s.stopOnce.Do(func() { close(s.stopped) })
	return nil
}

func generationPlatform(t *testing.T) (*LinuxPlatform, *generationStream, chan *api.Event) {
	t.Helper()
	p, err := NewLinuxPlatform(LinuxConfig{})
	if err != nil {
		t.Fatal(err)
	}
	lp, ok := p.(*LinuxPlatform)
	if !ok {
		t.Fatal("not Linux")
	}
	s := &generationStream{reads: make(chan generationRead, 32), stopped: make(chan struct{})}
	ch := make(chan *api.Event, 32)
	lp.lsmEvents, lp.eventChan = s, ch
	lp.wg.Add(1)
	go lp.monitorLSMEvents(context.Background())
	t.Cleanup(func() {
		if err := lp.Stop(); err != nil {
			t.Error(err)
		}
	})
	return lp, s, ch
}

func TestGenerationReaderPreservesEveryHookAndOrdersFence(t *testing.T) {
	p, stream, events := generationPlatform(t)
	var captures atomic.Int32
	p.SetEventCapture(func(e *api.Event) bool {
		captures.Add(1)
		e.GenerationContext = api.NewGenerationContext(e.PolicyGeneration, nil)
		return true
	})
	g := &linuxPolicyGenerations{p: p}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.Drain(ctx) }()
	for stream.flushes.Load() == 0 {
		select {
		case <-ctx.Done():
			t.Fatal("no flush")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	hooks := []string{"exec", "file", "connect", "connect_unix", "bind", "listen", "mount", "ptrace"}
	for _, hook := range hooks {
		stream.reads <- generationRead{event: &ebpf.Event{Kind: ebpf.EventKindProcess, Hook: hook, PolicyGeneration: 77}}
	}
	// Sentinel is wrapped in production; errors.Is must preserve it.
	stream.reads <- generationRead{err: fmt.Errorf("read lsm: %w", ringbuf.ErrFlushed)}
	for _, hook := range hooks {
		e := <-events
		if e.Hook != hook || e.PolicyGeneration != 77 || e.GenerationContext.ID != 77 {
			t.Fatalf("lost %s generation: %+v", hook, e)
		}
		e.GenerationContext.Complete()
	}
	fence := <-events
	if fence.DispatchBarrier == nil || captures.Load() != int32(len(hooks)) {
		t.Fatal("fence passed through event capture")
	}
	select {
	case <-done:
		t.Fatal("flush observation acknowledged before worker queue fence")
	default:
	}
	close(fence.DispatchBarrier)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestGenerationDrainTimeoutReusesOutstandingFlush(t *testing.T) {
	p, stream, events := generationPlatform(t)
	g := &linuxPolicyGenerations{p: p}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := g.Drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout guessed ring empty: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- g.Drain(context.Background()) }()
	stream.reads <- generationRead{err: ringbuf.ErrFlushed}
	fence := <-events
	close(fence.DispatchBarrier)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if stream.flushes.Load() != 1 {
		t.Fatal("overlapping flush requests")
	}
}

func TestGenerationReaderFailureAndCanceledDelivery(t *testing.T) {
	p, stream, _ := generationPlatform(t)
	stream.reads <- generationRead{err: errors.New("malformed record")}
	<-p.readerFailed
	g := &linuxPolicyGenerations{p: p}
	if err := g.Drain(context.Background()); err == nil {
		t.Fatal("reader failure acknowledged drain")
	}
	if stream.flushes.Load() != 0 {
		t.Fatal("flush started after reader failure")
	}
	var released atomic.Int32
	p.SetEventCapture(func(e *api.Event) bool {
		e.GenerationContext = api.NewGenerationContext(0, func() { released.Add(1) })
		return true
	})
	p.eventChan = make(chan *api.Event) // delivery cannot succeed
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p.deliver(ctx, &api.Event{}) || released.Load() != 1 {
		t.Fatal("canceled delivery leaked captured zero generation")
	}
}

func TestGenerationScopedQueueLeaseSurvivesReconciliationAndOrdersFence(t *testing.T) {
	p, stream, events := generationPlatform(t)
	p.ebpfLoader = &ebpf.Loader{} // readiness only; never Load or attach BPF
	p.config = LinuxConfig{CgroupFilter: []string{"auto"}, CgroupReconcileInterval: time.Second}
	p.scope.enabled = true
	p.scope.accept([]uint64{42}, nil)
	var captures, released atomic.Int32
	p.SetEventCapture(func(e *api.Event) bool {
		captures.Add(1)
		e.GenerationContext = api.NewGenerationContext(e.PolicyGeneration, func() { released.Add(1) })
		return true
	})
	if err := p.Ready(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The raw outside-scope sample is consumed, but must never acquire a
	// generation lease. Only the exact accepted ID reaches the queue.
	stream.reads <- generationRead{event: &ebpf.Event{CgroupID: 999, PolicyGeneration: 70, Hook: "exec"}}
	stream.reads <- generationRead{event: &ebpf.Event{CgroupID: 42, PolicyGeneration: 71, Hook: "exec", KernelTimestampNS: 12345}}
	var queued *api.Event
	select {
	case queued = <-events:
	case <-ctx.Done():
		t.Fatal("scoped event not delivered")
	}
	if queued.CgroupID != 42 || queued.GenerationContext.ID != 71 || queued.KernelTimestampNS != 12345 || captures.Load() != 1 {
		t.Fatalf("scope or captured identity lost: %+v", queued)
	}
	writerErr := errors.New("scope map update failed")
	if err := p.reconcileCgroups(func(string) ([]uint64, error) { return []uint64{43}, nil }, func([]uint64) error { return writerErr }); !errors.Is(err, writerErr) {
		t.Fatal(err)
	}
	if !p.scope.contains(42) || p.scope.contains(43) || p.Ready() == nil {
		t.Fatal("failed reconciliation changed accepted scope or stayed ready")
	}
	if err := p.reconcileCgroups(func(string) ([]uint64, error) { return []uint64{43}, nil }, func([]uint64) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if p.Ready() != nil || p.scope.contains(42) || !p.scope.contains(43) {
		t.Fatal("accepted scope replacement failed")
	}
	if released.Load() != 0 || queued.GenerationContext.ID != 71 {
		t.Fatal("scope churn released or relabeled an already captured lease")
	}
	g := &linuxPolicyGenerations{p: p}
	done := make(chan error, 1)
	go func() { done <- g.Drain(ctx) }()
	for stream.flushes.Load() == 0 {
		select {
		case <-ctx.Done():
			t.Fatal("no generation flush")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	// Scope removal applies before new captures, not retroactively to work
	// already queued. Even an empty accepted scope cannot filter a fence.
	p.scope.accept(nil, nil)
	stream.reads <- generationRead{event: &ebpf.Event{CgroupID: 42, PolicyGeneration: 71, Hook: "exec"}}
	stream.reads <- generationRead{event: &ebpf.Event{CgroupID: 43, PolicyGeneration: 72, Hook: "exec"}}
	stream.reads <- generationRead{err: fmt.Errorf("scoped ring: %w", ringbuf.ErrFlushed)}
	var fence *api.Event
	select {
	case fence = <-events:
	case <-ctx.Done():
		t.Fatal("empty scope swallowed the generation queue fence")
	}
	if fence.DispatchBarrier == nil || captures.Load() != 1 || p.Ready() != nil {
		t.Fatal("filtered event captured, fence captured, or normal flush withdrew readiness")
	}
	queued.GenerationContext.Complete()
	close(fence.DispatchBarrier)
	if err := <-done; err != nil || released.Load() != 1 {
		t.Fatal("queue fence or captured lease did not complete", err)
	}
	readerErr := errors.New("LSM stream disconnected after scope churn")
	stream.reads <- generationRead{err: readerErr}
	select {
	case <-p.readerFailed:
	case <-ctx.Done():
		t.Fatal("reader failure did not wake generation drain")
	}
	if err := p.Ready(); !errors.Is(err, readerErr) {
		t.Fatal("reader failure did not withdraw scope readiness", err)
	}
	if err := g.Drain(ctx); !errors.Is(err, readerErr) || stream.flushes.Load() != 1 {
		t.Fatal("reader failure silently acknowledged/overlapped drain", err)
	}
}

func TestGenerationStopInterruptsBlockedReaderAndDrain(t *testing.T) {
	for _, blockedDelivery := range []bool{false, true} {
		t.Run(fmt.Sprint("delivery=", blockedDelivery), func(t *testing.T) {
			p, stream, _ := generationPlatform(t)
			var released atomic.Int32
			captured := make(chan struct{})
			if blockedDelivery {
				p.eventChan = make(chan *api.Event)
				p.SetEventCapture(func(e *api.Event) bool {
					e.GenerationContext = api.NewGenerationContext(17, func() { released.Add(1) })
					close(captured)
					return true
				})
				stream.reads <- generationRead{event: &ebpf.Event{Hook: "exec", PolicyGeneration: 17}}
				select {
				case <-captured:
				case <-time.After(time.Second):
					t.Fatal("reader did not capture blocked delivery")
				}
			}
			g := &linuxPolicyGenerations{p: p}
			drain := make(chan error, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			go func() { drain <- g.Drain(ctx) }()
			for stream.flushes.Load() == 0 {
				select {
				case <-ctx.Done():
					t.Fatal("no pending flush")
				default:
					time.Sleep(time.Millisecond)
				}
			}
			done := make(chan error, 1)
			go func() { done <- p.Stop() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("Stop joined before interrupting LSM reader/delivery")
			}
			if err := <-drain; err == nil {
				t.Fatal("shutdown falsely acknowledged pending drain")
			}
			if blockedDelivery && released.Load() != 1 {
				t.Fatal("shutdown leaked canceled-delivery lease")
			}
			if err := g.Drain(context.Background()); err == nil || stream.flushes.Load() != 1 {
				t.Fatal("stopped reader started a fresh flush", err)
			}
		})
	}
}

func TestGenerationCanceledDrainDoesNotStartFlush(t *testing.T) {
	p, stream, _ := generationPlatform(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (&linuxPolicyGenerations{p: p}).Drain(ctx); !errors.Is(err, context.Canceled) || stream.flushes.Load() != 0 {
		t.Fatal("canceled drain touched reader", err)
	}
}
