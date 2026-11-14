//go:build linux

package platform

import (
	"context"
	"errors"
	"fmt"
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
}

func (s *generationStream) ReadLSMEvent() (*ebpf.Event, error) { r := <-s.reads; return r.event, r.err }
func (s *generationStream) FlushLSMEvents() error              { s.flushes.Add(1); return s.flushErr }

func generationPlatform(t *testing.T) (*LinuxPlatform, *generationStream, chan *api.Event) {
	t.Helper()
	return generationPlatformInScope(t, nil)
}

func generationPlatformInScope(t *testing.T, ids []uint64) (*LinuxPlatform, *generationStream, chan *api.Event) {
	t.Helper()
	p, err := NewLinuxPlatform(LinuxConfig{})
	if err != nil {
		t.Fatal(err)
	}
	lp, ok := p.(*LinuxPlatform)
	if !ok {
		t.Fatal("not Linux")
	}
	s := &generationStream{reads: make(chan generationRead, 32)}
	ch := make(chan *api.Event, 32)
	lp.lsmEvents, lp.eventChan = s, ch
	if ids != nil {
		lp.ebpfLoader = &ebpf.Loader{} // readiness only; no BPF loaded
		lp.scope.enabled = true
		lp.scope.accept(ids, nil)
	}
	lp.wg.Add(1)
	go lp.monitorLSMEvents(context.Background())
	t.Cleanup(func() {
		lp.stopOnce.Do(func() { close(lp.stopChan) })
		s.reads <- generationRead{err: ringbuf.ErrClosed}
		lp.wg.Wait()
	})
	return lp, s, ch
}

func TestGenerationScopedReaderPreservesFenceAndWithdrawsReadinessOnFailure(t *testing.T) {
	p, stream, events := generationPlatformInScope(t, []uint64{42})
	var captures atomic.Int32
	p.SetEventCapture(func(event *api.Event) bool {
		captures.Add(1)
		event.GenerationContext = api.NewGenerationContext(event.PolicyGeneration, nil)
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
	for _, id := range []uint64{999, 42} {
		stream.reads <- generationRead{event: &ebpf.Event{Kind: ebpf.EventKindProcess, Hook: "exec", CgroupID: id, PolicyGeneration: 77}}
	}
	stream.reads <- generationRead{err: fmt.Errorf("read lsm: %w", ringbuf.ErrFlushed)}
	select {
	case event := <-events:
		if event.CgroupID != 42 || event.PolicyGeneration != 77 || event.GenerationContext == nil || event.GenerationContext.ID != 77 {
			t.Fatalf("scope or kernel-captured generation lost: %+v", event)
		}
		event.GenerationContext.Complete()
	case <-ctx.Done():
		t.Fatal("no scoped event")
	}
	select {
	case fence := <-events:
		if fence.DispatchBarrier == nil || captures.Load() != 1 {
			t.Fatal("scope filtered fence or captured out-of-scope event")
		}
		close(fence.DispatchBarrier)
	case <-ctx.Done():
		t.Fatal("scope blocked drain fence")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := p.Ready(); err != nil {
		t.Fatalf("wrapped flush must not withdraw readiness: %v", err)
	}
	readerErr := errors.New("scoped generation reader failed")
	stream.reads <- generationRead{err: readerErr}
	select {
	case <-p.readerFailed:
	case <-ctx.Done():
		t.Fatal("reader failure not published")
	}
	if err := p.Ready(); !errors.Is(err, readerErr) {
		t.Fatalf("reader failure must withdraw readiness: %v", err)
	}
	if err := g.Drain(ctx); !errors.Is(err, readerErr) {
		t.Fatalf("failed scoped reader must not acknowledge drain: %v", err)
	}
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
