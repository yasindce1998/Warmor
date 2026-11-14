// Package coordinator maintains node-local workload identities. It does not
// activate selectors, install policy, or classify unknown cgroups as host tasks.
package coordinator

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yasindce1998/warmor/internal/workload"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// Poller is a trusted source of complete runtime inventory and host-verified
// bindings. A failed poll is never authoritative emptiness or a freshness renewal.
type Poller interface {
	Poll(context.Context) (workload.Inventory, []workload.Binding, error)
	Close() error
}

// PodSource publishes complete, exclusively node-local Pod sets. Sync must stop
// on cancellation and return after a bounded watch/resync interval. Its callback
// is synchronous; inputs must not be mutated during the callback.
type PodSource interface {
	Sync(context.Context, func([]corev1.Pod) error) error
}

type Config struct {
	NodeName, Runtime                                 string
	PollInterval, PollTimeout, MaxAge                 time.Duration
	BackoffMin, BackoffMax                            time.Duration
	MaxPods, MaxContainers, MaxSandboxes, MaxBindings int
	EventBuffer                                       int
}

func DefaultConfig(node, runtime string) Config {
	return Config{NodeName: node, Runtime: runtime, PollInterval: 5 * time.Second,
		PollTimeout: 10 * time.Second, MaxAge: 30 * time.Second,
		BackoffMin: time.Second, BackoffMax: 15 * time.Second,
		MaxPods: 2048, MaxContainers: 8192, MaxSandboxes: 4096,
		MaxBindings: 8192, EventBuffer: 64}
}

func (c Config) validate() error {
	if c.NodeName == "" || len(c.NodeName) > 253 || c.Runtime == "" || len(c.Runtime) > 64 {
		return errors.New("coordinator requires explicit node and runtime")
	}
	if c.PollInterval < time.Millisecond || c.PollTimeout < time.Millisecond ||
		c.MaxAge <= c.PollInterval || c.MaxAge > 10*time.Minute || c.PollTimeout > c.MaxAge ||
		c.BackoffMin < time.Millisecond || c.BackoffMax < c.BackoffMin || c.BackoffMax > time.Minute {
		return errors.New("invalid coordinator timing budget")
	}
	for _, n := range []int{c.MaxPods, c.MaxContainers, c.MaxSandboxes, c.MaxBindings} {
		if n < 1 || n > 65536 {
			return errors.New("invalid coordinator object budget")
		}
	}
	if c.EventBuffer < 1 || c.EventBuffer > 4096 {
		return errors.New("invalid event buffer")
	}
	_, err := workload.NewSnapshot(workload.Inputs{NodeName: c.NodeName, Runtime: c.Runtime})
	return err
}

// Event delivery is best effort and nonblocking. Consumers must read Current,
// not reconstruct security state from these notifications. No Pod/label data or
// unbounded remote error text is included. DroppedEvents is monotonic.
type Event struct {
	Kind  string
	Epoch uint64
	At    time.Time
}

type publication struct {
	epoch    uint64
	until    time.Time
	snapshot *workload.Snapshot
	ready    bool
}

// View is an immutable lease on exactly one identity epoch. Even a retained View
// refuses lookups after replacement, source expiry, or coordinator shutdown.
type View struct {
	owner *Coordinator
	state *publication
}

func (v View) Epoch() uint64 {
	if v.state == nil {
		return 0
	}
	return v.state.epoch
}
func (v View) ValidUntil() time.Time {
	if v.state == nil {
		return time.Time{}
	}
	return v.state.until
}
func (v View) Ready() bool {
	return v.owner != nil && v.state != nil && v.state.ready &&
		v.owner.current.Load() == v.state && time.Now().Before(v.state.until)
}

const Unavailable workload.Reason = "identity_unavailable"

func (v View) Lookup(cgroupID uint64, lifetime string) (workload.Identity, workload.Reason) {
	if !v.Ready() {
		return workload.Identity{}, Unavailable
	}
	i, reason := v.state.snapshot.Lookup(cgroupID, lifetime)
	// Catch replacement while joining. Activation must still fence actions by
	// Epoch; a userspace lookup is not an atomic kernel enforcement transaction.
	if !v.Ready() {
		return workload.Identity{}, Unavailable
	}
	return i, reason
}

type Coordinator struct {
	cfg                    Config
	runtime                Poller
	pods                   PodSource
	current                atomic.Pointer[publication]
	started                atomic.Bool
	dropped                atomic.Uint64
	events                 chan Event
	mu                     sync.Mutex
	epoch                  uint64
	podSet                 []corev1.Pod
	inventory              workload.Inventory
	bindings               []workload.Binding
	podUntil, runtimeUntil time.Time
}

func New(cfg Config, runtime Poller, pods PodSource) (*Coordinator, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if runtime == nil || pods == nil {
		return nil, errors.New("coordinator requires both trusted sources")
	}
	c := &Coordinator{cfg: cfg, runtime: runtime, pods: pods, events: make(chan Event, cfg.EventBuffer)}
	c.current.Store(&publication{})
	return c, nil
}

func (c *Coordinator) Current() View         { return View{owner: c, state: c.current.Load()} }
func (c *Coordinator) Events() <-chan Event  { return c.events }
func (c *Coordinator) DroppedEvents() uint64 { return c.dropped.Load() }

// Run owns both sources until cancellation; exactly one call is permitted.
// Source failure immediately revokes the current view. No last-known-good
// identity is silently retained. Expiry also applies without a running timer.
func (c *Coordinator) Run(ctx context.Context) error {
	if !c.started.CompareAndSwap(false, true) {
		return errors.New("coordinator already run")
	}
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); c.poll(ctx) }()
	go func() { defer wg.Done(); c.watch(ctx) }()
	go func() { defer wg.Done(); c.expire(ctx) }()
	<-ctx.Done()
	c.mu.Lock()
	c.podUntil, c.runtimeUntil = time.Time{}, time.Time{}
	c.publishLocked("stopped")
	c.mu.Unlock()
	wg.Wait()
	err := c.runtime.Close()
	close(c.events)
	return errors.Join(ctx.Err(), err)
}

func (c *Coordinator) expire(ctx context.Context) {
	interval := max(time.Millisecond, min(time.Second, c.cfg.MaxAge/4))
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			p := c.current.Load()
			if p.ready && !time.Now().Before(p.until) {
				c.publishLocked("expired")
			}
			c.mu.Unlock()
		}
	}
}

func (c *Coordinator) poll(ctx context.Context) {
	backoff := c.cfg.BackoffMin
	for ctx.Err() == nil {
		start := time.Now()
		pollCtx, cancel := context.WithTimeout(ctx, c.cfg.PollTimeout)
		inv, bindings, err := c.runtime.Poll(pollCtx)
		if err == nil {
			err = pollCtx.Err()
		}
		cancel()
		if err == nil && (len(inv.Containers) > c.cfg.MaxContainers || len(inv.Sandboxes) > c.cfg.MaxSandboxes || len(bindings) > c.cfg.MaxBindings) {
			err = errors.New("runtime object budget exceeded")
		}
		c.mu.Lock()
		if err == nil && ctx.Err() == nil {
			// Build under the callback's ownership; NewSnapshot copies all data
			// used by readers. Poller transfers these inputs until the next poll.
			c.inventory, c.bindings = cloneInventory(inv), append([]workload.Binding(nil), bindings...)
			c.runtimeUntil = start.Add(c.cfg.MaxAge)
			c.publishLocked("runtime")
		} else {
			c.inventory, c.bindings, c.runtimeUntil = workload.Inventory{}, nil, time.Time{}
			c.publishLocked("runtime_unavailable")
		}
		c.mu.Unlock()
		delay := c.cfg.PollInterval
		if err != nil {
			delay = backoff
			backoff = min(backoff*2, c.cfg.BackoffMax)
		} else {
			backoff = c.cfg.BackoffMin
		}
		if !wait(ctx, delay) {
			return
		}
	}
}

func (c *Coordinator) watch(ctx context.Context) {
	backoff := c.cfg.BackoffMin
	for ctx.Err() == nil {
		start := time.Now()
		// A watch event cannot extend the age of the rest of the Pod cache.
		syncCtx, cancel := context.WithTimeout(ctx, c.cfg.MaxAge)
		err := c.pods.Sync(syncCtx, func(pods []corev1.Pod) error {
			if len(pods) > c.cfg.MaxPods {
				return errors.New("Pod budget exceeded")
			}
			if !time.Now().Before(start.Add(c.cfg.MaxAge)) {
				return errors.New("Pod sync expired")
			}
			copied := make([]corev1.Pod, len(pods))
			for n := range pods {
				if pods[n].Spec.NodeName != c.cfg.NodeName {
					return fmt.Errorf("nonlocal Pod rejected")
				}
				copied[n] = *pods[n].DeepCopy()
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			if syncCtx.Err() != nil {
				return syncCtx.Err()
			}
			c.podSet, c.podUntil = copied, start.Add(c.cfg.MaxAge)
			c.publishLocked("pods")
			return nil
		})
		cancel()
		c.mu.Lock()
		c.podSet, c.podUntil = nil, time.Time{}
		c.publishLocked("pods_unavailable")
		c.mu.Unlock()
		// Every exit requires a new bounded list/watch session.
		delay := c.cfg.BackoffMin // also bound a source repeatedly returning empty success
		if err != nil {
			delay = backoff
			backoff = min(backoff*2, c.cfg.BackoffMax)
		} else {
			backoff = c.cfg.BackoffMin
		}
		if !wait(ctx, delay) {
			return
		}
	}
}

func (c *Coordinator) publishLocked(kind string) {
	c.epoch++
	p := &publication{epoch: c.epoch, until: c.podUntil}
	if c.runtimeUntil.Before(p.until) {
		p.until = c.runtimeUntil
	}
	if time.Now().Before(p.until) {
		p.snapshot, _ = workload.NewSnapshot(workload.Inputs{NodeName: c.cfg.NodeName, Runtime: c.cfg.Runtime,
			Pods: c.podSet, Inventory: c.inventory, Bindings: c.bindings})
		p.ready = p.snapshot != nil
	}
	c.current.Store(p)
	select {
	case c.events <- Event{Kind: kind, Epoch: p.epoch, At: time.Now()}:
	default:
		c.dropped.Add(1)
	}
}

func wait(ctx context.Context, delay time.Duration) bool {
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func cloneInventory(in workload.Inventory) workload.Inventory {
	out := workload.Inventory{Containers: make([]*runtimeapi.Container, len(in.Containers)), Sandboxes: make([]*runtimeapi.PodSandbox, len(in.Sandboxes))}
	for n, c := range in.Containers {
		if c != nil {
			out.Containers[n] = proto.Clone(c).(*runtimeapi.Container)
		}
	}
	for n, s := range in.Sandboxes {
		if s != nil {
			out.Sandboxes[n] = proto.Clone(s).(*runtimeapi.PodSandbox)
		}
	}
	return out
}
