package wasm

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ErrPoolClosed is returned by Get after the pool has been closed.
var ErrPoolClosed = errors.New("policy pool is closed")

// Pool manages a set of pre-instantiated WASM policy instances for
// lock-free parallel evaluation.
type Pool struct {
	instances chan *Policy
	runtime   *Runtime
	size      int
	counter   atomic.Uint64

	// fields is the module's fields-read declaration per event type,
	// read once from the first instance.
	fields [numEventTypes]uint32
	// temporal: the module is sent temporal context (ABI >= 3).
	temporal bool

	// mu serialises Put against Close so no instance is returned to the
	// channel after it has been drained.
	mu        sync.Mutex
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// NewPool creates a pool of WASM policy instances from a compiled module.
func NewPool(ctx context.Context, runtime *Runtime, size int) (*Pool, error) {
	if size <= 0 {
		size = 1
	}
	if runtime.module == nil {
		return nil, fmt.Errorf("runtime has no compiled module")
	}

	p := &Pool{
		instances: make(chan *Policy, size),
		runtime:   runtime,
		size:      size,
		done:      make(chan struct{}),
	}

	for i := 0; i < size; i++ {
		policy, err := p.instantiate(ctx)
		if err != nil {
			p.Close(ctx)
			return nil, fmt.Errorf("instantiate pool member %d: %w", i, err)
		}
		if i == 0 {
			p.fields = readFieldsDeclaration(ctx, policy)
			p.temporal = policy.temporal
		}
		p.instances <- policy
	}

	return p, nil
}

func (p *Pool) instantiate(ctx context.Context) (*Policy, error) {
	n := p.counter.Add(1)
	modConfig := p.runtime.config.WithName(fmt.Sprintf("policy_%d", n))
	instance, err := p.runtime.runtime.InstantiateModule(ctx, p.runtime.module, modConfig)
	if err != nil {
		return nil, err
	}

	return initPolicy(ctx, p.runtime, instance)
}

// Get retrieves a policy instance from the pool. Blocks if all instances are
// in use. Returns ErrPoolClosed once the pool has been closed.
func (p *Pool) Get(ctx context.Context) (*Policy, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.done:
		return nil, ErrPoolClosed
	case policy := <-p.instances:
		return policy, nil
	}
}

// Put returns a policy instance to the pool. Instances returned after Close
// are closed instead of pooled.
func (p *Pool) Put(policy *Policy) {
	if policy == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.done:
		policy.Close(context.Background())
		return
	default:
	}
	select {
	case p.instances <- policy:
	default:
		// Pool is full (shouldn't happen normally), close the extra instance
		policy.Close(context.Background())
	}
}

// Replace discards an instance that may be unusable (it trapped, or was
// closed because its evaluation deadline expired) and puts a freshly
// instantiated one in its place, so the pool keeps its capacity. If the new
// instance cannot be created the pool shrinks by one and the error is
// returned; callers bound Get with a deadline, so an empty pool fails
// closed rather than blocking forever.
func (p *Pool) Replace(broken *Policy) error {
	if broken != nil {
		broken.Close(context.Background())
	}
	select {
	case <-p.done:
		return nil
	default:
	}
	ctx, cancel := context.WithTimeout(context.Background(), instantiateTimeout)
	defer cancel()
	fresh, err := p.instantiate(ctx)
	if err != nil {
		return fmt.Errorf("replace policy instance: %w", err)
	}
	p.Put(fresh)
	return nil
}

// instantiateTimeout bounds instantiating a replacement instance (which runs
// the module's start function and malloc).
const instantiateTimeout = 5 * time.Second

// Size returns the pool capacity.
func (p *Pool) Size() int {
	return p.size
}

// Close drains and closes all idle instances in the pool. Instances still
// checked out are closed when they are Put back. Close is idempotent.
func (p *Pool) Close(ctx context.Context) error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		close(p.done)
		for {
			select {
			case policy := <-p.instances:
				if err := policy.Close(ctx); err != nil && p.closeErr == nil {
					p.closeErr = err
				}
			default:
				return
			}
		}
	})
	return p.closeErr
}
