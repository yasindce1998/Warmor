package wasm

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
)

// ErrPoolClosed is returned by Get after the pool has been closed.
var ErrPoolClosed = errors.New("policy pool is closed")

// Pool manages a set of pre-instantiated WASM policy instances for
// lock-free parallel evaluation.
type Pool struct {
	instances chan *Policy
	runtime   *Runtime
	module    wazero.CompiledModule
	size      int

	// fields is the module's fields-read declaration per event type,
	// read once from the first instance.
	fields [numEventTypes]uint32
	// temporal: the module is sent temporal context (ABI >= 3).
	temporal   bool
	abiVersion uint32
	abiSet     bool
	// staticProcess/staticNetwork are the kernel default-deny declarations
	// (compiler.StaticRulesExport), read once from the first instance.
	staticProcess StaticDomain
	staticNetwork StaticDomain

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
	ctx, cancel := context.WithTimeout(ctx, runtime.initTimeout)
	defer cancel()

	p := &Pool{
		instances: make(chan *Policy, size),
		runtime:   runtime,
		module:    runtime.module,
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
			p.abiVersion = policy.abiVersion
			p.abiSet = true
			p.fields = readFieldsDeclaration(ctx, policy)
			p.temporal = policy.temporal()
			p.staticProcess = readStaticDomain(ctx, policy, 0)
			p.staticNetwork = readStaticDomain(ctx, policy, 2)
		}
		if policy.instance.IsClosed() || ctx.Err() != nil {
			policy.Close(ctx)
			p.Close(ctx)
			return nil, fmt.Errorf("initialize pool member %d: guest closed or initialization deadline exceeded", i)
		}
		if policy.abiVersion != p.abiVersion {
			policy.Close(ctx)
			p.Close(ctx)
			return nil, fmt.Errorf("inconsistent policy ABI declarations")
		}
		p.instances <- policy
	}

	return p, nil
}

func (p *Pool) instantiate(ctx context.Context) (*Policy, error) {
	// Anonymous instances allow multiple pools to coexist in one runtime.
	// Keep the captured module and bounded initialization path from main;
	// declaration checks must never reinstate raw/unbounded instantiation.
	policy, err := p.runtime.instantiatePolicy(ctx, p.module, p.runtime.config.WithName(""))
	if err != nil {
		return nil, err
	}
	if p.abiSet && policy.abiVersion != p.abiVersion {
		policy.Close(ctx)
		return nil, fmt.Errorf("replacement policy ABI declaration changed")
	}
	return policy, nil
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
	ctx, cancel := context.WithTimeout(context.Background(), p.runtime.initTimeout)
	defer cancel()
	fresh, err := p.instantiate(ctx)
	if err != nil {
		return fmt.Errorf("replace policy instance: %w", err)
	}
	p.Put(fresh)
	return nil
}

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
