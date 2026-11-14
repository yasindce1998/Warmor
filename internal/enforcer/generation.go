package enforcer

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/cache"
	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/kernelmap"
	"github.com/yasindce1998/warmor/internal/platform"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

// ErrActivationPending means the kernel commit succeeded: the candidate is
// active, but durability/drain is unresolved. Never acknowledge or discard its
// immutable revision. Retry the same path, not a freshly staged replacement.
var ErrActivationPending error = activationPendingError{}

type activationPendingError struct{}

func (activationPendingError) Error() string {
	return "policy active; durable publication or drain pending"
}

// ActivationUncertain lets fleet clients clear a now-inaccurate old active
// identity without importing the enforcer or acknowledging the new revision.
func (activationPendingError) ActivationUncertain() bool { return true }

const generationDrainTimeout = 5 * time.Second

type evaluationGeneration struct {
	id        uint64
	evaluator *wasm.PolicyEvaluator
	pool      *wasm.Pool
	runtime   *wasm.Runtime
	cache     *cache.DecisionCache
	policyID  string
	refs      int
	zero      chan struct{}
}

type generationActivation struct {
	path    string
	commit  func() error
	durable bool
	old     *evaluationGeneration
	digest  [sha256.Size]byte
}

// dispatchMu never acquires eventMu. Readers acquire it only to capture/release
// leases. Activation holds it for register -> kernel commit -> current publish;
// no worker/drain wait or filesystem callback runs while it is held.
type generationDispatch struct {
	mu      sync.Mutex
	states  map[uint64]*evaluationGeneration
	current uint64
	next    uint64
	pending *generationActivation // activationMu only
	kernel  platform.PolicyGenerations
	timeout time.Duration
	abortID uint64 // failed candidate cleanup; activationMu only
}

func (e *Enforcer) enableGenerations(gp platform.GenerationPlatform) error {
	kernel := gp.PolicyGenerations()
	if kernel == nil {
		return errors.New("atomic generations require loaded Linux BPF LSM")
	}
	old := &evaluationGeneration{id: 0, evaluator: e.evaluator, pool: e.pool,
		runtime: e.wasmRuntime, cache: e.cache, policyID: e.policyID}
	e.generations = &generationDispatch{states: map[uint64]*evaluationGeneration{0: old}, kernel: kernel}
	gp.SetEventCapture(e.captureGeneration)
	// Startup has no userspace work yet, but legacy samples can already be
	// queued. Keep ID 0 until the reader starts and proves the first flush.
	spec, err := e.generationSpec(e.evaluator)
	if err != nil {
		return err
	}
	e.generations.next = 1
	if err := kernel.Prepare(1, spec); err != nil {
		return err
	}
	e.generations.states[1] = &evaluationGeneration{id: 1, evaluator: e.evaluator,
		pool: e.pool, runtime: e.wasmRuntime, cache: e.cache, policyID: e.policyID}
	// Generation states now own caches. Do not retain the initial cache's
	// dependency closures (and its retired evaluator) through the legacy field.
	e.cache = nil
	if err := kernel.Activate(1); err != nil {
		delete(e.generations.states, 1)
		return errors.Join(err, kernel.Abort(1))
	}
	e.generations.current = 1
	e.policyGen.Store(1)
	e.generations.pending = &generationActivation{durable: true, old: old}
	return nil
}

func generationBearingHook(event *api.Event) bool {
	if !event.LSMEvent || event.IntegrityViolation {
		return false
	}
	switch event.Hook {
	case "exec", "connect", "bind", "listen", "mount", "ptrace":
		return true
	default:
		return false // file, AF_UNIX and integrity are observation-only
	}
}

func (e *Enforcer) captureGeneration(event *api.Event) bool {
	g := e.generations
	g.mu.Lock()
	defer g.mu.Unlock()
	id := g.current
	if generationBearingHook(event) {
		id = event.PolicyGeneration
	}
	state := g.states[id]
	if state == nil {
		e.logger.LogError(fmt.Errorf("unknown captured generation %d", id), "refuse event dispatch")
		return false
	}
	if state.refs == 0 {
		state.zero = make(chan struct{})
	}
	state.refs++
	event.GenerationContext = api.NewGenerationContext(id, func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		state.refs--
		if state.refs == 0 {
			close(state.zero)
		}
	})
	return true
}

func (e *Enforcer) eventGeneration(event *api.Event) *evaluationGeneration {
	if event.GenerationContext == nil && !e.captureGeneration(event) {
		return nil
	}
	g := e.generations
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.states[event.GenerationContext.ID]
}

// generationSpec only copies domains proved complete by the static export.
// In generation mode requested default-deny is strict: ineligible domains fail
// before Prepare, rather than quietly changing a previously protected domain.
func (e *Enforcer) generationSpec(src staticRulesSource) (kernelmap.GenerationSpec, error) {
	var spec kernelmap.GenerationSpec
	if !e.defaultDeny || e.learningMode {
		return spec, nil
	}
	mode := uint8(1)
	if e.auditMode {
		mode = 2
	}
	for _, d := range []struct {
		typ    uint8
		name   string
		domain wasm.StaticDomain
	}{
		{0, "exec", src.StaticRulesProcess()}, {2, "connect", src.StaticRulesNetwork()},
	} {
		if !d.domain.Eligible {
			return spec, fmt.Errorf("atomic default-deny requires complete %s static domain", d.name)
		}
		for _, r := range d.domain.Rules {
			rule := kernelmap.GenerationRule{EventType: d.typ, Action: r.Action, Audit: r.Audit || e.auditMode}
			if d.typ == 0 {
				rule.Pattern = r.Pattern
			} else {
				rule.Address, rule.Port = r.Pattern, r.Port
			}
			spec.Rules = append(spec.Rules, rule)
		}
		spec.DefaultDeny = append(spec.DefaultDeny, kernelmap.GenerationDomain{EventType: d.typ, Mode: mode})
	}
	return spec, nil
}

// finishGeneration bounds grace waiting, never the lifetime of the retained old
// resources. A timeout retains TWO generations and blocks third-buffer builds.
func (e *Enforcer) finishGeneration() error {
	g := e.generations
	p := g.pending
	if p == nil {
		return nil
	}
	if !p.durable {
		if p.commit != nil {
			if err := p.commit(); err != nil {
				return errors.Join(ErrActivationPending, err)
			}
		}
		p.durable = true
	}
	timeout := g.timeout
	if timeout == 0 {
		timeout = generationDrainTimeout
	}
	ctx, cancel := context.WithTimeout(e.ctx, timeout)
	defer cancel()
	if err := g.kernel.Drain(ctx); err != nil {
		return errors.Join(ErrActivationPending, err)
	}
	g.mu.Lock()
	var zero <-chan struct{}
	if p.old.refs > 0 {
		zero = p.old.zero
	}
	g.mu.Unlock()
	if zero != nil {
		select {
		case <-zero:
		case <-ctx.Done():
			return errors.Join(ErrActivationPending, ctx.Err())
		}
	}
	if err := g.kernel.AcknowledgeDrain(p.old.id); err != nil {
		return errors.Join(ErrActivationPending, err)
	}
	g.mu.Lock()
	delete(g.states, p.old.id)
	current := g.states[g.current]
	g.mu.Unlock()
	if p.old.pool != current.pool {
		closeEvaluationGeneration(p.old)
	}
	g.pending = nil
	return nil
}

func closeEvaluationGeneration(s *evaluationGeneration) {
	ctx := context.Background()
	s.evaluator.Close(ctx)
	s.pool.Close(ctx)
	s.runtime.Close(ctx)
}

// activateGeneration is called with activationMu held. Kernel Activate is the
// irreversible live commit. A failed disk barrier after it is NOT rollback.
func (e *Enforcer) activateGeneration(path string, commit func() error) error {
	g := e.generations
	if g.abortID != 0 {
		if err := g.kernel.Abort(g.abortID); err != nil && !errors.Is(err, kernelmap.ErrStaleGeneration) {
			return err
		}
		g.abortID = 0
	}
	if g.pending != nil {
		pendingPath := g.pending.path
		if pendingPath != "" && path != pendingPath {
			return fmt.Errorf("%w: retry original immutable revision %s", ErrActivationPending, pendingPath)
		}
		if pendingPath != "" {
			data, err := e.generationPolicyBytes(path)
			if err != nil || sha256.Sum256(data) != g.pending.digest {
				return errors.Join(ErrActivationPending, errors.New("pending revision bytes changed; restore the original immutable candidate"), err)
			}
		}
		if err := e.finishGeneration(); err != nil {
			return err
		}
		if pendingPath != "" {
			return nil
		}
	}
	if g.next == math.MaxUint64 {
		return errors.New("generation IDs exhausted; restart required")
	}
	data, err := e.generationPolicyBytes(path)
	if err != nil {
		return err
	}
	rt, err := wasm.NewRuntime(e.ctx, wasm.RuntimeConfig{CacheDir: wasm.DefaultCacheDir()})
	if err != nil {
		return err
	}
	if err := rt.LoadPolicyBytes(e.ctx, data); err != nil {
		rt.Close(e.ctx)
		return err
	}
	pool, err := wasm.NewPool(e.ctx, rt, runtime.NumCPU())
	if err != nil {
		rt.Close(e.ctx)
		return err
	}
	hostname, _ := os.Hostname()
	evaluator := wasm.NewPolicyEvaluator(pool, hostname)
	evaluator.SetTimeout(e.evalTimeout)
	state := &evaluationGeneration{evaluator: evaluator, pool: pool, runtime: rt,
		cache: cache.NewDecisionCache(10000, 5*time.Minute), policyID: policyID(path)}
	setCacheDependencies(state.cache, evaluator)
	active := false
	defer func() {
		if !active {
			closeEvaluationGeneration(state)
		}
	}()
	spec, err := e.generationSpec(evaluator)
	if err != nil {
		return err
	}
	g.next++
	state.id = g.next
	if err := g.kernel.Prepare(state.id, spec); err != nil {
		return errors.Join(err, e.abortGenerationCandidate(state.id))
	}
	// Fence legacy/cache writers too, with the existing documented ordering.
	e.decisionMu.Lock()
	g.mu.Lock()
	g.states[state.id] = state // register before the kernel can emit this ID
	if err := g.kernel.Activate(state.id); err != nil {
		delete(g.states, state.id)
		g.mu.Unlock()
		e.decisionMu.Unlock()
		return errors.Join(err, e.abortGenerationCandidate(state.id))
	}
	old := g.states[g.current]
	g.current = state.id
	e.policyGen.Store(state.id)
	e.evaluatorMu.Lock()
	e.evaluator, e.pool, e.wasmRuntime = evaluator, pool, rt
	e.policyID = state.policyID
	e.evaluatorMu.Unlock()
	g.mu.Unlock()
	e.decisionMu.Unlock()
	active = true
	g.pending = &generationActivation{path: path, commit: commit, old: old, digest: sha256.Sum256(data)}
	return e.finishGeneration()
}

func (e *Enforcer) abortGenerationCandidate(id uint64) error {
	err := e.generations.kernel.Abort(id)
	if errors.Is(err, kernelmap.ErrStaleGeneration) {
		return nil
	} // no FD was admitted
	if err != nil {
		e.generations.abortID = id
	}
	return err
}

// Generation candidates must already be compiled. Read/verify once, then load
// exactly those bytes; a mutable standalone path cannot change pending identity.
func (e *Enforcer) generationPolicyBytes(path string) ([]byte, error) {
	if wasm.IsYAMLPolicy(path) {
		return nil, errors.New("atomic generations require compiled WASM candidates")
	}
	if e.verifyKey != nil {
		return ReadVerifiedPolicy(path, e.verifyKey)
	}
	return crypto.ReadFileLimited(path, wasm.MaxPolicySize)
}

func (e *Enforcer) currentDecisionCache() *cache.DecisionCache {
	if e.generations == nil {
		return e.cache
	}
	g := e.generations
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.states[g.current].cache
}

// Called only after producer and consumer goroutines have stopped.
func (e *Enforcer) releaseQueuedGenerationEvents() {
	if e.generations == nil || e.eventChan == nil {
		return
	}
	for {
		select {
		case event, ok := <-e.eventChan:
			if !ok {
				return
			}
			event.GenerationContext.Complete()
		default:
			return
		}
	}
}
