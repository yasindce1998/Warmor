package enforcer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/crypto/assignment"
	"github.com/yasindce1998/warmor/internal/kernelmap"
	"github.com/yasindce1998/warmor/internal/platform"
	"github.com/yasindce1998/warmor/internal/policymeta"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

// The generation seam consumes the canonical source's effective static methods,
// not raw Module flags or a second generation-specific metadata representation.
var _ staticRulesSource = (policymeta.Source)(nil)

func TestGenerationSpecAcceptsCanonicalStaticDomainAliases(t *testing.T) {
	e := &Enforcer{defaultDeny: true}
	process := policymeta.StaticDomain{Eligible: true, Rules: []policymeta.StaticRule{{Event: "process", Pattern: "/bin/canonical", Action: 0}}}
	network := policymeta.StaticDomain{Eligible: true, Rules: []policymeta.StaticRule{{Event: "network", Pattern: "127.0.0.1", Port: 443, Action: 1, Audit: true}}}
	spec, err := e.generationSpec(fakeStaticSource{proc: process, net: network})
	if err != nil || len(spec.Rules) != 2 || len(spec.DefaultDeny) != 2 {
		t.Fatalf("canonical source aliases incompatible: %+v %v", spec, err)
	}
	process.Rules[0].Pattern = "/bin/changed"
	network.Rules[0].Port = 8443
	if spec.Rules[0].Pattern != "/bin/canonical" || spec.Rules[1].Port != 443 || !spec.Rules[1].Audit {
		t.Fatalf("generation installation input retained mutable canonical source data: %+v", spec)
	}
}

// Only the publication/drain boundary is faked; evaluators and pools are real.
// No test in this file loads/attaches BPF or signals a host process.
type generationKernel struct {
	mu                                        sync.Mutex
	active                                    uint64
	prepared                                  []uint64
	aborted                                   []uint64
	acked                                     []uint64
	writes                                    []uint64
	prepareErr, activateErr, ackErr, abortErr error
	drain                                     func(context.Context) error
	publish                                   func(uint64)
}

func (k *generationKernel) Prepare(id uint64, _ kernelmap.GenerationSpec) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.prepared = append(k.prepared, id)
	return k.prepareErr
}
func (k *generationKernel) Activate(id uint64) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.activateErr != nil {
		return k.activateErr
	}
	k.active = id
	if k.publish != nil {
		k.publish(id)
	}
	return nil
}
func (k *generationKernel) Abort(id uint64) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.aborted = append(k.aborted, id)
	return k.abortErr
}
func (k *generationKernel) AcknowledgeDrain(id uint64) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.ackErr != nil {
		return k.ackErr
	}
	k.acked = append(k.acked, id)
	return nil
}
func (k *generationKernel) SyncEvent(id uint64, _ *api.Event, _ uint8, _ bool) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if id != k.active {
		return errStaleDecision
	}
	k.writes = append(k.writes, id)
	return nil
}
func (k *generationKernel) Drain(ctx context.Context) error {
	if k.drain != nil {
		return k.drain(ctx)
	}
	return nil
}

type generationTestPlatform struct {
	fakePlatform
	k       *generationKernel
	capture func(*api.Event) bool
}

func (p *generationTestPlatform) PolicyGenerations() platform.PolicyGenerations { return p.k }
func (p *generationTestPlatform) SetEventCapture(f func(*api.Event) bool)       { p.capture = f }

func generationEnforcer(t *testing.T) (*Enforcer, *generationKernel) {
	t.Helper()
	isolateCacheDir(t)
	e, _ := newTestEnforcer(t, testEnforcerOpts{audit: true, policyMap: &fakePolicyMap{}, policyWasm: wasmtest.ConstPolicy(0, &[3]uint32{})})
	k := &generationKernel{}
	p := &generationTestPlatform{k: k}
	if err := e.enableGenerations(p); err != nil {
		t.Fatal(err)
	}
	if err := e.finishGeneration(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := e.Close(); err != nil {
			t.Error(err)
		}
	})
	return e, k
}

func generationCandidate(t *testing.T, action int32) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "candidate.wasm")
	if err := os.WriteFile(path, wasmtest.ConstPolicy(action, &[3]uint32{}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGenerationCapturedRoutingAndWorkerDrain(t *testing.T) {
	e, k := generationEnforcer(t)
	oldPool := e.pool
	old := &api.Event{PID: 0, UID: 1000, Filename: "/bin/same"}
	if !e.captureGeneration(old) || old.GenerationContext.ID != 1 {
		t.Fatal("tracepoint not captured")
	}
	entered := make(chan struct{})
	k.drain = func(ctx context.Context) error { close(entered); return nil }
	path := generationCandidate(t, 1)
	done := make(chan error, 1)
	go func() { done <- e.ActivatePolicy(path, nil) }()
	<-entered
	// A queued event still evaluates with OLD allow, despite current being deny.
	e.handleEvent(old)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if stats := e.GetStats(); stats.Allowed != 1 || stats.AuditDenied != 0 {
		t.Fatalf("old routed as new: %+v", stats)
	}
	if _, err := oldPool.Get(context.Background()); !errors.Is(err, wasm.ErrPoolClosed) {
		t.Fatalf("old pool not retired: %v", err)
	}
	e.handleEvent(&api.Event{PID: 0, UID: 1000, Filename: "/bin/same"})
	if e.GetStats().AuditDenied != 1 {
		t.Fatal("new generation used old allow cache/evaluator")
	}
	if len(k.acked) != 2 || k.acked[1] != 1 {
		t.Fatalf("bad retirement: %v", k.acked)
	}
}

func TestGenerationDrainRunsWithoutDispatchOrWorkerLocks(t *testing.T) {
	e, k := generationEnforcer(t)
	newHandled := make(chan struct{})
	k.publish = func(id uint64) {
		// Kernel producers do not take userspace locks; the reader can queue
		// new-ID work before Activate returns, but dispatch waits for publish.
		go func() {
			event := &api.Event{LSMEvent: true, Hook: "exec", PolicyGeneration: id, UID: 1000}
			e.handleEvent(event)
			close(newHandled)
		}()
	}
	k.drain = func(ctx context.Context) error {
		for _, hook := range []string{"exec", "connect", "bind", "listen", "mount", "ptrace"} {
			event := &api.Event{LSMEvent: true, Hook: hook, PolicyGeneration: 1, UID: 1000}
			if !e.captureGeneration(event) {
				return errors.New("old sample rejected before ring fence")
			}
			e.handleEvent(event)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	done := make(chan error, 1)
	path := generationCandidate(t, 0)
	go func() { done <- e.ActivatePolicy(path, nil) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("activation deadlocked single reader/worker")
	}
	<-newHandled
}

func TestGenerationZeroContextAndObservationHooks(t *testing.T) {
	e, _ := generationEnforcer(t)
	g := e.generations
	g.mu.Lock()
	g.states[0] = g.states[1] // model the first migration's retained evaluator
	g.mu.Unlock()
	legacy := &api.Event{LSMEvent: true, Hook: "exec"}
	if !e.captureGeneration(legacy) || legacy.GenerationContext.ID != 0 {
		t.Fatal("legacy zero relabeled")
	}
	legacy.GenerationContext.Complete()
	// A tracepoint captured as zero must not be recaptured as current.
	trace := &api.Event{GenerationContext: api.NewGenerationContext(0, nil)}
	if state := e.eventGeneration(trace); state != g.states[0] || trace.GenerationContext.ID != 0 {
		t.Fatal("captured ID zero treated as unset")
	}
	for _, hook := range []string{"", "file", "connect_unix", "integrity"} {
		event := &api.Event{LSMEvent: hook != "", Hook: hook}
		if !e.captureGeneration(event) || event.GenerationContext.ID != 1 {
			t.Fatalf("observation hook %q stuck in legacy", hook)
		}
		event.GenerationContext.Complete()
	}
	delete(g.states, 0)
	if e.captureGeneration(&api.Event{LSMEvent: true, Hook: "exec", PolicyGeneration: 99}) {
		t.Fatal("unknown ID silently routed as current")
	}
}

func TestGenerationCommitFailureRetainsActiveAndRetriesSameRevision(t *testing.T) {
	e, k := generationEnforcer(t)
	oldPool := e.pool
	path := generationCandidate(t, 1)
	calls := 0
	commit := func() error {
		calls++
		if calls == 1 {
			return errors.New("directory fsync uncertain")
		}
		return nil
	}
	if err := e.ActivatePolicy(path, commit); !errors.Is(err, ErrActivationPending) {
		t.Fatalf("bad commit outcome: %v", err)
	}
	if e.policyGen.Load() != 2 || k.active != 2 || e.pool == oldPool {
		t.Fatal("post-commit error pretended rollback")
	}
	if instance, err := oldPool.Get(context.Background()); err != nil {
		t.Fatalf("old resources prematurely closed: %v", err)
	} else {
		oldPool.Put(instance)
	}
	if len(k.acked) != 1 {
		t.Fatal("uncertain publication retired old generation")
	}
	if err := e.ActivatePolicy(generationCandidate(t, 0), nil); !errors.Is(err, ErrActivationPending) {
		t.Fatal("third candidate admitted while commit uncertain")
	}
	if len(k.prepared) != 2 {
		t.Fatal("pending retry allocated another kernel generation")
	}
	if err := e.ActivatePolicy(path, commit); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || e.policyGen.Load() != 2 || len(k.prepared) != 2 {
		t.Fatal("recovery reactivated instead of completing same commit")
	}
}

func TestGenerationBoundedGraceFailureAndRetry(t *testing.T) {
	for _, stage := range []string{"ring", "worker", "retire"} {
		t.Run(stage, func(t *testing.T) {
			e, k := generationEnforcer(t)
			e.generations.timeout = 20 * time.Millisecond
			var lease *api.Event
			if stage == "worker" {
				lease = &api.Event{}
				e.captureGeneration(lease)
				defer lease.GenerationContext.Complete()
			}
			if stage == "ring" {
				k.drain = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
			}
			if stage == "retire" {
				k.ackErr = errors.New("close FD")
			}
			path := generationCandidate(t, 0)
			if err := e.ActivatePolicy(path, nil); !errors.Is(err, ErrActivationPending) {
				t.Fatalf("failure acknowledged: %v", err)
			}
			if len(e.generations.states) != 2 || len(k.acked) != 1 {
				t.Fatal("failed drain destroyed retained evaluator")
			}
			if lease != nil {
				lease.GenerationContext.Complete()
			}
			k.drain, k.ackErr = nil, nil
			if err := e.ActivatePolicy(path, nil); err != nil {
				t.Fatal(err)
			}
			if len(e.generations.states) != 1 || len(k.prepared) != 2 {
				t.Fatal("drain retry allocated third buffer")
			}
		})
	}
}

func TestGenerationPrecommitFailureLeavesOldPolicyAndNeverClears(t *testing.T) {
	for _, stage := range []string{"prepare", "publish"} {
		t.Run(stage, func(t *testing.T) {
			e, k := generationEnforcer(t)
			old := e.evaluator
			if stage == "prepare" {
				k.prepareErr = errors.New("populate")
			} else {
				k.activateErr = errors.New("outer update")
			}
			committed := false
			if err := e.ActivatePolicy(generationCandidate(t, 1), func() error { committed = true; return nil }); err == nil {
				t.Fatal("failed preparation acknowledged")
			}
			if committed || e.evaluator != old || e.policyGen.Load() != 1 || k.active != 1 {
				t.Fatal("failure changed active policy")
			}
			pm, ok := e.policyMap.(*fakePolicyMap)
			if !ok {
				t.Fatal("missing fake map")
			}
			if pm.clearCount() != 0 || len(pm.eventLog()) != 0 {
				t.Fatal("generation activation used legacy clear/unmark rollback")
			}
			if stage == "publish" && len(k.aborted) != 1 {
				t.Fatal("unpublished candidate leaked")
			}
		})
	}
}

func TestGenerationOldWritebackFencedAndStaticDomainStrict(t *testing.T) {
	e, k := generationEnforcer(t)
	old := e.evaluator
	if err := e.ActivatePolicy(generationCandidate(t, 0), nil); err != nil {
		t.Fatal(err)
	}
	event := &api.Event{Filename: "/bin/x", CgroupID: 123}
	e.persistDecision(event, &api.ActionResult{Action: api.ActionDeny}, 1, old)
	if len(k.writes) != 0 {
		t.Fatal("old event wrote to new generation")
	}
	if err := e.syncDecision(event, &api.ActionResult{Action: api.ActionAllow}, 2, compiler.FieldBitPath); err != nil {
		t.Fatal(err)
	}
	if len(k.writes) != 1 || k.writes[0] != 2 {
		t.Fatal("current writeback missed generation API")
	}
	e.defaultDeny = true
	if _, err := e.generationSpec(fakeStaticSource{proc: wasm.StaticDomain{Eligible: true}}); err == nil {
		t.Fatal("incomplete network domain silently removed protection")
	}
	spec, err := e.generationSpec(fakeStaticSource{proc: wasm.StaticDomain{Eligible: true}, net: wasm.StaticDomain{Eligible: true}})
	if err != nil || len(spec.DefaultDeny) != 2 {
		t.Fatalf("complete empty allowlists rejected: %+v %v", spec, err)
	}
}

func TestGenerationPendingMutablePathNeverAcknowledgesDifferentBytes(t *testing.T) {
	e, _ := generationEnforcer(t)
	path := generationCandidate(t, 0)
	if err := e.ActivatePolicy(path, func() error { return errors.New("disk") }); !errors.Is(err, ErrActivationPending) {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, wasmtest.ConstPolicy(1, &[3]uint32{}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.ActivatePolicy(path, nil); !errors.Is(err, ErrActivationPending) {
		t.Fatalf("changed standalone file falsely acknowledged: %v", err)
	}
}

func TestGenerationCancellationRetainsOldUntilTeardown(t *testing.T) {
	e, k := generationEnforcer(t)
	k.drain = func(ctx context.Context) error { e.cancel(); <-ctx.Done(); return ctx.Err() }
	if err := e.ActivatePolicy(generationCandidate(t, 0), nil); !errors.Is(err, ErrActivationPending) {
		t.Fatal(err)
	}
	if len(e.generations.states) != 2 || len(k.acked) != 1 {
		t.Fatal("canceled drain retired old resources")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestGenerationStopCancelsInflightActivationWithoutDispatchLock(t *testing.T) {
	e, k := generationEnforcer(t)
	entered := make(chan struct{})
	k.drain = func(ctx context.Context) error {
		close(entered)
		<-ctx.Done()
		// Reader/worker cleanup must still be able to capture and release a
		// lease while Stop cancels the activation's outstanding drain.
		event := &api.Event{}
		if !e.captureGeneration(event) {
			return errors.New("current generation unavailable during cleanup")
		}
		event.GenerationContext.Complete()
		return ctx.Err()
	}
	path := generationCandidate(t, 1)
	activated := make(chan error, 1)
	go func() { activated <- e.ActivatePolicy(path, nil) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("activation never entered drain")
	}
	stopped := make(chan struct{})
	go func() { e.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop deadlocked with activation")
	}
	select {
	case err := <-activated:
		if !errors.Is(err, ErrActivationPending) || !errors.Is(err, context.Canceled) {
			t.Fatalf("interrupted live activation must remain pending: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("activation cleanup deadlocked on generation dispatch")
	}
	if len(k.acked) != 1 || e.generations.pending == nil || len(e.generations.states) != 2 {
		t.Fatal("Stop retired an undrained generation")
	}
	closed := make(chan error, 1)
	go func() { closed <- e.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close deadlocked after interrupted activation")
	}
}

func TestGenerationOptionFailsBeforePlatformSideEffects(t *testing.T) {
	for _, opts := range []*Options{
		{AtomicGenerations: true},
		{AtomicGenerations: true, RequireLSM: true, SkipLSM: true},
	} {
		if e, err := New(context.Background(), "not-read.wasm", opts); err == nil || e != nil {
			t.Fatal("invalid generation posture reached platform")
		}
	}
	if e, err := New(context.Background(), "not-read.yaml", &Options{AtomicGenerations: true, RequireLSM: true}); err == nil || e != nil {
		t.Fatal("mutable compile-on-reload path admitted")
	}
}

func TestGenerationSignedAssignmentRejectedBeforeStartupSideEffects(t *testing.T) {
	artifact, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	original := newPlatform
	t.Cleanup(func() { newPlatform = original })
	called := false
	newPlatform = func(platform.Config) (platform.Platform, error) {
		called = true
		return nil, errors.New("unexpected platform construction")
	}
	_, err = New(context.Background(), "not-read.wasm", &Options{
		AtomicGenerations: true, RequireLSM: true, PolicyVerifyKey: artifact.Public,
		SignedAssignment: &assignment.Policy{},
	})
	if err == nil || !strings.Contains(err.Error(), "separately reviewed") || called {
		t.Fatalf("signed/generation startup reached artifact/platform preparation: %v", err)
	}
}

func TestGenerationSignedAssignmentCannotUseLiveFirstCommit(t *testing.T) {
	e, k := generationEnforcer(t)
	old := e.evaluator
	committed := false
	err := e.ActivateAssignment("not-read.wasm", assignment.Policy{}, func() error { committed = true; return nil })
	if err == nil || !strings.Contains(err.Error(), "separately reviewed") || committed || e.evaluator != old || len(k.prepared) != 1 || e.generations.pending != nil {
		t.Fatalf("signed update crossed experimental generation boundary: %v", err)
	}
}

func TestGenerationFailedCandidateCleanupRetriedBeforeNextPrepare(t *testing.T) {
	e, k := generationEnforcer(t)
	k.prepareErr, k.abortErr = errors.New("populate"), errors.New("close")
	path := generationCandidate(t, 0)
	if err := e.ActivatePolicy(path, nil); err == nil {
		t.Fatal("failed prepare acknowledged")
	}
	if e.generations.abortID != 2 {
		t.Fatal("failed candidate cleanup ownership lost")
	}
	k.prepareErr = nil
	if err := e.ActivatePolicy(path, nil); err == nil {
		t.Fatal("new prepare passed unresolved cleanup")
	}
	if len(k.prepared) != 2 {
		t.Fatal("third candidate prepared")
	}
	k.abortErr = nil
	if err := e.ActivatePolicy(path, nil); err != nil {
		t.Fatal(err)
	}
	if e.policyGen.Load() != 3 || e.generations.abortID != 0 {
		t.Fatal("cleanup retry reused failed ID")
	}
}

func TestGenerationRetirementWaitsForOldProcessOutcome(t *testing.T) {
	e, k := generationEnforcer(t)
	// Install a denying generation, then let an event's action outlive the
	// next live commit. Its outcome must finish before old pool retirement.
	k.drain = nil
	if err := e.ActivatePolicy(generationCandidate(t, 1), nil); err != nil {
		t.Fatal(err)
	}
	e.actionHandler.auditMode = false
	entered, release, handled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	e.actionHandler.terminate = func(*api.Event) (bool, error) {
		close(entered)
		<-release
		return false, errors.New("injected identity refusal")
	}
	event := &api.Event{PID: 123, UID: 1000, Filename: "/bin/test"}
	if !e.captureGeneration(event) {
		t.Fatal("capture failed")
	}
	go func() { e.handleEvent(event); close(handled) }()
	<-entered
	draining := make(chan struct{})
	k.drain = func(context.Context) error { close(draining); return nil }
	oldPool := e.pool
	done := make(chan error, 1)
	path := generationCandidate(t, 0)
	go func() { done <- e.ActivatePolicy(path, nil) }()
	<-draining
	select {
	case <-done:
		t.Fatal("unfinished process action crossed retirement")
	default:
	}
	if p, err := oldPool.Get(context.Background()); err != nil {
		t.Fatal("old action pool closed early")
	} else {
		oldPool.Put(p)
	}
	unblock()
	<-handled
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := oldPool.Get(context.Background()); !errors.Is(err, wasm.ErrPoolClosed) {
		t.Fatal("old pool not closed after outcome")
	}
	if stats := e.GetStats(); stats.Denied != 1 || stats.EnforcementRefused != 1 || stats.EnforcementSucceeded != 0 {
		t.Fatalf("old outcome lost through activation: %+v", stats)
	}
}
