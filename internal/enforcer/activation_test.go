package enforcer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/platform"
	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestActivationWaitsForEvaluationAndCacheHit(t *testing.T) {
	for _, mode := range []string{"evaluation", "cache-hit"} {
		t.Run(mode, func(t *testing.T) {
			isolateCacheDir(t)
			e, _ := newTestEnforcer(t, testEnforcerOpts{audit: true, poolSize: 1, policyWasm: wasmtest.ConstPolicy(0, &[3]uint32{})})
			oldPool := e.pool
			e.evaluator.SetTimeout(5 * time.Second)
			event := &api.Event{PID: 0, UID: 1000, Filename: "/bin/test"}
			var release func()
			if mode == "evaluation" {
				p, err := oldPool.Get(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				release = func() { oldPool.Put(p) }
			} else {
				unblock := make(chan struct{})
				var once sync.Once
				var gate atomic.Bool
				e.cache.SetTimeDependent(func(api.EventType) bool {
					if gate.Load() {
						once.Do(func() { <-unblock })
					}
					return false
				})
				e.cache.Put(event, &api.ActionResult{Action: api.ActionAllow})
				gate.Store(true)
				release = func() { close(unblock) }
			}
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(release) }
			defer unblock()
			handled := make(chan struct{})
			go func() { e.handleEvent(event); close(handled) }()
			deadline := time.Now().Add(5 * time.Second)
			for e.eventMu.TryLock() {
				e.eventMu.Unlock()
				if time.Now().After(deadline) {
					t.Fatal("event did not enter")
				}
				time.Sleep(time.Millisecond)
			}
			committed, done := make(chan struct{}), make(chan error, 1)
			go func() { done <- e.ActivatePolicy(testPolicyPath, func() error { close(committed); return nil }) }()
			select {
			case <-committed:
				t.Fatal("revision committed while an old event was active")
			case <-time.After(30 * time.Millisecond):
			}
			unblock()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("activation did not finish after drain")
			}
			<-handled
			if _, err := oldPool.Get(context.Background()); !errors.Is(err, wasm.ErrPoolClosed) {
				t.Fatalf("retired pool not closed: %v", err)
			}
			if _, hit := e.cache.Get(event); hit {
				t.Fatal("old generation repopulated new cache")
			}
		})
	}
}

func TestActivationCommitFailureRetainsEvaluatorAndRetries(t *testing.T) {
	isolateCacheDir(t)
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyMap: &fakePolicyMap{}})
	old, gen := e.evaluator, e.policyGen.Load()
	if err := e.ActivatePolicy(testPolicyPath, func() error { return errors.New("disk full") }); err == nil {
		t.Fatal("commit failure acknowledged")
	}
	if e.evaluator != old || e.policyGen.Load() != gen {
		t.Fatal("generation advanced despite failed commit")
	}
	if _, err := old.Evaluate(context.Background(), &api.Event{UID: 1000, Filename: "/bin/true"}); err != nil {
		t.Fatalf("old runtime unusable: %v", err)
	}
	if err := e.ActivatePolicy(testPolicyPath, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if e.evaluator == old || e.policyGen.Load() != gen+1 {
		t.Fatal("retry did not activate")
	}
}

func TestActivationBadModuleNeverCommits(t *testing.T) {
	isolateCacheDir(t)
	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	old := e.evaluator
	path := filepath.Join(t.TempDir(), "invalid.wasm")
	if err := os.WriteFile(path, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	committed := false
	if err := e.ActivatePolicy(path, func() error { committed = true; return nil }); err == nil {
		t.Fatal("invalid module activated")
	}
	if committed || e.evaluator != old {
		t.Fatal("load failure changed active revision")
	}
}

func TestActivationKernelFailureNeverCommitsAndRetries(t *testing.T) {
	isolateCacheDir(t)
	pm := &fakePolicyMap{clearErr: errors.New("injected map clear failure")}
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyMap: pm})
	old := e.evaluator
	committed := false
	if err := e.ActivatePolicy(testPolicyPath, func() error { committed = true; return nil }); err == nil {
		t.Fatal("kernel failure acknowledged")
	}
	if committed || e.evaluator != old {
		t.Fatal("kernel preparation failure published candidate")
	}
	pm.clearErr = nil
	if err := e.ActivatePolicy(testPolicyPath, func() error { committed = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !committed || e.evaluator == old {
		t.Fatal("transient kernel failure was not retryable")
	}
}

func TestReloadUnderConcurrentEventLoad(t *testing.T) {
	isolateCacheDir(t)
	e, _ := newTestEnforcer(t, testEnforcerOpts{audit: true, poolSize: 4, policyMap: &fakePolicyMap{}, policyWasm: wasmtest.ConstPolicy(0, &[3]uint32{})})
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				e.handleEvent(&api.Event{PID: 0, UID: 1000, Filename: "/bin/test"})
			}
		}()
	}
	for i := 0; i < 4; i++ {
		if err := e.ReloadPolicy(); err != nil {
			t.Error(err)
			break
		}
	}
	wg.Wait()
	if e.policyGen.Load() != 4 {
		t.Fatalf("unexpected active generation: %d", e.policyGen.Load())
	}
}

func TestDefaultDenyPreparationErrorsReturned(t *testing.T) {
	for _, mode := range []string{"clear-domain", "write", "mark"} {
		t.Run(mode, func(t *testing.T) {
			pm := &fakePolicyMap{}
			e := ddEnforcer(t, pm, false, false)
			switch mode {
			case "clear-domain":
				pm.ddClearErr = errDDTest
			case "write":
				pm.setErr = errDDTest
			case "mark":
				pm.ddMarkErr = errDDTest
			}
			src := fakeStaticSource{proc: wasm.StaticDomain{Eligible: true}}
			if mode == "write" {
				src.proc.Rules = []compiler.StaticRule{{Event: "process", Pattern: "/bin/sh"}}
			}
			if err := e.prepareKernel(src); !errors.Is(err, errDDTest) {
				t.Fatalf("%s failure not returned: %v", mode, err)
			}
		})
	}
}

type activationBootPlatform struct {
	fakePlatform
	pm *fakePolicyMap
}

func (p *activationBootPlatform) Capabilities() platform.Capabilities {
	return platform.Capabilities{LSMEnforcement: true}
}
func (p *activationBootPlatform) PolicyMap() any { return p.pm }

func TestBootKernelPreparationFailureClosesAndCanRetry(t *testing.T) {
	isolateCacheDir(t)
	pm := &fakePolicyMap{ddClearErr: errDDTest}
	failed := &activationBootPlatform{pm: pm}
	stubPlatform(t, failed, nil)
	opts := &Options{AuditMode: true, DefaultDeny: true, MetricsPort: -1}
	if e, err := New(context.Background(), testPolicyPath, opts); !errors.Is(err, errDDTest) || e != nil {
		t.Fatalf("failed boot returned usable enforcer: %v %v", e, err)
	}
	if failed.closed != 1 {
		t.Fatalf("failed boot leaked platform: closed=%d", failed.closed)
	}
	pm.ddClearErr = nil
	recovered := &activationBootPlatform{pm: pm}
	stubPlatform(t, recovered, nil)
	e, err := New(context.Background(), testPolicyPath, opts)
	if err != nil {
		t.Fatalf("boot failed after transient kernel error recovered: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if recovered.closed != 1 {
		t.Fatalf("recovered boot leaked platform: closed=%d", recovered.closed)
	}
}

func TestActivationDrainsProcessActionAndPreservesActualOutcome(t *testing.T) {
	isolateCacheDir(t)
	sink := &activationOutcomeSink{events: make(chan streaming.SecurityEvent, 1)}
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyWasm: wasmtest.ConstPolicy(1, &[3]uint32{})})
	e.pipeline = streaming.NewPipeline(streaming.PipelineConfig{Sinks: []streaming.Sink{sink}})
	t.Cleanup(func() {
		if err := e.pipeline.Close(); err != nil {
			t.Error(err)
		}
	})
	entered, release, handled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	stamp := time.Now()
	e.actionHandler.terminate = func(event *api.Event) (bool, error) {
		if !event.Timestamp.Equal(stamp) {
			t.Errorf("activation integration lost event identity timestamp: %v", event.Timestamp)
		}
		close(entered)
		<-release
		return false, errors.New("injected identity refusal")
	}
	go func() {
		e.handleEvent(&api.Event{PID: 123, UID: 1000, Timestamp: stamp, Filename: "/bin/test"})
		close(handled)
	}()
	<-entered
	committed, activated := make(chan struct{}), make(chan error, 1)
	go func() {
		activated <- e.ActivatePolicy(testPolicyPath, func() error { close(committed); return nil })
	}()
	select {
	case <-committed:
		t.Fatal("activation crossed an unfinished old-generation process action")
	case <-time.After(30 * time.Millisecond):
	}
	unblock()
	<-handled
	if err := <-activated; err != nil {
		t.Fatal(err)
	}
	if err := e.pipeline.Close(); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("expected one old-generation outcome: %d", len(sink.events))
	}
	outcome := <-sink.events
	if outcome.Enforced || outcome.EnforcementAttempted || outcome.EnforcementError != "injected identity refusal" || outcome.Decision != "deny" {
		t.Fatalf("activation lost actual refusal outcome: %+v", outcome)
	}
}

type activationOutcomeSink struct{ events chan streaming.SecurityEvent }

func (s *activationOutcomeSink) Write(_ context.Context, event *streaming.SecurityEvent) error {
	s.events <- *event
	return nil
}
func (*activationOutcomeSink) Flush(context.Context) error { return nil }
func (*activationOutcomeSink) Close() error                { return nil }
func (*activationOutcomeSink) Name() string                { return "activation-outcome" }
