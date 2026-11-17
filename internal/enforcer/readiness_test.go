package enforcer

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/platform"
)

type readinessPlatform struct {
	fakePlatform
	err error
}

func (p *readinessPlatform) Ready() error { return p.err }
func TestReadinessRequiresActiveLoopPolicyAndCapture(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{audit: true})
	if err := e.Ready(); err == nil || !strings.Contains(err.Error(), "event loop") {
		t.Fatal(err)
	}
	e.processing.Store(true)
	if err := e.Ready(); err != nil {
		t.Fatal(err)
	}
	p := &readinessPlatform{err: errors.New("discovery failed")}
	e.platform = p
	if err := e.Ready(); err == nil || err.Error() != "discovery failed" {
		t.Fatal(err)
	}
	p.err = nil
	if err := e.Ready(); err != nil {
		t.Fatal(err)
	}
	e.evaluatorMu.Lock()
	old := e.evaluator
	e.evaluator = nil
	e.evaluatorMu.Unlock()
	if err := e.Ready(); err == nil || !strings.Contains(err.Error(), "no active policy") {
		t.Fatal(err)
	}
	e.evaluatorMu.Lock()
	e.evaluator = old
	e.evaluatorMu.Unlock()
	e.cancel()
	if err := e.Ready(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// postureTestPlatform reports an initialized kernel-blocking posture without
// touching BPF, so startup gating can be exercised in isolation.
type postureTestPlatform struct {
	fakePlatform
	enforcement bool
	blocking    bool
}

func (p *postureTestPlatform) Capabilities() platform.Capabilities {
	return platform.Capabilities{LSMEnforcement: p.enforcement}
}
func (p *postureTestPlatform) LSMBlocking() bool { return p.blocking }

// --require-enforce-posture is opt-in: it fails startup only when enforcement
// was requested but the kernel did not actually establish blocking. The
// default keeps the existing degraded-but-running behavior for every
// deployment, so no readiness semantics change unless the flag is set.
func TestNew_RequireEnforcePosture(t *testing.T) {
	isolateCacheDir(t)
	for _, tc := range []struct {
		name        string
		enforcement bool
		blocking    bool
		wantErr     bool
	}{
		{"blocking established", true, true, false},
		{"lsm unavailable", false, false, true},
		{"hooks loaded but toggle unset", true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &postureTestPlatform{enforcement: tc.enforcement, blocking: tc.blocking}
			stubPlatform(t, p, nil)
			e, err := New(context.Background(), testPolicyPath, &Options{
				MetricsPort:           -1,
				LSMEnforce:            true,
				RequireEnforcePosture: true,
			})
			if tc.wantErr {
				if err == nil {
					e.Close()
					t.Fatal("expected startup to fail without established kernel blocking")
				}
				if !strings.Contains(err.Error(), "require-enforce-posture") {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			e.Close()
		})
	}

	t.Run("default still degrades", func(t *testing.T) {
		stubPlatform(t, &postureTestPlatform{enforcement: false, blocking: false}, nil)
		e, err := New(context.Background(), testPolicyPath, &Options{MetricsPort: -1, LSMEnforce: true})
		if err != nil {
			t.Fatalf("New with default posture: %v", err)
		}
		e.Close()
	})

	t.Run("no enforcement requested", func(t *testing.T) {
		stubPlatform(t, &postureTestPlatform{enforcement: false, blocking: false}, nil)
		e, err := New(context.Background(), testPolicyPath, &Options{MetricsPort: -1, RequireEnforcePosture: true})
		if err != nil {
			t.Fatalf("New without LSMEnforce: %v", err)
		}
		e.Close()
	})
}

func TestEventLoopExitWithdrawsReadiness(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{audit: true})
	e.wg.Add(1)
	go e.eventLoop()
	deadline := time.Now().Add(time.Second)
	for !e.processing.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := e.Ready(); err != nil {
		t.Fatal(err)
	}
	e.cancel()
	e.wg.Wait()
	if e.Ready() == nil {
		t.Fatal("stopped loop is ready")
	}
}
