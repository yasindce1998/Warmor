package enforcer

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
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
