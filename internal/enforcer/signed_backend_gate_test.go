package enforcer

import (
	"context"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/crypto/assignment"
	"github.com/yasindce1998/warmor/internal/platform"
	"github.com/yasindce1998/warmor/internal/policyhost"
)

func TestSignedUnsupportedBackendsRejectBeforePlatformAndPolicyIO(t *testing.T) {
	old := newPlatform
	called := false
	newPlatform = func(platform.Config) (platform.Platform, error) {
		called = true
		t.Fatal("unsupported signed backend reached platform")
		return nil, nil
	}
	t.Cleanup(func() { newPlatform = old })
	want := &assignment.Policy{}
	for _, opts := range []*Options{
		{SignedAssignment: want, AtomicGenerations: true},
		{SignedAssignment: want, SupervisedBackend: &policyhost.Config{}},
		{SignedAssignment: want, AtomicGenerations: true, SupervisedBackend: &policyhost.Config{}},
		{ExpectedAssignment: want, AtomicGenerations: true},
	} {
		if e, err := New(context.Background(), "not-read.wasm", opts); err == nil || e != nil || called || !strings.Contains(err.Error(), "unsupported") {
			t.Fatal("unsupported signed combination did not reject first", err)
		}
	}
}

func TestSignedAssignmentActivationCannotEnterGenerationCommit(t *testing.T) {
	e, k := generationEnforcer(t)
	e.verifyKey = make([]byte, 32)
	old, gen := e.evaluator, e.policyGen.Load()
	called := false
	err := e.ActivateAssignment("not-read.wasm", assignment.Policy{}, func() error { called = true; return nil })
	if err == nil || !strings.Contains(err.Error(), "unsupported") || called || e.evaluator != old || e.policyGen.Load() != gen || len(k.prepared) != 1 {
		t.Fatal("signed activation entered generation preparation/commit", err)
	}
	// Generic artifact activation is still the independent unsigned-intent path.
	e.verifyKey = nil
	path := generationCandidate(t, 0)
	if err := e.ActivatePolicy(path, nil); err != nil {
		t.Fatal(err)
	}
}
