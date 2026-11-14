//go:build linux

package enforcer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/agentstore"
	"github.com/yasindce1998/warmor/internal/crypto/assignment"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

// This exercises the real quiesce/prepare/commit/swap boundary, not a second
// activation implementation. Production daemon/client wiring is intentionally
// absent until the signed-mode startup, posture and protocol hooks exist.
func TestAssignmentStoreAtRealActivationBoundary(t *testing.T) {
	isolateCacheDir(t)
	e, _ := newTestEnforcer(t, testEnforcerOpts{audit: true, policyWasm: wasmtest.ConstPolicy(0, &[3]uint32{})})
	root := t.TempDir()
	statePath := filepath.Join(root, "assignment.json")
	target := assignment.Target{Scope: "test-scope", Audience: "test-agent"}
	store, err := agentstore.Create(statePath, target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := assignment.Clock{Now: time.Unix(1800000001, 0), Trusted: true}
	opts := assignment.VerifyOptions{Target: target, Clock: clock, SupportedABIs: []uint32{1}, AllowedCompilers: []string{"wasmtest"}, MaxLifetime: time.Hour}
	trust := assignment.Trust{"test": assignment.Key{Public: pub, Target: target}}
	// fsync a real immutable candidate directory and its parent before commit.
	stage := func(revision string, module []byte) string {
		t.Helper()
		dir := filepath.Join(root, revision)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "module.wasm")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(module); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{dir, root} {
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			err = f.Sync()
			_ = f.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
		return path
	}
	d := assignment.Deployment{Format: assignment.Format, KeyID: "test", Target: target,
		Policy:   assignment.Policy{ID: "policy", Version: 1, ABI: 1, Compiler: "wasmtest", Posture: assignment.Posture{Mode: "audit", DefaultAction: "allow"}},
		Sequence: 1, IssuedAt: 1800000000, ExpiresAt: 1800003600}
	verified := func(module []byte) assignment.Verified {
		t.Helper()
		d.Policy.SHA256 = assignment.Digest(module)
		envelope, err := assignment.Sign(private, d)
		if err != nil {
			t.Fatal(err)
		}
		v, err := assignment.Verify(envelope, module, trust, opts)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	old, gen := e.evaluator, e.policyGen.Load()
	badModule := []byte("signed but not WASM")
	badPath := stage("revision-invalid", badModule)
	v := verified(badModule)
	called := false
	if err := e.ActivatePolicy(badPath, func() error { called = true; return store.Commit(v, "revision-invalid", clock) }); err == nil {
		t.Fatal("invalid module activated")
	}
	st, err := store.Snapshot()
	if err != nil || st.HighWater != 0 || called || e.evaluator != old {
		t.Fatalf("prepare failure consumed authorization: %+v %v", st, err)
	}
	module := wasmtest.ConstPolicy(1, &[3]uint32{})
	path := stage("revision-good", module)
	v = verified(module)
	unknownClock := clock
	unknownClock.Trusted = false
	if err := e.ActivatePolicy(path, func() error { return store.Commit(v, "revision-good", unknownClock) }); !errors.Is(err, assignment.ErrClock) {
		t.Fatal(err)
	}
	if e.evaluator != old || e.policyGen.Load() != gen {
		t.Fatal("commit rejection swapped evaluator")
	}
	if err := e.ActivatePolicy(path, func() error { return store.Commit(v, "revision-good", clock) }); err != nil {
		t.Fatal(err)
	}
	if e.evaluator == old || e.policyGen.Load() != gen+1 {
		t.Fatal("durable commit did not swap evaluator")
	}
	current := e.evaluator
	if err := e.ActivatePolicy(path, func() error { return store.Commit(v, "revision-good", clock) }); !errors.Is(err, agentstore.ErrReplay) {
		t.Fatal(err)
	}
	if e.evaluator != current {
		t.Fatal("replay changed evaluator")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = agentstore.Open(statePath, target)
	if err != nil {
		t.Fatal(err)
	}
	st, err = store.Snapshot()
	if err != nil || st.Active == nil || st.HighWater != 1 {
		t.Fatalf("recovery lost activation: %+v %v", st, err)
	}
	envelope, err := assignment.Decode(st.Active.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := os.ReadFile(filepath.Join(root, st.Active.Revision, "module.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assignment.Verify(envelope, recovered, trust, opts); err != nil {
		t.Fatal(err)
	}
	// A crash after durable commit but before userspace swap recovers precisely
	// this same record. Load the selected bytes, never retry Commit on restart.
	runtime, err := wasm.NewRuntime(context.Background(), wasm.RuntimeConfig{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(context.Background())
	if err := runtime.LoadPolicyBytes(context.Background(), recovered); err != nil {
		t.Fatal(err)
	}
	pool, err := wasm.NewPool(context.Background(), runtime, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close(context.Background())
	evaluator := wasm.NewPolicyEvaluator(pool, "recovered")
	defer evaluator.Close(context.Background())
	result, err := evaluator.Evaluate(context.Background(), &api.Event{UID: 1000})
	if err != nil || result.Action != api.ActionDeny {
		t.Fatalf("recovery selected wrong policy: %+v %v", result, err)
	}
}
