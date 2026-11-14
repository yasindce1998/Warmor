//go:build linux

package enforcer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/crypto/assignment"
	"github.com/yasindce1998/warmor/internal/platform"
	"github.com/yasindce1998/warmor/internal/policybuild"
	"github.com/yasindce1998/warmor/internal/policyhost"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Only kernel/platform publication is faked. Every host is the actual standalone
// cmd/warmor-policy-host, never a test-binary worker or host-wide monitor.
var supervisedBuild sync.Once
var supervisedExecutable, supervisedDigest string
var supervisedBuildErr error

func supervisedConfig(t *testing.T) policyhost.Config {
	t.Helper()
	supervisedBuild.Do(func() {
		base := ""
		if st, err := os.Stat("/tmp/opencode"); err == nil && st.IsDir() {
			base = "/tmp/opencode"
		}
		dir, err := os.MkdirTemp(base, "supervised-integration-")
		if err != nil {
			supervisedBuildErr = err
			return
		}
		supervisedExecutable = filepath.Join(dir, "warmor-policy-host")
		cmd := exec.Command("go", "build", "-p", "2", "-o", supervisedExecutable, "../../cmd/warmor-policy-host")
		if out, err := cmd.CombinedOutput(); err != nil {
			supervisedBuildErr = errors.New(string(out))
			return
		}
		data, err := os.ReadFile(supervisedExecutable)
		if err != nil {
			supervisedBuildErr = err
			return
		}
		sum := sha256.Sum256(data)
		supervisedDigest = hex.EncodeToString(sum[:])
	})
	if supervisedBuildErr != nil {
		t.Fatal(supervisedBuildErr)
	}
	c := DefaultSupervisedConfig(supervisedExecutable, supervisedDigest, 200*time.Millisecond)
	c.LoadTimeout = time.Second
	return c
}

func TestMain(m *testing.M) {
	code := m.Run()
	if supervisedExecutable != "" {
		_ = os.Remove(supervisedExecutable)
		_ = os.Remove(filepath.Dir(supervisedExecutable))
	}
	os.Exit(code)
}

func supervisedHost(t *testing.T, e Evaluator) *hostEvaluator {
	t.Helper()
	h, ok := e.(*hostEvaluator)
	if !ok {
		t.Fatal("test requires supervised evaluator")
	}
	return h
}

func signedCandidate(t *testing.T, key ed25519.PrivateKey, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "module.wasm")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sig", ed25519.Sign(key, data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func supervisedEnforcer(t *testing.T, module []byte, c policyhost.Config, atomic bool) (*Enforcer, *generationKernel, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k := &generationKernel{}
	old := newPlatform
	newPlatform = func(platform.Config) (platform.Platform, error) { return &generationTestPlatform{k: k}, nil }
	t.Cleanup(func() { newPlatform = old })
	e, err := New(context.Background(), signedCandidate(t, key, module), &Options{AuditMode: true, RequireLSM: atomic,
		AtomicGenerations: atomic, PolicyVerifyKey: pub, SupervisedBackend: &c})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	if atomic {
		if err := e.finishGeneration(); err != nil {
			t.Fatal(err)
		}
	}
	if e.pool != nil || e.wasmRuntime != nil || e.backend.runtime != nil || e.backend.pool != nil {
		t.Fatal("supervised backend constructed a parent runtime/pool")
	}
	return e, k, key
}

func TestSupervisedGenerationRetainsHostUntilCapturedLeaseDrains(t *testing.T) {
	c := supervisedConfig(t)
	e, k, key := supervisedEnforcer(t, wasmtest.ConstPolicy(0, nil), c, true)
	oldHost := supervisedHost(t, e.evaluator)
	oldEvent := &api.Event{UID: 1000, Filename: "/same"}
	if !e.captureGeneration(oldEvent) {
		t.Fatal("capture refused")
	}
	entered := make(chan struct{})
	k.drain = func(context.Context) error { close(entered); return nil }
	done := make(chan error, 1)
	path := signedCandidate(t, key, wasmtest.ConstPolicy(1, nil))
	go func() { done <- e.ActivatePolicy(path, nil) }()
	<-entered
	if r, err := oldHost.Evaluate(context.Background(), &api.Event{}); err != nil || r.Action != api.ActionAllow {
		t.Fatalf("old host retired before lease drain: %+v %v", r, err)
	}
	e.handleEvent(oldEvent)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := oldHost.Evaluate(context.Background(), &api.Event{}); !errors.Is(err, policyhost.ErrClosed) {
		t.Fatalf("old host not retired after lease drain: %v", err)
	}
	e.handleEvent(&api.Event{UID: 1000, Filename: "/same"})
	if s := e.GetStats(); s.Allowed != 1 || s.AuditDenied != 1 {
		t.Fatalf("wrong generation decision/cache %+v", s)
	}
}

func TestSupervisedCompileDeadlinePreservesConcurrentActiveGeneration(t *testing.T) {
	c := supervisedConfig(t)
	c.LoadTimeout = 100 * time.Millisecond
	e, k, key := supervisedEnforcer(t, wasmtest.ConstPolicy(0, nil), c, true)
	old, gen := e.evaluator, e.policyGen.Load()
	path := signedCandidate(t, key, wasmtest.CompileHeavy())
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- e.ActivatePolicy(path, nil) }()
	// Real active-generation evaluations run while candidate compilation owns
	// activationMu. No event/decision/dispatch fence may be held during load.
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(c.InitializationTimeout + time.Second)
	defer deadline.Stop()
	processed := uint64(0)
	var err error
wait:
	for {
		select {
		case err = <-done:
			break wait
		case <-tick.C:
			e.handleEvent(&api.Event{UID: 1000, Filename: "/good"})
			processed++
		case <-deadline.C:
			t.Fatal("candidate load blocked the daemon")
		}
	}
	var failure *policyhost.Failure
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &failure) || failure.Phase != "load" {
		t.Fatalf("expected real child compilation deadline, got %v", err)
	}
	if time.Since(start) > c.InitializationTimeout+time.Second || e.evaluator != old || e.policyGen.Load() != gen || len(k.prepared) != 1 {
		t.Fatal("candidate failure changed generation or exceeded hard bound")
	}
	if processed < 10 || e.GetStats().Allowed != processed {
		t.Fatal("active work did not continue")
	}
	// Immediate next activation needs the same bounded second host slot; it
	// proves the killed compiler was reaped/released before failure returned.
	if err := e.ActivatePolicy(signedCandidate(t, key, wasmtest.ConstPolicy(0, nil)), nil); err != nil {
		t.Fatal("compiler child leaked host capacity", err)
	}
}

func TestSupervisedTerminalHostCannotServeEarlierCachedAllow(t *testing.T) {
	module := wasmtest.DeclaredPolicy(0)
	c := supervisedConfig(t)
	c.TrustedDeclarationDigests = []string{assignment.Digest(module)}
	e, _, _ := supervisedEnforcer(t, module, c, true)
	event := func() *api.Event { return &api.Event{UID: 1000, Filename: "/cached"} }
	e.handleEvent(event())
	if e.currentDecisionCache().Stats().Size != 1 {
		t.Fatal("fixture failed to cache genuine allow")
	}
	if err := supervisedHost(t, e.evaluator).Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.handleEvent(event())
	if s := e.GetStats(); s.Allowed != 1 || s.AuditDenied != 1 {
		t.Fatalf("dead host authorized cached allow %+v", s)
	}
}

func TestSupervisedReadinessRequiresLiveHostAndHealthyCapture(t *testing.T) {
	e, _, key := supervisedEnforcer(t, wasmtest.ConstPolicy(0, nil), supervisedConfig(t), false)
	if err := e.Ready(); err == nil {
		t.Fatal("inactive loop reported ready")
	}
	e.processing.Store(true)
	if err := e.Ready(); err != nil {
		t.Fatal("live supervised host incorrectly requires an in-process pool", err)
	}
	captureErr := errors.New("cgroup reconciliation failed")
	p := &readinessPlatform{err: captureErr}
	e.platform = p
	if err := e.Ready(); !errors.Is(err, captureErr) {
		t.Fatal("supervised backend hid platform scope/readiness error", err)
	}
	p.err = nil
	if err := e.Ready(); err != nil {
		t.Fatal(err)
	}
	if err := supervisedHost(t, e.evaluator).Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.Ready(); err == nil {
		t.Fatal("dead supervised host reported ready")
	}
	if err := e.ActivatePolicy(signedCandidate(t, key, wasmtest.ConstPolicy(0, nil)), nil); err != nil {
		t.Fatal(err)
	}
	if err := e.Ready(); err != nil {
		t.Fatal("explicit replacement did not restore readiness", err)
	}
	e.cancel()
	if err := e.Ready(); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled enforcer reported ready", err)
	}
}

func TestSupervisedPendingCommitRetainsBothHostsAndReusesExactCandidate(t *testing.T) {
	c := supervisedConfig(t)
	e, k, key := supervisedEnforcer(t, wasmtest.ConstPolicy(0, nil), c, true)
	old := e.evaluator
	path := signedCandidate(t, key, wasmtest.ConstPolicy(1, nil))
	commitErr := errors.New("directory barrier failed")
	calls := 0
	err := e.ActivatePolicy(path, func() error { calls++; return commitErr })
	if !errors.Is(err, ErrActivationPending) || e.evaluator == old || calls != 1 {
		t.Fatal("live commit confused with rollback", err)
	}
	if r, err := old.Evaluate(context.Background(), &api.Event{}); err != nil || r.Action != api.ActionAllow {
		t.Fatal("old host closed during uncertain commit", err)
	}
	current := e.evaluator
	commitErr = nil
	if err := e.ActivatePolicy(path, func() error { t.Error("substituted retained callback"); return nil }); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || e.evaluator != current || len(k.prepared) != 2 {
		t.Fatal("recovery respawned host or prepared another kernel generation")
	}
	if _, err := old.Evaluate(context.Background(), &api.Event{}); !errors.Is(err, policyhost.ErrClosed) {
		t.Fatal("resolved old host not retired", err)
	}
}

func TestSupervisedInvalidCandidateNeverPreparesKernelOrCommits(t *testing.T) {
	c := supervisedConfig(t)
	e, k, key := supervisedEnforcer(t, wasmtest.ConstPolicy(0, nil), c, true)
	old, gen := e.evaluator, e.policyGen.Load()
	for _, candidate := range []struct {
		module       []byte
		badSignature bool
	}{{module: []byte("signed but malformed WASM")}, {module: wasmtest.ConstPolicy(1, nil), badSignature: true}} {
		path := signedCandidate(t, key, candidate.module)
		if candidate.badSignature {
			if err := os.WriteFile(path+".sig", []byte("bad signature"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		called := false
		if err := e.ActivatePolicy(path, func() error { called = true; return nil }); err == nil || called {
			t.Fatal("invalid candidate reached durable commit")
		}
		if e.evaluator != old || e.policyGen.Load() != gen || len(k.prepared) != 1 {
			t.Fatal("invalid candidate reached kernel preparation")
		}
	}
}

func TestSupervisedStartupRejectsBeforePlatformCreation(t *testing.T) {
	c := supervisedConfig(t)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := newPlatform
	called := false
	newPlatform = func(platform.Config) (platform.Platform, error) {
		called = true
		return &fakePlatform{}, nil
	}
	t.Cleanup(func() { newPlatform = old })
	path := signedCandidate(t, key, wasmtest.ConstPolicy(0, nil))
	for _, opts := range []*Options{
		{SupervisedBackend: &c},
		{SupervisedBackend: &policyhost.Config{}, PolicyVerifyKey: pub},
	} {
		if e, err := New(context.Background(), path, opts); err == nil || e != nil || called {
			t.Fatal("invalid supervised config reached platform", err)
		}
	}
	if err := os.WriteFile(path+".sig", []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if e, err := New(context.Background(), path, &Options{SupervisedBackend: &c, PolicyVerifyKey: pub}); err == nil || e != nil || called {
		t.Fatal("invalid signature reached platform", err)
	}
	bad := signedCandidate(t, key, []byte("signed invalid WASM"))
	if e, err := New(context.Background(), bad, &Options{SupervisedBackend: &c, PolicyVerifyKey: pub}); err == nil || e != nil || called {
		t.Fatal("invalid child readiness reached platform", err)
	}
}

func TestSupervisedWorkerFailureIsNoncacheableAndNeverRespawns(t *testing.T) {
	c := supervisedConfig(t)
	e, _, key := supervisedEnforcer(t, wasmtest.LoopOnUIDPolicy(), c, true)
	failed := e.evaluator
	e.handleEvent(&api.Event{UID: 0, Filename: "/spin"})
	for range 3 {
		e.handleEvent(&api.Event{UID: 1000, Filename: "/would-allow"})
	}
	if e.evaluator != failed || e.currentDecisionCache().Stats().Size != 0 {
		t.Fatal("worker automatically respawned or error cached")
	}
	if s := e.GetStats(); s.AuditDenied != 4 || s.Allowed != 0 {
		t.Fatalf("worker failure was not fail-closed %+v", s)
	}
	if err := e.ActivatePolicy(signedCandidate(t, key, wasmtest.ConstPolicy(0, nil)), nil); err != nil {
		t.Fatal(err)
	}
}

func TestSupervisedEffectiveTrustAndMetadataBeforeKernelPrepare(t *testing.T) {
	module := wasmtest.DeclaredPolicy(0)
	for _, trusted := range []bool{false, true} {
		t.Run(map[bool]string{false: "untrusted", true: "attested"}[trusted], func(t *testing.T) {
			c := supervisedConfig(t)
			if trusted {
				c.TrustedDeclarationDigests = []string{assignment.Digest(module)}
			}
			e, k, _ := supervisedEnforcer(t, module, c, true)
			if !e.evaluator.Metadata().Domains[0].Eligible || e.evaluator.StaticRulesProcess().Eligible != trusted {
				t.Fatal("effective static trust confused with raw observations")
			}
			e.defaultDeny = true
			spec, err := e.generationSpec(e.evaluator)
			if trusted && (err != nil || len(spec.DefaultDeny) != 2) || !trusted && err == nil {
				t.Fatal("incomplete or untrusted static domain admitted", err)
			}
			e.handleEvent(&api.Event{UID: 1000, Filename: "/same"})
			if cached := e.currentDecisionCache().Stats().Size != 0; cached != trusted {
				t.Fatal("cache did not use effective eligibility")
			}
			if len(k.prepared) != 1 {
				t.Fatal("unexpected prepare")
			}
		})
	}
}

func TestSupervisedAssignmentUsesChildObservedBuildAndRejectsAtomicCombination(t *testing.T) {
	module, err := policybuild.Append(wasmtest.DeclaredPolicy(0), policybuild.Metadata{Compiler: "reviewed-build", DefaultAction: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	c := supervisedConfig(t)
	e, _, key := supervisedEnforcer(t, module, c, false)
	want := assignment.Policy{SHA256: assignment.Digest(module), ABI: 5, Compiler: "reviewed-build", Posture: assignment.Posture{Mode: "audit", DefaultAction: "allow"}}
	if err := e.checkAssignment(e.evaluator, want); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*assignment.Policy){func(p *assignment.Policy) { p.ABI = 4 }, func(p *assignment.Policy) { p.Compiler = "other" }, func(p *assignment.Policy) { p.Posture.DefaultAction = "deny" }, func(p *assignment.Policy) { p.Posture.RequireDefaultDeny = true }} {
		bad := want
		mutate(&bad)
		called := false
		if err := e.ActivateAssignment(signedCandidate(t, key, module), bad, func() error { called = true; return nil }); !errors.Is(err, assignment.ErrCompatibility) || called {
			t.Fatal("assignment mismatch reached commit", err)
		}
	}
	called := false
	if err := e.ActivateAssignment(signedCandidate(t, key, module), want, func() error { called = true; return nil }); err != nil || !called {
		t.Fatal("matching child metadata refused", err)
	}
	if _, err := New(context.Background(), "unused.wasm", &Options{ExpectedAssignment: &want, AtomicGenerations: true, SupervisedBackend: &c}); err == nil {
		t.Fatal("unsupported signed+atomic+host mode accepted")
	}
}

type supervisedPosturePlatform struct {
	fakePlatform
	policyMap        *fakePolicyMap
	loaded, blocking bool
}

func (p *supervisedPosturePlatform) Capabilities() platform.Capabilities {
	return platform.Capabilities{LSMEnforcement: p.loaded}
}
func (p *supervisedPosturePlatform) PolicyMap() any    { return p.policyMap }
func (p *supervisedPosturePlatform) LSMBlocking() bool { return p.blocking }

func TestSupervisedRequiredDefaultDenyRejectsLoadedAuditOnlyLSM(t *testing.T) {
	module, err := policybuild.Append(wasmtest.DeclaredPolicy(1), policybuild.Metadata{Compiler: "reviewed-build", DefaultAction: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	c := supervisedConfig(t)
	c.TrustedDeclarationDigests = []string{assignment.Digest(module)}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := signedCandidate(t, key, module)
	want := assignment.Policy{SHA256: assignment.Digest(module), ABI: 5, Compiler: "reviewed-build",
		Posture: assignment.Posture{Mode: "enforce", DefaultAction: "deny", RequireDefaultDeny: true}}
	for _, tc := range []struct {
		name                   string
		requested, initialized bool
		loadErr                error
		accept                 bool
	}{
		{name: "loaded audit-only, require-lsm is not enforce"},
		{name: "requested but not initialized", requested: true},
		{name: "status without operator request", initialized: true},
		{name: "toggle write failure", requested: true, loadErr: errors.New("set LSM enforce mode: injected write failure")},
		{name: "verified blocking", requested: true, initialized: true, accept: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pm := &fakePolicyMap{}
			p := &supervisedPosturePlatform{policyMap: pm, loaded: true, blocking: tc.initialized}
			p.loadErr = tc.loadErr
			old := newPlatform
			newPlatform = func(platform.Config) (platform.Platform, error) { return p, nil }
			t.Cleanup(func() { newPlatform = old })
			e, err := New(context.Background(), path, &Options{PolicyVerifyKey: pub, SupervisedBackend: &c,
				ExpectedAssignment: &want, DefaultDeny: true, RequireLSM: true, LSMEnforce: tc.requested})
			if e != nil {
				defer e.Close()
			}
			if tc.accept {
				if err != nil || e == nil || !e.kernelEnforce || len(pm.ddMarks) != 2 {
					t.Fatal("verified required default-deny did not initialize", err)
				}
				if e.pool != nil || e.wasmRuntime != nil || e.evaluator.Metadata().ABIVersion != 5 {
					t.Fatal("required-default-deny bypassed real child metadata")
				}
			} else {
				if err == nil || e != nil || len(pm.ddMarks) != 0 || pm.ddClears != 0 {
					t.Fatal("nonblocking startup claimed required default-deny", err)
				}
				if tc.loadErr == nil && !errors.Is(err, assignment.ErrCompatibility) {
					t.Fatal("missing explicit posture incompatibility", err)
				}
			}
		})
	}
}

func TestSupervisedRelativePolicyAndRevisionAliasPaths(t *testing.T) {
	c := supervisedConfig(t) // build command before changing the process cwd
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	t.Chdir(root)
	if err := os.Mkdir("revision", 0o700); err != nil {
		t.Fatal(err)
	}
	module := wasmtest.ConstPolicy(0, nil)
	if err := os.WriteFile("revision/module.wasm", module, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("revision/module.wasm.sig", ed25519.Sign(key, module), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("revision", "current"); err != nil {
		t.Fatal(err)
	}
	old := newPlatform
	newPlatform = func(platform.Config) (platform.Platform, error) { return &fakePlatform{}, nil }
	t.Cleanup(func() { newPlatform = old })
	for _, tc := range []struct {
		name   string
		path   string
		atomic bool
	}{
		{name: "relative", path: "revision/module.wasm"},
		{name: "relative revision alias", path: "current/module.wasm"},
		{name: "atomic relative", path: "revision/module.wasm", atomic: true},
		{name: "atomic relative revision alias", path: "current/module.wasm", atomic: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.atomic {
				newPlatform = func(platform.Config) (platform.Platform, error) {
					return &generationTestPlatform{k: &generationKernel{}}, nil
				}
			} else {
				newPlatform = func(platform.Config) (platform.Platform, error) { return &fakePlatform{}, nil }
			}
			e, err := New(context.Background(), tc.path, &Options{AuditMode: true, PolicyVerifyKey: pub,
				SupervisedBackend: &c, AtomicGenerations: tc.atomic, RequireLSM: tc.atomic})
			if err != nil {
				t.Fatal("supported relative policy path rejected", err)
			}
			defer e.Close()
			if err := e.ReloadPolicy(); err != nil {
				t.Fatal("relative reload rejected", err)
			}
			if r, err := e.evaluator.Evaluate(context.Background(), &api.Event{}); err != nil || r.Action != api.ActionAllow {
				t.Fatal("wrong relative artifact loaded", err)
			}
		})
	}
	resolved, err := resolveSupervisedPolicyPath("current/module.wasm")
	if err != nil || resolved != filepath.Join(root, "revision", "module.wasm") {
		t.Fatal("relative revision did not resolve to an absolute identity", resolved, err)
	}
	// Changing a parent after resolution must not make strict StageFile follow
	// the new symlink, even if the substituted artifact also has a valid key.
	if err := os.Rename("revision", "retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("retained", "revision"); err != nil {
		t.Fatal(err)
	}
	if _, err := policyhost.StageFile(resolved, pub); err == nil {
		t.Fatal("staging followed a parent alias introduced after resolution")
	}
	// Resolving the alias afresh is explicit; detached signature paths still
	// may not be symlinks at the strict staging boundary.
	if err := os.Rename("retained/module.wasm.sig", "retained/signature"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("signature", "retained/module.wasm.sig"); err != nil {
		t.Fatal(err)
	}
	if e, err := New(context.Background(), "current/module.wasm", &Options{PolicyVerifyKey: pub, SupervisedBackend: &c}); err == nil || e != nil {
		t.Fatal("relative alias bypassed no-follow signature staging", err)
	}
}
