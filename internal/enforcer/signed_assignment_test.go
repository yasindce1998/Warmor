package enforcer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/agentstore"
	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/crypto/assignment"
	"github.com/yasindce1998/warmor/internal/platform"
	"github.com/yasindce1998/warmor/internal/policybuild"
	"github.com/yasindce1998/warmor/internal/policyserver"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestSignedHTTPActivationWaitsForRealEventDrain(t *testing.T) {
	isolateCacheDir(t)
	e, _ := newTestEnforcer(t, testEnforcerOpts{audit: true, poolSize: 1, policyWasm: wasmtest.ConstPolicy(0, &[3]uint32{})})
	inProcessEvaluator(t, e).SetTimeout(5 * time.Second)
	artifact, _ := crypto.GenerateSigningKey()
	signer, _ := crypto.GenerateSigningKey()
	e.verifyKey = artifact.Public
	e.signedAssignment = true
	module, err := policybuild.Append(wasmtest.VersionedConstPolicy(1, 1), policybuild.Metadata{Compiler: "test-build", DefaultAction: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "candidate.wasm")
	if err := os.WriteFile(path, module, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sig", artifact.SignPolicyFile(module), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	clock := assignment.Clock{Now: now, Trusted: true}
	target := assignment.Target{Scope: "scope", Audience: "node"}
	d := assignment.Deployment{Format: 1, KeyID: "deployment", Target: target, Policy: assignment.Policy{ID: "policy", Version: 1, SHA256: assignment.Digest(module), ABI: 1, Compiler: "test-build", Posture: assignment.Posture{Mode: "audit", DefaultAction: "allow"}}, Sequence: 1, IssuedAt: now.Unix() - 1, ExpiresAt: now.Unix() + 60}
	envelope, err := assignment.Sign(signer.Private, d)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := assignment.Encode(envelope)
	if err != nil {
		t.Fatal(err)
	}
	b := assignment.Bundle{Envelope: wire, WASM: module, ArtifactSignature: artifact.Sign(module)}
	body, _ := json.Marshal(b)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(assignment.ProtocolHeader, "1")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	store, err := agentstore.Create(filepath.Join(root, "assignment.json"), target)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	trust := assignment.Trust{"deployment": assignment.Key{Public: signer.Public, Target: target}}
	opts := assignment.VerifyOptions{Target: target, Clock: clock, SupportedABIs: []uint32{1}, AllowedCompilers: []string{"test-build"}, MaxLifetime: time.Hour}
	committed := make(chan struct{})
	client := policyserver.NewClient(policyserver.ClientConfig{ServerURL: srv.URL, AgentID: "node", SignedAssignments: true, Verify: func(*policyserver.PolicyAssignment, []byte) error { return nil }, OnUpdate: func(a *policyserver.PolicyAssignment, data []byte) error {
		v, err := assignment.Verify(envelope, data, trust, opts)
		if err != nil {
			return err
		}
		return e.ActivateAssignment(path, d.Policy, func() error {
			if err := store.Commit(v, "revision-drained", clock); err != nil {
				return err
			}
			close(committed)
			return nil
		})
	}})
	oldPool := e.pool
	p, err := oldPool.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			oldPool.Put(p)
		}
	}()
	handled := make(chan struct{})
	go func() { e.handleEvent(&api.Event{UID: 1000, Filename: "/bin/test"}); close(handled) }()
	deadline := time.Now().Add(5 * time.Second)
	for e.eventMu.TryLock() {
		e.eventMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("event did not enter")
		}
		time.Sleep(time.Millisecond)
	}
	done := make(chan error, 1)
	go func() { done <- client.Poll(context.Background()) }()
	select {
	case <-committed:
		t.Fatal("signed publication crossed unfinished event")
	case <-time.After(30 * time.Millisecond):
	}
	st, _ := store.Snapshot()
	if st.HighWater != 0 {
		t.Fatal("sequence consumed before event drain")
	}
	oldPool.Put(p)
	released = true
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-handled
	st, _ = store.Snapshot()
	if st.HighWater != 1 {
		t.Fatal("drained signed activation not published")
	}
	if err := e.ReloadPolicy(); err == nil {
		t.Fatal("generic reload bypassed signed intent")
	}
	if err := e.ActivateAssignment(path, d.Policy, func() error { return store.Commit(assignment.Verified{}, "revision-zero", clock) }); !errors.Is(err, assignment.ErrInvalid) {
		t.Fatal(err)
	}
}

type signedKernelPlatform struct {
	fakePlatform
	pm *fakePolicyMap
}

func (*signedKernelPlatform) Capabilities() platform.Capabilities {
	return platform.Capabilities{Enforcement: true, LSMEnforcement: true}
}
func (p *signedKernelPlatform) PolicyMap() any    { return p.pm }
func (p *signedKernelPlatform) LSMBlocking() bool { return true }

func TestSignedRequiredDefaultDenyUsesActualEligibleDomainsAndRequiredLSM(t *testing.T) {
	isolateCacheDir(t)
	artifact, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	module, err := policybuild.Append(wasmtest.DefaultDenyPolicy(), policybuild.Metadata{Compiler: "test-build", DefaultAction: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.wasm")
	if err := os.WriteFile(path, module, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sig", artifact.SignPolicyFile(module), 0o600); err != nil {
		t.Fatal(err)
	}
	want := assignment.Policy{ID: "deny-all", Version: 1, SHA256: assignment.Digest(module), ABI: 1, Compiler: "test-build", Posture: assignment.Posture{Mode: "enforce", DefaultAction: "deny", RequireDefaultDeny: true}}
	for _, mode := range []string{"valid", "missing-require-lsm", "ineligible", "kernel-failure"} {
		t.Run(mode, func(t *testing.T) {
			pm := &fakePolicyMap{}
			opts := &Options{Platform: &signedKernelPlatform{pm: pm}, MetricsPort: -1, LSMEnforce: true, RequireLSM: true, DefaultDeny: true, PolicyVerifyKey: artifact.Public, SignedAssignment: &want}
			if mode == "missing-require-lsm" {
				opts.RequireLSM = false
			}
			if mode == "kernel-failure" {
				pm.ddMarkErr = errors.New("injected kernel publication failure")
			}
			candidate := path
			if mode == "ineligible" {
				other, err := policybuild.Append(wasmtest.VersionedConstPolicy(1, 1), policybuild.Metadata{Compiler: "test-build", DefaultAction: "deny"})
				if err != nil {
					t.Fatal(err)
				}
				candidate = filepath.Join(t.TempDir(), "ineligible.wasm")
				if err := os.WriteFile(candidate, other, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(candidate+".sig", artifact.SignPolicyFile(other), 0o600); err != nil {
					t.Fatal(err)
				}
				copy := want
				copy.SHA256 = assignment.Digest(other)
				opts.SignedAssignment = &copy
			}
			e, err := New(context.Background(), candidate, opts)
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				defer e.Close()
				if !e.pool.StaticRulesProcess().Eligible || !e.pool.StaticRulesNetwork().Eligible {
					t.Fatal("test domains not eligible")
				}
			} else if err == nil {
				e.Close()
				t.Fatal("unsatisfied signed kernel posture accepted")
			}
		})
	}
}

func TestSignedStartupRetainsCgroupOptionsAndCaptureReadiness(t *testing.T) {
	isolateCacheDir(t)
	artifact, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	module, err := policybuild.Append(wasmtest.VersionedConstPolicy(0, 1), policybuild.Metadata{Compiler: "reviewed-build", DefaultAction: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.wasm")
	if err := os.WriteFile(path, module, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sig", artifact.SignPolicyFile(module), 0o600); err != nil {
		t.Fatal(err)
	}
	want := assignment.Policy{ID: "signed-policy", Version: 1, SHA256: assignment.Digest(module), ABI: 1, Compiler: "reviewed-build", Posture: assignment.Posture{Mode: "audit", DefaultAction: "allow"}}
	p := &readinessPlatform{}
	cfg := stubPlatform(t, p, nil)
	opts := &Options{AuditMode: true, MetricsPort: -1, MetricsBindAddress: "127.0.0.1", CgroupFilter: []string{"auto"}, CgroupRoot: "/host/cgroup", CgroupReconcileInterval: 2 * time.Second, PolicyVerifyKey: artifact.Public, SignedAssignment: &want}
	e, err := New(context.Background(), path, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if cfg.CgroupRoot != opts.CgroupRoot || cfg.CgroupReconcileInterval != opts.CgroupReconcileInterval || len(cfg.CgroupFilter) != 1 || cfg.CgroupFilter[0] != "auto" || !cfg.AuditMode {
		t.Fatalf("signed startup lost scoped capture configuration: %+v", cfg)
	}
	if e.Ready() == nil {
		t.Fatal("signed bootstrap reported ready before capture loop")
	}
	e.processing.Store(true)
	if err := e.Ready(); err != nil {
		t.Fatal(err)
	}
	p.err = errors.New("dynamic cgroup reconciliation failed")
	if err := e.Ready(); !errors.Is(err, p.err) {
		t.Fatalf("signed readiness ignored capture health: %v", err)
	}
	p.err = nil
	old := e.evaluator
	refused := errors.New("fresh assignment authorization refused")
	if err := e.ActivateAssignment(path, want, func() error { return refused }); !errors.Is(err, refused) {
		t.Fatal(err)
	}
	if e.evaluator != old {
		t.Fatal("failed signed commit replaced last-known-good evaluator")
	}
	if err := e.Ready(); err != nil {
		t.Fatal("failed signed update lost healthy last-known-good readiness", err)
	}
	if err := e.ReloadPolicy(); err == nil {
		t.Fatal("signed mode allowed generic reload bypass")
	}
}
