//go:build linux

package main

import (
	"bytes"
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
	"github.com/yasindce1998/warmor/internal/enforcer"
	"github.com/yasindce1998/warmor/internal/platform"
	"github.com/yasindce1998/warmor/internal/policybuild"
	"github.com/yasindce1998/warmor/internal/policyserver"
	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
)

type signedTestPlatform struct{ events chan<- *api.Event }

func (*signedTestPlatform) Name() string               { return "signed-test" }
func (*signedTestPlatform) Load(context.Context) error { return nil }
func (p *signedTestPlatform) Start(_ context.Context, ch chan<- *api.Event) error {
	p.events = ch
	return nil
}
func (*signedTestPlatform) Stop() error                         { return nil }
func (*signedTestPlatform) Close() error                        { return nil }
func (*signedTestPlatform) Capabilities() platform.Capabilities { return platform.Capabilities{} }
func (*signedTestPlatform) PolicyMap() any                      { return nil }

type signedFixture struct {
	m                *signedPolicyManager
	artifact, signer *crypto.SigningKey
	config           assignmentConfig
	clock            time.Time
	base             assignment.Deployment
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func newSignedFixture(t *testing.T) *signedFixture {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	artifact, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := signer.MarshalPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	cfg := assignmentConfig{Scope: "tenant/prod", Audience: "node-1", Keys: []assignmentKeyConfig{{ID: "deployment", PublicKey: string(pub), CanRollback: true}}, Compilers: []string{"test-build-1"}, MaxLifetimeSeconds: 3600}
	// Independently reviewed stateless fixtures, not pins derived from any
	// received deployment or signature.
	for _, action := range []int32{0, 1} {
		module, err := policybuild.Append(wasmtest.VersionedConstPolicy(action, 1), policybuild.Metadata{Compiler: "test-build-1", DefaultAction: "allow"})
		if err != nil {
			t.Fatal(err)
		}
		cfg.TrustedDeclarationDigests = append(cfg.TrustedDeclarationDigests, assignment.Digest(module))
	}
	configPath, clockPath := filepath.Join(root, "trust.json"), filepath.Join(root, "clock.json")
	writeJSON(t, configPath, cfg)
	writeJSON(t, clockPath, clockHealth{CheckedAt: now.Unix() - 1, ValidUntil: now.Unix() + 30})
	m, err := openSignedPolicy(configPath, clockPath, root, artifact.Public, true)
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return now }
	t.Cleanup(func() { _ = m.store.Close() })
	return &signedFixture{m: m, artifact: artifact, signer: signer, config: cfg, clock: now, base: assignment.Deployment{Format: 1, KeyID: "deployment", Target: m.target,
		Policy: assignment.Policy{ID: "policy", Version: 1, ABI: 1, Compiler: "test-build-1", Posture: assignment.Posture{Mode: "audit", DefaultAction: "allow"}}, Sequence: 1, IssuedAt: now.Unix() - 1, ExpiresAt: now.Unix() + 3599}}
}

func (f *signedFixture) bundle(t *testing.T, d assignment.Deployment, action int32) assignment.Bundle {
	t.Helper()
	module, err := policybuild.Append(wasmtest.VersionedConstPolicy(action, 1), policybuild.Metadata{Compiler: "test-build-1", DefaultAction: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	d.Policy.SHA256 = assignment.Digest(module)
	e, err := assignment.Sign(f.signer.Private, d)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := assignment.Encode(e)
	if err != nil {
		t.Fatal(err)
	}
	return assignment.Bundle{Envelope: wire, WASM: module, ArtifactSignature: f.artifact.Sign(module)}
}

func bundleAssignment(t *testing.T, b assignment.Bundle) *policyserver.PolicyAssignment {
	t.Helper()
	e, err := assignment.Decode(b.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	d := e.Deployment
	return &policyserver.PolicyAssignment{PolicyID: d.Policy.ID, Version: int64(d.Policy.Version), WASMHash: d.Policy.SHA256, Envelope: b.Envelope, Signature: b.ArtifactSignature, DeploymentSequence: d.Sequence}
}

func bootstrapFixture(t *testing.T, f *signedFixture, sinks ...streaming.Sink) (*enforcer.Enforcer, *signedTestPlatform) {
	t.Helper()
	p := &signedTestPlatform{}
	e, err := f.m.bootstrap(context.Background(), f.bundle(t, f.base, 0), &enforcer.Options{Platform: p, AuditMode: true, MetricsPort: -1, PolicyVerifyKey: f.artifact.Public, StreamSinks: sinks})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e, p
}

func TestSignedModeHTTPRelayRealActivationRestartRollback(t *testing.T) {
	f := newSignedFixture(t)
	e, _ := bootstrapFixture(t, f)
	// Use the actual server HTTP handlers on an in-process fake listener. The
	// relay has PUBLIC trust only and never receives either private key.
	storePath := filepath.Join(t.TempDir(), "server.json")
	store, err := policyserver.OpenStore(storePath, policyserver.StoreOptions{VerifyKey: f.artifact.Public})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	srv := policyserver.NewServer(policyserver.ServerConfig{Store: store, VerifyKey: f.artifact.Public, Insecure: true, AssignmentTrust: assignment.Trust{"deployment": assignment.Key{Public: f.signer.Public, Target: f.m.target, CanRollback: true}}})
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()
	publish := func(b assignment.Bundle) {
		t.Helper()
		wire, err := policyserver.MarshalDeploymentBundle(b)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/deployments", bytesReader(wire))
		response := httptest.NewRecorder()
		srv.Handler().ServeHTTP(response, req)
		if response.Code != http.StatusCreated {
			t.Fatalf("publish: %d %s", response.Code, response.Body.String())
		}
	}
	initial := f.bundle(t, f.base, 0)
	newClient := func(initial *policyserver.PolicyAssignment) *policyserver.Client {
		return policyserver.NewClient(policyserver.ClientConfig{ServerURL: httpServer.URL, AgentID: f.m.target.Audience, SignedAssignments: true, InitialAssignment: initial,
			Verify: func(a *policyserver.PolicyAssignment, data []byte) error {
				_, err := f.m.verify(assignment.Bundle{Envelope: a.Envelope, WASM: data, ArtifactSignature: a.Signature})
				return err
			},
			OnUpdate: func(a *policyserver.PolicyAssignment, data []byte) error {
				return f.m.update(a, data, e.ActivateAssignment)
			}})
	}
	client := newClient(bundleAssignment(t, initial))
	if err := client.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	v2 := f.base
	v2.Sequence = 2
	v2.Policy.Version = 2
	b2 := f.bundle(t, v2, 1)
	publish(b2)
	if err := client.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := client.SendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	a, ok := store.GetAgent(f.m.target.Audience)
	if !ok || a.DeploymentSequence != 2 || a.EnvelopeHash != assignment.Digest(b2.Envelope) {
		t.Fatalf("signed acknowledgement not durable: %+v", a)
	}
	// Same policy bytes with a new signed lease/sequence must not be skipped.
	v2.Sequence = 3
	renewal := f.bundle(t, v2, 1)
	publish(renewal)
	if err := client.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, _ := f.m.store.Snapshot()
	if st.HighWater != 3 {
		t.Fatal("same-artifact renewal skipped")
	}
	if err := f.m.store.Close(); err != nil {
		t.Fatal(err)
	}
	f.m.store, err = agentstore.Open(filepath.Join(f.m.root, "assignment.json"), f.m.target)
	if err != nil {
		t.Fatal(err)
	}
	f.m.commit = f.m.store.Commit
	path, d, err := f.m.restore()
	if err != nil {
		t.Fatal(err)
	}
	if d.Sequence != 3 || path != filepath.Join(f.m.root, st.Active.Revision, "module.wasm") {
		t.Fatal("restart selected wrong authority")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = enforcer.New(context.Background(), path, &enforcer.Options{Platform: &signedTestPlatform{}, AuditMode: true, MetricsPort: -1, PolicyVerifyKey: f.artifact.Public, SignedAssignment: &d.Policy})
	if err != nil {
		t.Fatal("restored signed artifact did not load", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	// A new client can re-ack restored state without replaying commit.
	client = newClient(bundleAssignment(t, renewal))
	if err := client.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := client.SendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	current, _ := assignment.Decode(renewal.Envelope)
	rb := f.base
	rb.Sequence = 4
	rb.Rollback = &assignment.Rollback{FromSequence: 3, From: current.Deployment.Policy, Reason: "approved exact restore"}
	publish(f.bundle(t, rb, 0))
	if err := client.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, _ = f.m.store.Snapshot()
	if st.HighWater != 4 || st.Policies["policy"].Version != 2 {
		t.Fatal("rollback lowered replay/version history")
	}
	if _, err := os.Lstat(filepath.Join(f.m.root, "current")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("signed mode created PR38 pointer authority")
	}
}

// Tiny reader helper avoids shared mutable buffers between HTTP requests.
func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

func TestSignedCommitFreshTrustClockAndActualDeclarations(t *testing.T) {
	for _, failure := range []string{"revoked", "clock", "abi", "compiler", "default-action", "mode", "default-deny", "artifact", "replay", "untrusted-declarations"} {
		t.Run(failure, func(t *testing.T) {
			f := newSignedFixture(t)
			e, _ := bootstrapFixture(t, f)
			d := f.base
			d.Sequence = 2
			d.Policy.Version = 2
			switch failure {
			case "abi":
				d.Policy.ABI = 2
			case "compiler":
				d.Policy.Compiler = "not-the-artifact-compiler"
				f.config.Compilers = append(f.config.Compilers, d.Policy.Compiler)
				writeJSON(t, f.m.configPath, f.config)
			case "default-action":
				d.Policy.Posture.DefaultAction = "deny"
			case "mode":
				d.Policy.Posture.Mode = "enforce"
			case "default-deny":
				d.Policy.Posture = assignment.Posture{Mode: "enforce", DefaultAction: "deny", RequireDefaultDeny: true}
			case "replay":
				d.Sequence = 1
			case "untrusted-declarations":
				f.config.TrustedDeclarationDigests = f.config.TrustedDeclarationDigests[:1]
				writeJSON(t, f.m.configPath, f.config)
			}
			b := f.bundle(t, d, 1)
			if failure == "artifact" {
				b.ArtifactSignature[0] ^= 1
			}
			activate := func(path string, p assignment.Policy, commit func() error) error {
				if failure == "revoked" {
					f.config.Keys[0].ID = "revoked"
					writeJSON(t, f.m.configPath, f.config)
				}
				if failure == "clock" {
					writeJSON(t, f.m.clockPath, clockHealth{})
				}
				return e.ActivateAssignment(path, p, commit)
			}
			if err := f.m.update(bundleAssignment(t, b), b.WASM, activate); err == nil {
				t.Fatal("invalid signed activation accepted")
			}
			st, _ := f.m.store.Snapshot()
			if st.HighWater != 1 {
				t.Fatal("failed activation consumed sequence")
			}
		})
	}
}

func TestSignedTransportNeverDowngrades(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNotModified, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer srv.Close()
			called := false
			c := policyserver.NewClient(policyserver.ClientConfig{ServerURL: srv.URL, AgentID: "node", SignedAssignments: true, OnUpdate: func(*policyserver.PolicyAssignment, []byte) error { called = true; return nil }})
			if err := c.Poll(context.Background()); err == nil || called {
				t.Fatal("legacy response accepted in signed mode")
			}
		})
	}
}

func TestSignedPublicationFaultsRetainUncertainRevision(t *testing.T) {
	for _, failure := range []string{"stage-sync", "before-publication", "after-publication"} {
		t.Run(failure, func(t *testing.T) {
			f := newSignedFixture(t)
			e, _ := bootstrapFixture(t, f)
			old, _ := f.m.store.Snapshot()
			d := f.base
			d.Sequence = 2
			d.Policy.Version = 2
			b := f.bundle(t, d, 1)
			injected := errors.New("injected durability failure")
			switch failure {
			case "stage-sync":
				f.m.syncDir = func(string) error { return injected }
			case "before-publication":
				f.m.commit = func(assignment.Verified, string, assignment.Clock) error { return injected }
			case "after-publication":
				f.m.commit = func(v assignment.Verified, r string, c assignment.Clock) error {
					if err := f.m.store.Commit(v, r, c); err != nil {
						return err
					}
					return errors.Join(agentstore.ErrIndeterminate, injected)
				}
			}
			if err := f.m.update(bundleAssignment(t, b), b.WASM, e.ActivateAssignment); err == nil {
				t.Fatal("failed publication acknowledged")
			}
			st, _ := f.m.store.Snapshot()
			if failure == "after-publication" {
				if st.HighWater != 2 || f.m.fatal == nil {
					t.Fatal("uncertain publication not terminal")
				}
				if _, err := os.Stat(filepath.Join(f.m.root, st.Active.Revision, "module.wasm")); err != nil {
					t.Fatal("uncertain active revision deleted", err)
				}
				if err := f.m.update(bundleAssignment(t, b), b.WASM, e.ActivateAssignment); !errors.Is(err, agentstore.ErrIndeterminate) {
					t.Fatal(err)
				}
			} else if st.HighWater != old.HighWater || st.Active.Revision != old.Active.Revision {
				t.Fatal("failure changed durable active record")
			}
			if err := f.m.store.Close(); err != nil {
				t.Fatal(err)
			}
			var err error
			f.m.store, err = agentstore.Open(filepath.Join(f.m.root, "assignment.json"), f.m.target)
			if err != nil {
				t.Fatal(err)
			}
			f.m.commit = f.m.store.Commit
			f.m.fatal = nil
			_, restored, err := f.m.restore()
			if err != nil {
				t.Fatal(err)
			}
			want := uint64(1)
			if failure == "after-publication" {
				want = 2
			}
			if restored.Sequence != want {
				t.Fatal("restart selected wrong complete record")
			}
		})
	}
}

func TestSignedRestoreRejectsUntrustedTimeExpiredLeaseAndMissingState(t *testing.T) {
	f := newSignedFixture(t)
	_, _ = bootstrapFixture(t, f)
	writeJSON(t, f.m.clockPath, clockHealth{})
	if _, _, err := f.m.restore(); err == nil {
		t.Fatal("unknown-clock startup accepted")
	}
	future := f.clock.Add(2 * time.Hour)
	f.m.now = func() time.Time { return future }
	writeJSON(t, f.m.clockPath, clockHealth{CheckedAt: future.Unix() - 1, ValidUntil: future.Unix() + 30})
	if _, _, err := f.m.restore(); !errors.Is(err, assignment.ErrExpired) {
		t.Fatal(err)
	}
	if err := f.m.store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.m.root, "assignment.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := openSignedPolicy(f.m.configPath, f.m.clockPath, f.m.root, f.artifact.Public, false); err == nil {
		t.Fatal("missing anti-replay state recreated")
	}
}

func TestSignedTrustRotationLockFailsClosed(t *testing.T) {
	f := newSignedFixture(t)
	e, _ := bootstrapFixture(t, f)
	d := f.base
	d.Sequence = 2
	d.Policy.Version = 2
	b := f.bundle(t, d, 1)
	err := agentstore.WithConfigurationLock(f.m.configPath+".lock", func() error { return f.m.update(bundleAssignment(t, b), b.WASM, e.ActivateAssignment) })
	if err == nil {
		t.Fatal("activation ignored concurrent trust rotation lock")
	}
	st, _ := f.m.store.Snapshot()
	if st.HighWater != 1 {
		t.Fatal("lock conflict consumed sequence")
	}
}

func TestSignedActualArtifactMissingMetadataABIAndExpiredDuringPreparation(t *testing.T) {
	for _, failure := range []string{"missing-metadata", "missing-abi", "expired-after-prepare", "clock-regression", "signature-pair"} {
		t.Run(failure, func(t *testing.T) {
			f := newSignedFixture(t)
			e, _ := bootstrapFixture(t, f)
			d := f.base
			d.Sequence = 2
			d.Policy.Version = 2
			b := f.bundle(t, d, 1)
			if failure == "missing-metadata" || failure == "missing-abi" {
				module := wasmtest.VersionedConstPolicy(1, 1)
				if failure == "missing-abi" {
					var err error
					module, err = policybuild.Append(wasmtest.ConstPolicy(1, nil), policybuild.Metadata{Compiler: "test-build-1", DefaultAction: "allow"})
					if err != nil {
						t.Fatal(err)
					}
				}
				d.Policy.SHA256 = assignment.Digest(module)
				signed, err := assignment.Sign(f.signer.Private, d)
				if err != nil {
					t.Fatal(err)
				}
				wire, err := assignment.Encode(signed)
				if err != nil {
					t.Fatal(err)
				}
				b = assignment.Bundle{Envelope: wire, WASM: module, ArtifactSignature: f.artifact.Sign(module)}
				f.config.TrustedDeclarationDigests = append(f.config.TrustedDeclarationDigests, d.Policy.SHA256)
				writeJSON(t, f.m.configPath, f.config)
			}
			activate := func(path string, p assignment.Policy, commit func() error) error {
				if failure == "signature-pair" {
					if err := os.WriteFile(path+".sig", f.artifact.SignPolicyFile([]byte("unrelated")), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				return e.ActivateAssignment(path, p, func() error {
					if failure == "expired-after-prepare" {
						future := f.clock.Add(2 * time.Hour)
						f.m.now = func() time.Time { return future }
						writeJSON(t, f.m.clockPath, clockHealth{CheckedAt: future.Unix() - 1, ValidUntil: future.Unix() + 30})
					}
					if failure == "clock-regression" {
						past := f.clock.Add(-time.Second)
						f.m.now = func() time.Time { return past }
					}
					return commit()
				})
			}
			if err := f.m.update(bundleAssignment(t, b), b.WASM, activate); err == nil {
				t.Fatal("invalid artifact/lease accepted")
			}
			st, _ := f.m.store.Snapshot()
			if st.HighWater != 1 {
				t.Fatal("failed preparation consumed deployment sequence")
			}
		})
	}
}

func TestSignedBootstrapRecoveryKeepsMarksAndRequiresFreshSource(t *testing.T) {
	f := newSignedFixture(t)
	initial, _ := bootstrapFixture(t, f)
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	v2 := f.base
	v2.Sequence = 2
	v2.Policy.Version = 2
	b2 := f.bundle(t, v2, 1)
	opts := &enforcer.Options{Platform: &signedTestPlatform{}, AuditMode: true, MetricsPort: -1, PolicyVerifyKey: f.artifact.Public}
	recovered, err := f.m.bootstrap(context.Background(), b2, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if _, err := openSignedPolicy(f.m.configPath, f.m.clockPath, f.m.root, f.artifact.Public, true); err == nil {
		t.Fatal("explicit bootstrap reset existing replay state")
	}
	st, _ := f.m.store.Snapshot()
	if st.HighWater != 2 || st.Policies["policy"].Version != 2 {
		t.Fatal("recovery reset marks")
	}
	if _, err := f.m.bootstrap(context.Background(), f.bundle(t, f.base, 0), opts); !errors.Is(err, agentstore.ErrReplay) {
		t.Fatal("recovery replay accepted", err)
	}
	_, current, err := f.m.restore()
	if err != nil {
		t.Fatal(err)
	}
	rb := f.base
	rb.Sequence = 3
	rb.Rollback = &assignment.Rollback{FromSequence: 2, From: current.Policy, Reason: "approved pre-start restore"}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err = f.m.bootstrap(context.Background(), f.bundle(t, rb, 0), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	st, _ = f.m.store.Snapshot()
	if st.HighWater != 3 || st.Policies["policy"].Version != 2 {
		t.Fatal("pre-start rollback lowered history")
	}
}
