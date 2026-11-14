package enforcer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/nodereceipt"
	"github.com/yasindce1998/warmor/internal/nodereceipt/receipttest"
	"github.com/yasindce1998/warmor/internal/policybuild"
	"github.com/yasindce1998/warmor/internal/telemetry"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
)

// This exercises actual Enforcer.New/ActivatePolicy, WASM runtime/pool commit,
// HTTPS client/controller receipt handler and real REST TokenReview+Pod reads.
// Only the kernel platform and Kubernetes server are fakes: no host privilege,
// live cluster or real token requests are used, and this is NOT attestation.
func TestActualActivationReceiptHTTPS(t *testing.T) {
	for _, withTelemetry := range []bool{false, true} {
		name := "without-collector"
		if withTelemetry {
			name = "embedded-collector"
		}
		t.Run(name, func(t *testing.T) { testActualActivationReceiptHTTPS(t, withTelemetry) })
	}
}

func testActualActivationReceiptHTTPS(t *testing.T, withTelemetry bool) {
	isolateCacheDir(t)
	pm := &fakePolicyMap{}
	stubPlatform(t, &activationBootPlatform{pm: pm}, nil)
	data, err := policybuild.Append(wasmtest.VersionedConstPolicy(0, 3), policybuild.Metadata{Compiler: "test-compiler", DefaultAction: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.wasm")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sig", key.SignPolicyFile(data), 0600); err != nil {
		t.Fatal(err)
	}
	opts := &Options{AuditMode: true, MetricsPort: -1, PolicyVerifyKey: key.Public}
	var collector *telemetry.Collector
	lease := telemetry.Session{Epoch: "embedded-test", SessionID: "embedded-session"}
	if withTelemetry {
		collector = &telemetry.Collector{}
		if err := collector.SetSession(lease); err != nil {
			t.Fatal(err)
		}
		opts.Telemetry = collector
	}
	e, err := New(context.Background(), path, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	activationSequence := uint64(0)
	activate := func(candidate string, commit func() error) error {
		if !withTelemetry {
			return e.ActivatePolicy(candidate, commit)
		}
		activationSequence++
		// A structurally valid telemetry label is NOT trusted artifact evidence.
		// Deliberately supply a different hash to prove receipts use Pool.Identity.
		return e.ActivatePolicyTelemetry(candidate, commit, telemetry.Assignment{Session: lease, AssignmentRevision: activationSequence}, telemetry.Revision{PolicyID: "telemetry-label", PolicyVersion: 1, PolicyHash: strings.Repeat("f", 64)})
	}
	if _, err := e.ActiveReceipt(); err == nil {
		t.Fatal("unit preparation/initialization claimed running activation")
	}
	// Start the real daemon lifecycle on an owned ephemeral loopback listener.
	// The platform backend alone is fake; pool preparation is not activation.
	e.metricsServer = metrics.NewServerAddress("127.0.0.1:0")
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	deadline := time.Now().Add(time.Second)
	for !e.processing.Load() {
		if time.Now().After(deadline) {
			t.Fatal("event loop did not start")
		}
		time.Sleep(time.Millisecond)
	}
	active, err := e.ActiveReceipt()
	if err != nil {
		t.Fatal(err)
	}
	if active.Digest != nodereceipt.Digest(data) {
		t.Fatal("active identity is not exact runtime bytes")
	}
	k := receipttest.NewKube(t)
	m := nodereceipt.Manifest{Version: 1, PublicationEpoch: nodereceipt.Digest([]byte("publication-a")), Revision: "effective:actual", Digest: active.Digest, SnapshotDigest: nodereceipt.Digest([]byte("snapshot")), Compiler: "controller/test", ArtifactCompiler: active.ArtifactCompiler, DefaultAction: active.DefaultAction, ABI: active.ABI, Posture: active.Posture, Sources: []nodereceipt.Source{{Namespace: "security", Name: "p", UID: "policy-uid", Generation: 1}}}
	if active.ABI == 0 {
		t.Fatal("fixture must declare an ABI for real receipt test")
	}
	s, err := nodereceipt.NewServer(receipttest.Config(k, func(context.Context) (nodereceipt.Manifest, error) { return m, nil }))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(s.Handler())
	defer server.Close()
	dir := t.TempDir()
	manifestPath, tokenPath := filepath.Join(dir, "manifest.json"), filepath.Join(dir, "token")
	b, _ := json.Marshal(m)
	if err := os.WriteFile(manifestPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("bound-token-a"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := nodereceipt.NewClient(nodereceipt.ClientConfig{URL: server.URL, TLS: receipttest.Trust(server), TokenPath: tokenPath, ManifestPath: manifestPath, Active: e.ActiveReceipt})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result, err := s.Aggregate(context.Background(), m); err != nil || !result.All {
		t.Fatalf("actual activation not acknowledged: %+v %v", result, err)
	}
	originalManifest := m
	originalManifest.Sources = append([]nodereceipt.Source(nil), m.Sources...)
	validPath := filepath.Join(t.TempDir(), "valid.wasm")
	candidate, err := policybuild.Append(wasmtest.VersionedConstPolicy(1, 3), policybuild.Metadata{Compiler: "test-compiler-next", DefaultAction: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(validPath, candidate, 0600); err != nil {
		t.Fatal(err)
	}
	// Detached artifact signatures are compatible with controller mode. They
	// authenticate pool build declarations; a failed signature cannot advance
	// the receipt identity. Fleet signed-intent mode is separately rejected.
	if err := os.WriteFile(validPath+".sig", key.SignPolicyFile(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := activate(validPath, nil); !errors.Is(err, crypto.ErrPolicySignatureInvalid) {
		t.Fatalf("candidate signature bypassed: %v", err)
	}
	if current, err := e.ActiveReceipt(); err != nil || current != active {
		t.Fatal("failed signature changed receipt identity", err)
	}
	if err := os.WriteFile(validPath+".sig", key.SignPolicyFile(candidate), 0600); err != nil {
		t.Fatal(err)
	}
	// The real runtime moves A->B while desired publication remains A. The
	// client must send an authenticated withdrawal, not only forget locally.
	if err := activate(validPath, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Report(context.Background()); err == nil {
		t.Fatal("actual runtime drift acknowledged as A")
	}
	if result, err := s.Aggregate(context.Background(), m); err != nil || result.All || result.Applied != 0 {
		t.Fatalf("old A survived real activation B: %+v %v", result, err)
	}
	if err := activate(path, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertTelemetryUnchanged := func(before telemetry.Revision) {
		t.Helper()
		if withTelemetry && collector.ActiveRevision() != before {
			t.Fatal("failed candidate advanced telemetry revision")
		}
	}
	var telemetryBeforeFailure telemetry.Revision
	if withTelemetry {
		telemetryBeforeFailure = collector.ActiveRevision()
	}
	// Real kernel-preparation AND rollback failure invalidates the enforcer's
	// acknowledgement. The real ActiveReceipt error must withdraw prior A.
	pm.clearErr = errors.New("kernel preparation and rollback unavailable")
	if err := activate(validPath, nil); err == nil {
		t.Fatal("kernel failure acknowledged")
	}
	assertTelemetryUnchanged(telemetryBeforeFailure)
	if err := c.Report(context.Background()); err == nil {
		t.Fatal("unacknowledged activation accepted")
	}
	if result, err := s.Aggregate(context.Background(), m); err != nil || result.All {
		t.Fatalf("active error retained A: %+v %v", result, err)
	}
	pm.clearErr = nil
	if err := activate(path, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	active, err = e.ActiveReceipt()
	if err != nil {
		t.Fatal(err)
	}
	// Reading changed content from disk must NOT change the reported active
	// digest; it has not passed WASM validation or evaluator/kernel commit.
	if err := os.WriteFile(path, []byte("downloaded-invalid-candidate"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.ReloadPolicy(); err == nil {
		t.Fatal("invalid reload succeeded")
	}
	still, err := e.ActiveReceipt()
	if err != nil || still != active {
		t.Fatalf("failed preparation changed active receipt: %+v %v", still, err)
	}
	// Even a valid module must not advance the activation timestamp/digest
	// before the durable publication callback succeeds.
	m.Digest = nodereceipt.Digest(candidate)
	m.ArtifactCompiler, m.DefaultAction = "test-compiler-next", "deny"
	m.PublicationEpoch = nodereceipt.Digest([]byte("publication-b"))
	m.Revision = "effective:next"
	m.Sources[0].Generation++
	b, _ = json.Marshal(m)
	if err := os.WriteFile(manifestPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.Report(context.Background()); err == nil {
		t.Fatal("downloaded manifest counted before activation")
	}
	if result, err := s.Aggregate(context.Background(), m); err != nil || result.All {
		t.Fatalf("old receipt blessed desired candidate: %+v %v", result, err)
	}
	if withTelemetry {
		telemetryBeforeFailure = collector.ActiveRevision()
	}
	if err := activate(validPath, func() error { return errors.New("failed durable commit") }); err == nil {
		t.Fatal("failed commit acknowledged")
	}
	assertTelemetryUnchanged(telemetryBeforeFailure)
	still, err = e.ActiveReceipt()
	if err != nil || still != active {
		t.Fatalf("failed commit advanced receipt: %+v %v", still, err)
	}
	// Receipt readers cannot observe a candidate while its durable commit is
	// outstanding, with or without the optional telemetry overload.
	commitEntered, releaseCommit := make(chan struct{}), make(chan struct{})
	activationDone := make(chan error, 1)
	go func() {
		activationDone <- activate(validPath, func() error { close(commitEntered); <-releaseCommit; return nil })
	}()
	select {
	case <-commitEntered:
	case err := <-activationDone:
		t.Fatalf("activation missed commit barrier: %v", err)
	}
	type observation struct {
		active nodereceipt.Activation
		err    error
	}
	observed := make(chan observation, 1)
	readerStarted := make(chan struct{})
	go func() { close(readerStarted); a, err := e.ActiveReceipt(); observed <- observation{a, err} }()
	<-readerStarted
	select {
	case value := <-observed:
		close(releaseCommit)
		<-activationDone
		t.Fatalf("receipt escaped uncommitted activation: %+v", value)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseCommit)
	if err := <-activationDone; err != nil {
		t.Fatal(err)
	}
	value := <-observed
	next, err := value.active, value.err
	if err != nil || !next.ActivatedAt.After(active.ActivatedAt) || next.Digest != m.Digest || next.ArtifactCompiler != m.ArtifactCompiler || next.DefaultAction != m.DefaultAction {
		t.Fatalf("successful activation not recorded: %+v %v", next, err)
	}
	if err := c.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result, err := s.Aggregate(context.Background(), m); err != nil || !result.All {
		t.Fatalf("committed evaluator not acknowledged: %+v %v", result, err)
	}
	if withTelemetry {
		if snapshot := collector.Snapshot(); snapshot == nil || snapshot.Revision.PolicyHash == next.Digest {
			t.Fatal("test did not distinguish telemetry label from actual active artifact")
		}
		// A generic activation seals fleet attribution without removing the
		// independently committed pool's receipt identity.
		if err := e.ActivatePolicy(validPath, nil); err != nil {
			t.Fatal(err)
		}
		if collector.Snapshot() != nil {
			t.Fatal("generic reload retained fleet attribution")
		}
		if err := c.Report(context.Background()); err != nil {
			t.Fatal(err)
		}
		if result, err := s.Aggregate(context.Background(), m); err != nil || !result.All {
			t.Fatalf("telemetry sealing removed genuine receipt: %+v %v", result, err)
		}
	}
	// Return the publication to byte-identical A, but never reactivate A. Old
	// A's still-young receipt cannot resurrect across the new durable epoch.
	m = originalManifest
	m.PublicationEpoch = nodereceipt.Digest([]byte("publication-a-again"))
	b, _ = json.Marshal(m)
	if err := os.WriteFile(manifestPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	if result, err := s.Aggregate(context.Background(), m); err != nil || result.All {
		t.Fatalf("ABA revived A while B active: %+v %v", result, err)
	}
	for i := 0; i < 2; i++ {
		if err := c.Report(context.Background()); err == nil {
			t.Fatal("B active falsely acknowledged returned A")
		}
		if result, err := s.Aggregate(context.Background(), m); err != nil || result.All {
			t.Fatalf("ABA mismatch retained evidence: %+v %v", result, err)
		}
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := activate(path, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result, err := s.Aggregate(context.Background(), m); err != nil || !result.All {
		t.Fatalf("fresh A activation missing: %+v %v", result, err)
	}
}

func TestControllerReceiptRefusesSignedAssignmentEnforcer(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	e.signedAssignment = true
	if _, err := e.ActiveReceipt(); err == nil || !strings.Contains(err.Error(), "unsupported in signed fleet") {
		t.Fatalf("signed fleet runtime exposed controller receipt: %v", err)
	}
}

func TestReceiptPostureDoesNotConfuseLoadedLSMHooksWithEnforcement(t *testing.T) {
	for _, tc := range []struct {
		name        string
		opts        Options
		enforcement bool
	}{
		{"loaded-but-not-enforcing", Options{}, false},
		{"explicit-enforcing", Options{LSMEnforce: true}, true},
		{"audit-overrides-enforcing", Options{LSMEnforce: true, AuditMode: true}, false},
		{"learning-overrides-enforcing", Options{LSMEnforce: true, LearningMode: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateCacheDir(t)
			stubPlatform(t, &activationBootPlatform{pm: &fakePolicyMap{}}, nil)
			tc.opts.MetricsPort = -1
			e, err := New(context.Background(), testPolicyPath, &tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if e.activation.Posture.LSMEnforcement != tc.enforcement {
				t.Fatalf("loaded hooks misreported as enforcement: %+v", e.activation.Posture)
			}
		})
	}
}

func TestFailedKernelRollbackInvalidatesReceiptIdentity(t *testing.T) {
	isolateCacheDir(t)
	pm := &fakePolicyMap{}
	stubPlatform(t, &activationBootPlatform{pm: pm}, nil)
	e, err := New(context.Background(), testPolicyPath, &Options{LSMEnforce: true, MetricsPort: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.activation.Digest == "" {
		t.Fatal("startup missing activation identity")
	}
	pm.clearErr = errors.New("kernel clear and rollback failed")
	if err := e.ActivatePolicy(testPolicyPath, nil); err == nil {
		t.Fatal("kernel failure acknowledged")
	}
	if e.activation.Digest != "" {
		t.Fatal("degraded rollback retained acknowledged kernel state")
	}
	pm.clearErr = nil
	if err := e.ActivatePolicy(testPolicyPath, nil); err != nil {
		t.Fatal(err)
	}
	if e.activation.Digest == "" {
		t.Fatal("recovery did not restore identity")
	}
}
