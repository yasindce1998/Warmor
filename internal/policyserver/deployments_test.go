package policyserver

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/crypto/assignment"
)

func TestDeploymentRelayDurabilityLimitsTrustAndAuthorization(t *testing.T) {
	artifact, _ := crypto.GenerateSigningKey()
	signer, _ := crypto.GenerateSigningKey()
	wrong, _ := crypto.GenerateSigningKey()
	path := filepath.Join(t.TempDir(), "server.json")
	store, err := OpenStore(path, StoreOptions{VerifyKey: artifact.Public})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	target := assignment.Target{Scope: "tenant/prod", Audience: "node-1"}
	trust := assignment.Trust{"deployment": assignment.Key{Public: signer.Public, Target: target, CanRollback: true}}
	srv := NewServer(ServerConfig{Store: store, Insecure: true, AssignmentTrust: trust})
	now := time.Now().Unix()
	d := assignment.Deployment{Format: 1, KeyID: "deployment", Target: target, Policy: assignment.Policy{ID: "policy", Version: 1, SHA256: assignment.Digest([]byte("module")), ABI: 1, Compiler: "build", Posture: assignment.Posture{Mode: "audit", DefaultAction: "allow"}}, Sequence: 1, IssuedAt: now - 1, ExpiresAt: now + 60}
	bundle := func(d assignment.Deployment) assignment.Bundle {
		t.Helper()
		e, err := assignment.Sign(signer.Private, d)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := assignment.Encode(e)
		if err != nil {
			t.Fatal(err)
		}
		return assignment.Bundle{Envelope: wire, WASM: []byte("module"), ArtifactSignature: artifact.Sign([]byte("module"))}
	}
	post := func(b assignment.Bundle) int {
		t.Helper()
		wire, err := MarshalDeploymentBundle(b)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/admin/deployments", bytes.NewReader(wire)))
		return w.Code
	}
	b := bundle(d)
	if status := post(b); status != http.StatusCreated {
		t.Fatal(status)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(path, StoreOptions{VerifyKey: artifact.Public})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := assignment.DecodeBundle(store.deployment(target.Audience)); err != nil || !reflect.DeepEqual(got, b) {
		t.Fatalf("restore: %v", err)
	}
	srv = NewServer(ServerConfig{Store: store, Insecure: true, AssignmentTrust: trust})
	if status := post(b); status != http.StatusCreated {
		t.Fatal("identical upload should be idempotent", status)
	}
	d.Sequence = 2
	badArtifact := bundle(d)
	badArtifact.ArtifactSignature = wrong.Sign(badArtifact.WASM)
	if status := post(badArtifact); status != http.StatusForbidden {
		t.Fatal("bad artifact accepted", status)
	}
	d.Target.Audience = "another-node"
	if status := post(bundle(d)); status != http.StatusForbidden {
		t.Fatal("signer target grant bypassed", status)
	}
	d.Target = target
	d.Sequence = 1
	d.Policy.Version = 2
	if status := post(bundle(d)); status != http.StatusConflict {
		t.Fatal("same sequence equivocation accepted", status)
	}
	// Failed snapshot publication must not leak a replacement into memory.
	d.Sequence = 2
	next := bundle(d)
	before := store.deployment(target.Audience)
	oldPath := store.backend.path
	store.backend.path = filepath.Join(t.TempDir(), "missing", "state.json")
	if status := post(next); status != http.StatusConflict {
		t.Fatal(status)
	}
	if !bytes.Equal(before, store.deployment(target.Audience)) {
		t.Fatal("failed relay publication changed active bundle")
	}
	store.backend.path = oldPath
	store.limits.MaxRetainedWASMBytes = 1
	if status := post(next); status != http.StatusConflict {
		t.Fatal("relay bypassed retained artifact limits", status)
	}
	store.limits = DefaultStoreLimits()
	// An authenticated node cannot request another audience's signed bundle.
	if _, err := store.RegisterAgentChecked(&RegisterRequest{ID: target.Audience}); err != nil {
		t.Fatal(err)
	}
	secret := []byte("deployment-test-secret-which-is-long-enough")
	secure := NewServer(ServerConfig{Store: store, JWTSecret: secret, AssignmentTrust: trust})
	token, err := crypto.NewJWTIssuer(secret).Issue("node-2", "agent", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/deployment?agent_id=node-1", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	secure.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("cross-audience download accepted", w.Code, w.Body.String())
	}
}
