package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/kube"
	"github.com/yasindce1998/warmor/internal/nodereceipt"
	"github.com/yasindce1998/warmor/internal/nodereceipt/receipttest"
)

// Real HTTPS receipt client/endpoint and real Kubernetes REST calls against
// owned fakes; compilation is stubbed, so this is not kernel enforcement proof.
func TestAuthenticatedReceiptStatusExactAcceptedGeneration(t *testing.T) {
	_, restore := stubCompile(t)
	defer restore()
	api := newFakeAPI()
	cr := testCR("alpha", nil)
	api.addCR(cr)
	apiServer := httptest.NewTLSServer(api.handler(t))
	defer apiServer.Close()
	apiClient := kube.New(&kube.Config{BaseURL: apiServer.URL, TLS: receipttest.Trust(apiServer)})
	opts := Options{Namespace: "warmor-system", ConfigMapNamespace: "warmor-system", ConfigMapName: "warmor-effective-policy"}
	ctl := New(apiClient, opts)
	k := receipttest.NewKube(t)
	posture := nodereceipt.Posture{Audit: true}
	if err := ctl.EnableReceipts(receipttest.Config(k, nil), posture); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(ctl.ReceiptHandler())
	defer server.Close()
	reconcile := func() {
		t.Helper()
		if _, err := ctl.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	assertApplied := func(want bool) {
		t.Helper()
		s := api.policies["warmor-system/alpha"].Status
		applied := false
		for _, c := range s.Conditions {
			if c.Type == "Applied" {
				applied = c.Status == "True"
			}
		}
		if applied != want {
			t.Fatalf("status = %+v; want applied=%t", s, want)
		}
		if !want && (s.LastApplied != "" || s.NodesApplied != 0 || s.Phase == PhaseActive) {
			t.Fatalf("unverified activation claimed: %+v", s)
		}
		if want && (s.LastApplied == "" || s.NodesApplied != 1 || s.Phase != PhaseActive) {
			t.Fatalf("valid receipt not reflected: %+v", s)
		}
		if want {
			expires, err := time.Parse(time.RFC3339Nano, s.ReceiptExpiresAt)
			if err != nil || !time.Now().Before(expires) {
				t.Fatalf("missing fresh evidence expiry: %s", s.ReceiptExpiresAt)
			}
		}
	}
	reconcile()
	assertApplied(false)
	m, err := ctl.publishedManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	manifestPath, tokenPath := filepath.Join(dir, "manifest.json"), filepath.Join(dir, "token")
	writeManifest := func(m nodereceipt.Manifest) {
		t.Helper()
		b, _ := json.Marshal(m)
		if err := os.WriteFile(manifestPath, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeManifest(m)
	if err := os.WriteFile(tokenPath, []byte("bound-token-a"), 0600); err != nil {
		t.Fatal(err)
	}
	active := nodereceipt.Activation{Digest: m.Digest, ABI: m.ABI, Posture: posture, ActivatedAt: time.Now().Add(-time.Second)}
	client, err := nodereceipt.NewClient(nodereceipt.ClientConfig{URL: server.URL, TLS: receipttest.Trust(server), TokenPath: tokenPath, ManifestPath: manifestPath, Active: func() (nodereceipt.Activation, error) { return active, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	reconcile()
	assertApplied(true)
	k.Mu.Lock()
	k.Fail = true
	k.Mu.Unlock()
	reconcile()
	assertApplied(false)
	k.Mu.Lock()
	k.Fail = false
	k.Mu.Unlock()
	reconcile()
	assertApplied(true)
	// A new accepted source generation with byte-identical compiled output
	// MUST revoke the previous receipt; revision+digest alone is insufficient.
	cr.Metadata.Generation++
	cr.Spec.Description = "same output; newly accepted generation"
	reconcile()
	assertApplied(false)
	newManifest, err := ctl.publishedManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if newManifest.Digest != m.Digest || newManifest.ID() == m.ID() {
		t.Fatal("fixture did not exercise exact generation with identical bytes")
	}
	writeManifest(newManifest)
	// Existing challenge is obsolete, then a new registration may succeed.
	_ = client.Report(context.Background())
	if err := client.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	reconcile()
	assertApplied(true)
	// Selectors remain Pending; last known good activation never blesses a
	// desired selector edit, even with a verified current receipt.
	cr.Metadata.Generation++
	cr.Spec.Selector = &Selector{}
	reconcile()
	assertApplied(false)
	if cr.Status.Phase != PhasePending {
		t.Fatalf("selector phase %s", cr.Status.Phase)
	}
	cr.Spec.Selector = nil
	cr.Metadata.Generation++
	reconcile()
	assertApplied(false)
	// Controller restarts cannot inherit the previous process's receipt map.
	restarted := New(apiClient, opts)
	if err := restarted.EnableReceipts(receipttest.Config(k, nil), posture); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertApplied(false)
	// Default controller handler never accidentally exposes the HTTPS route.
	w := httptest.NewRecorder()
	ctl.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/node-receipts", nil))
	if w.Code != 404 {
		t.Fatal("receipt endpoint exposed on metrics listener")
	}
}
