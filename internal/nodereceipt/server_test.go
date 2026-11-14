package nodereceipt_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/nodereceipt"
	"github.com/yasindce1998/warmor/internal/nodereceipt/receipttest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func manifest() nodereceipt.Manifest {
	return nodereceipt.Manifest{Version: 1, PublicationEpoch: nodereceipt.Digest([]byte("publication-a")), Revision: "effective:test", Digest: nodereceipt.Digest([]byte("active")), SnapshotDigest: nodereceipt.Digest([]byte("snapshot")), Compiler: "compiler/test", ABI: 3, Posture: nodereceipt.Posture{Audit: true}, Sources: []nodereceipt.Source{{Namespace: "security", Name: "policy", UID: "policy-uid", Generation: 1}}}
}

type fixture struct {
	k    *receipttest.Kube
	s    *nodereceipt.Server
	http *httptest.Server
	m    nodereceipt.Manifest
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{k: receipttest.NewKube(t), m: manifest()}
	s, err := nodereceipt.NewServer(receipttest.Config(f.k, func(context.Context) (nodereceipt.Manifest, error) { return f.m, nil }))
	if err != nil {
		t.Fatal(err)
	}
	f.s = s
	f.http = httptest.NewTLSServer(s.Handler())
	t.Cleanup(f.http.Close)
	return f
}

func (f *fixture) post(t *testing.T, path, token string, body, out any) int {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest(http.MethodPost, f.http.URL+path, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	resp, err := f.http.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode/100 == 2 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode
}

func (f *fixture) register(t *testing.T, epoch string) nodereceipt.Receipt {
	t.Helper()
	var challenge nodereceipt.Challenge
	if code := f.post(t, "/v1/node-receipts/register", "bound-token-a", nodereceipt.Registration{BootEpoch: epoch}, &challenge); code != 200 {
		t.Fatalf("register HTTP %d", code)
	}
	now := time.Now().UTC()
	return nodereceipt.Receipt{Challenge: challenge.Nonce, BootEpoch: epoch, Sequence: 1, MeasuredAt: now, Manifest: challenge.Manifest, Active: nodereceipt.Activation{Digest: f.m.Digest, ABI: f.m.ABI, Posture: f.m.Posture, ActivatedAt: now.Add(-time.Second)}}
}

func (f *fixture) all(t *testing.T, want bool) {
	t.Helper()
	result, err := f.s.Aggregate(context.Background(), f.m)
	if result.All != want {
		t.Fatalf("aggregate = %+v, err %v; want all=%t", result, err, want)
	}
	if want && (err != nil || result.Applied != 1 || result.Oldest.IsZero()) {
		t.Fatalf("bad successful aggregation: %+v %v", result, err)
	}
}

func TestAuthenticatedReceiptReplayRestartFences(t *testing.T) {
	f := setup(t)
	f.all(t, false)
	receipt := f.register(t, strings.Repeat("a", 64))
	f.all(t, false) // registration alone is NOT activation
	if code := f.post(t, "/v1/node-receipts", "bound-token-a", receipt, nil); code != 204 {
		t.Fatalf("receipt HTTP %d", code)
	}
	f.all(t, true)
	if code := f.post(t, "/v1/node-receipts", "bound-token-a", receipt, nil); code != 409 {
		t.Fatalf("replay accepted: %d", code)
	}
	newBoot := f.register(t, strings.Repeat("b", 64))
	f.all(t, false)
	receipt.Sequence++
	if code := f.post(t, "/v1/node-receipts", "bound-token-a", receipt, nil); code != 409 {
		t.Fatalf("old boot restored applied: %d", code)
	}
	if code := f.post(t, "/v1/node-receipts", "bound-token-a", newBoot, nil); code != 204 {
		t.Fatal(code)
	}
	f.all(t, true)
	// Kubernetes restart epoch independently fences a container restart in the
	// SAME pod, before the new process has had a chance to register.
	f.k.Mu.Lock()
	f.k.Pod.Status.ContainerStatuses[0].RestartCount++
	f.k.Mu.Unlock()
	f.all(t, false)
	newBoot.Sequence++
	if code := f.post(t, "/v1/node-receipts", "bound-token-a", newBoot, nil); code != 409 {
		t.Fatalf("previous container epoch accepted: %d", code)
	}
	// A controller restart loses all registrations/challenges, not just receipts.
	s, err := nodereceipt.NewServer(receipttest.Config(f.k, func(context.Context) (nodereceipt.Manifest, error) { return f.m, nil }))
	if err != nil {
		t.Fatal(err)
	}
	if result, err := s.Aggregate(context.Background(), f.m); err != nil || result.All {
		t.Fatalf("restart inherited applied: %+v %v", result, err)
	}
}

func TestRejectsIdentityForgeryUsingRealREST(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*receipttest.Kube)
	}{
		{"wrong-audience", func(k *receipttest.Kube) { k.Review.Audiences = []string{"kubernetes"} }},
		{"unauthenticated", func(k *receipttest.Kube) { k.Review.Authenticated = false }},
		{"review-error", func(k *receipttest.Kube) { k.Review.Error = "no" }},
		{"wrong-service-account", func(k *receipttest.Kube) { k.Review.User.Username = "system:serviceaccount:security:other" }},
		{"unbound-shared-sa-token", func(k *receipttest.Kube) { k.Review.User.Extra = nil }},
		{"recreated-pod-uid", func(k *receipttest.Kube) { k.Pod.UID = "replacement" }},
		{"recreated-sa-uid", func(k *receipttest.Kube) { k.SA.UID = "replacement" }},
		{"wrong-pod-sa", func(k *receipttest.Kube) { k.Pod.Spec.ServiceAccountName = "other" }},
		{"not-daemonset-owned", func(k *receipttest.Kube) { k.Pod.OwnerReferences = nil }},
		{"different-ds-uid", func(k *receipttest.Kube) { k.DS.UID = "other" }},
		{"terminating-pod", func(k *receipttest.Kube) { now := metav1.Now(); k.Pod.DeletionTimestamp = &now }},
		{"unassigned", func(k *receipttest.Kube) { k.Pod.Spec.NodeName = "" }},
		{"cannot-claim-another-node", func(k *receipttest.Kube) { k.Pod.Spec.NodeName = "node-b" }},
		{"not-running", func(k *receipttest.Kube) { k.Pod.Status.ContainerStatuses[0].State.Running = nil }},
		{"api-unavailable", func(k *receipttest.Kube) { k.Fail = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			f.k.Mu.Lock()
			tc.mutate(f.k)
			f.k.Mu.Unlock()
			code := f.post(t, "/v1/node-receipts/register", "bound-token-a", nodereceipt.Registration{BootEpoch: strings.Repeat("a", 64)}, nil)
			if code/100 == 2 {
				t.Fatalf("forged principal accepted: %d", code)
			}
			f.all(t, false)
		})
	}
	f := setup(t)
	// Even a correctly reviewed shared SA principal cannot add node args.
	if code := f.post(t, "/v1/node-receipts/register", "bound-token-a", map[string]any{"bootEpoch": strings.Repeat("a", 64), "nodeName": "node-b"}, nil); code != 400 {
		t.Fatalf("node arg accepted: %d", code)
	}
	if code := f.post(t, "/v1/node-receipts/register", "eyJ.fake.unverified", nodereceipt.Registration{BootEpoch: strings.Repeat("a", 64)}, nil); code != 401 {
		t.Fatalf("unreviewed JWT accepted: %d", code)
	}
}

func TestExactManifestActivePostureAndFreshness(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*nodereceipt.Receipt)
	}{
		{"stale", func(r *nodereceipt.Receipt) { r.MeasuredAt = time.Now().Add(-2 * time.Minute) }},
		{"future", func(r *nodereceipt.Receipt) { r.MeasuredAt = time.Now().Add(time.Minute) }},
		{"generation", func(r *nodereceipt.Receipt) { r.Manifest.Sources[0].Generation++ }},
		{"revision", func(r *nodereceipt.Receipt) { r.Manifest.Revision = "other" }},
		{"compiler", func(r *nodereceipt.Receipt) { r.Manifest.Compiler = "other" }},
		{"snapshot", func(r *nodereceipt.Receipt) { r.Manifest.SnapshotDigest = nodereceipt.Digest(nil) }},
		{"active-digest", func(r *nodereceipt.Receipt) { r.Active.Digest = nodereceipt.Digest(nil) }},
		{"abi", func(r *nodereceipt.Receipt) { r.Active.ABI++ }},
		{"posture", func(r *nodereceipt.Receipt) { r.Active.Posture.Audit = false }},
		{"preparation-only", func(r *nodereceipt.Receipt) { r.Active.ActivatedAt = time.Time{} }},
		{"zero-sequence", func(r *nodereceipt.Receipt) { r.Sequence = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			r := f.register(t, strings.Repeat("a", 64))
			tc.mutate(&r)
			if code := f.post(t, "/v1/node-receipts", "bound-token-a", r, nil); code != 409 {
				t.Fatalf("invalid receipt accepted: %d", code)
			}
			f.all(t, false)
		})
	}
}

func TestAggregateNeverAppliesOfflineReplacedOrUnverifiedRoster(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*receipttest.Kube)
	}{
		{"offline", func(k *receipttest.Kube) { k.Node.Status.Conditions[0].Status = corev1.ConditionUnknown }},
		{"node-replaced", func(k *receipttest.Kube) { k.Node.UID = "new-node" }},
		{"pod-replaced", func(k *receipttest.Kube) { k.Pod.UID = "new-pod" }},
		{"sa-replaced", func(k *receipttest.Kube) { k.SA.UID = "new-sa" }},
		{"ds-replaced-with-forged-pod-owner", func(k *receipttest.Kube) { k.DS.UID = "new-ds"; k.Pod.OwnerReferences[0].UID = "new-ds" }},
		{"pending", func(k *receipttest.Kube) { k.Pod.Status.Phase = corev1.PodPending }},
		{"zero-desired", func(k *receipttest.Kube) { k.DS.Status.DesiredNumberScheduled = 0 }},
		{"missing-node-roster", func(k *receipttest.Kube) { k.DS.Status.DesiredNumberScheduled = 2 }},
		{"unobserved-ds", func(k *receipttest.Kube) { k.DS.Generation++ }},
		{"duplicate-daemons", func(k *receipttest.Kube) {
			p := *k.Pod.DeepCopy()
			p.Name = "extra"
			p.UID = "extra"
			k.ExtraPods = []corev1.Pod{p}
		}},
		{"api-down", func(k *receipttest.Kube) { k.Fail = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			r := f.register(t, strings.Repeat("a", 64))
			if code := f.post(t, "/v1/node-receipts", "bound-token-a", r, nil); code != 204 {
				t.Fatal(code)
			}
			f.all(t, true)
			f.k.Mu.Lock()
			tc.mutate(f.k)
			f.k.Mu.Unlock()
			f.all(t, false)
		})
	}
	f := setup(t)
	cfg := receipttest.Config(f.k, func(context.Context) (nodereceipt.Manifest, error) { return f.m, nil })
	cfg.RequiredNodes = nil
	if _, err := nodereceipt.NewServer(cfg); err == nil {
		t.Fatal("empty required set enabled")
	}
}

func TestClientHTTPSManifestActiveBindingAndTokenRotation(t *testing.T) {
	f := setup(t)
	dir := t.TempDir()
	token, path := filepath.Join(dir, "token"), filepath.Join(dir, "manifest.json")
	write := func(path string, b []byte) {
		t.Helper()
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(token, []byte("bound-token-a"))
	b, _ := json.Marshal(f.m)
	write(path, b)
	active := nodereceipt.Activation{Digest: f.m.Digest, ABI: f.m.ABI, Posture: f.m.Posture, ActivatedAt: time.Now().Add(-time.Second)}
	cfg := nodereceipt.ClientConfig{URL: f.http.URL, TokenPath: token, ManifestPath: path, TLS: receipttest.Trust(f.http), Active: func() (nodereceipt.Activation, error) { return active, nil }}
	c, err := nodereceipt.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	untrusted := cfg
	untrusted.TLS = nil
	untrustedClient, err := nodereceipt.NewClient(untrusted)
	if err != nil {
		t.Fatal(err)
	}
	if err := untrustedClient.Report(context.Background()); err == nil {
		t.Fatal("untrusted controller certificate accepted")
	}
	insecure := cfg
	insecure.TLS = &tls.Config{InsecureSkipVerify: true} // test must reject bypass
	if _, err := nodereceipt.NewClient(insecure); err == nil {
		t.Fatal("TLS identity bypass accepted")
	}
	if err := c.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.all(t, true)
	active.Digest = nodereceipt.Digest([]byte("downloaded-but-not-active"))
	if err := c.Report(context.Background()); err == nil {
		t.Fatal("non-active digest acknowledged")
	}
	f.all(t, false) // the locally rejected report must withdraw old server evidence
	active.Digest = f.m.Digest
	// Rotated invalid token must be used rather than an in-memory token cache.
	write(token, []byte("expired-token"))
	if err := c.Report(context.Background()); err == nil {
		t.Fatal("token rotation ignored")
	}
	write(token, []byte("bound-token-a"))
	if err := c.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.all(t, true)
	cfg.URL = "http://127.0.0.1:1234"
	if _, err := nodereceipt.NewClient(cfg); err == nil {
		t.Fatal("plaintext client enabled")
	}
	r := httptest.NewRequest(http.MethodPost, "http://controller/v1/node-receipts", nil)
	w := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(w, r)
	if w.Code != 426 {
		t.Fatal("plaintext endpoint enabled")
	}
}
