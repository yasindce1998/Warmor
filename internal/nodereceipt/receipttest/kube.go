// Package receipttest provides an owned HTTPS fake Kubernetes API. It never
// reads kubeconfig, requests real credentials or contacts a live cluster.
package receipttest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/kube"
	"github.com/yasindce1998/warmor/internal/nodereceipt"
	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const Audience = "warmor-receipts-test"

type Kube struct {
	Mu          sync.Mutex
	Review      authv1.TokenReviewStatus
	Pod         corev1.Pod
	Node        corev1.Node
	SA          corev1.ServiceAccount
	DS          appsv1.DaemonSet
	Fail        bool
	ExtraPods   []corev1.Pod
	OtherNodes  []corev1.Node
	Tokens      map[string]authv1.TokenReviewStatus
	ReviewCalls int
	Client      *kube.Client
	REST        nodereceipt.RESTKube
}

func Trust(server *httptest.Server) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
}

func NewKube(t testing.TB) *Kube {
	t.Helper()
	yes := true
	f := &Kube{
		Review: authv1.TokenReviewStatus{Authenticated: true, Audiences: []string{Audience}, User: authv1.UserInfo{Username: "system:serviceaccount:security:daemon", UID: "sa-uid", Extra: map[string]authv1.ExtraValue{"authentication.kubernetes.io/pod-name": {"daemon-a"}, "authentication.kubernetes.io/pod-uid": {"pod-a"}}}},
		SA:     corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "daemon", Namespace: "security", UID: "sa-uid"}},
		DS:     appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "daemon", Namespace: "security", UID: "ds-uid", Generation: 1}, Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "daemon"}}}, Status: appsv1.DaemonSetStatus{ObservedGeneration: 1, DesiredNumberScheduled: 1}},
		Pod:    corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "daemon-a", Namespace: "security", UID: "pod-a", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "DaemonSet", Name: "daemon", UID: "ds-uid", Controller: &yes}}}, Spec: corev1.PodSpec{ServiceAccountName: "daemon", NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "warmor", ContainerID: "fake://container-1", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(time.Now().Add(-time.Minute))}}}}}},
		Node:   corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: "node-uid"}, Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.Mu.Lock()
		defer f.Mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer controller-test" {
			t.Errorf("missing controller API credentials")
			w.WriteHeader(401)
			return
		}
		if f.Fail {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		if r.Method == http.MethodPost && r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews" {
			var review authv1.TokenReview
			if json.NewDecoder(r.Body).Decode(&review) != nil || review.Kind != "TokenReview" || review.APIVersion != "authentication.k8s.io/v1" || len(review.Spec.Audiences) != 1 || review.Spec.Audiences[0] != Audience {
				t.Errorf("invalid real TokenReview request")
				w.WriteHeader(400)
				return
			}
			f.ReviewCalls++
			if status, ok := f.Tokens[review.Spec.Token]; ok {
				write(authv1.TokenReview{Status: status})
				return
			}
			if review.Spec.Token != "bound-token-a" {
				write(authv1.TokenReview{Status: authv1.TokenReviewStatus{Authenticated: false}})
				return
			}
			write(authv1.TokenReview{Status: f.Review})
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(405)
			return
		}
		switch r.URL.Path {
		case "/api/v1/namespaces/security/serviceaccounts/daemon":
			write(f.SA)
		case "/apis/apps/v1/namespaces/security/daemonsets/daemon":
			write(f.DS)
		case "/api/v1/namespaces/security/pods/daemon-a":
			write(f.Pod)
		case "/api/v1/namespaces/security/pods":
			pods := append([]corev1.Pod{f.Pod}, f.ExtraPods...)
			write(corev1.PodList{Items: pods})
		case "/api/v1/nodes/node-a":
			write(f.Node)
		default:
			for _, pod := range f.ExtraPods {
				if r.URL.Path == "/api/v1/namespaces/security/pods/"+pod.Name {
					write(pod)
					return
				}
			}
			for _, node := range f.OtherNodes {
				if r.URL.Path == "/api/v1/nodes/"+node.Name {
					write(node)
					return
				}
			}
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	f.Client = kube.New(&kube.Config{BaseURL: server.URL, TLS: Trust(server), Token: func() (string, error) { return "controller-test", nil }})
	f.REST = nodereceipt.RESTKube{Client: f.Client}
	return f
}

func Config(f *Kube, desired func(context.Context) (nodereceipt.Manifest, error)) nodereceipt.Config {
	return nodereceipt.Config{Kube: f.REST, Audience: Audience, Namespace: "security", ServiceAccount: "daemon", DaemonSet: "daemon", Container: "warmor", RequiredNodes: []string{"node-a"}, MaxAge: time.Minute, Desired: desired}
}
