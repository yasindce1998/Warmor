package nodereceipt_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/nodereceipt"
	"github.com/yasindce1998/warmor/internal/nodereceipt/receipttest"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
)

func TestSharedServiceAccountCannotSatisfyAnotherRequiredNode(t *testing.T) {
	f := &fixture{k: receipttest.NewKube(t), m: manifest()}
	f.k.Mu.Lock()
	podB := *f.k.Pod.DeepCopy()
	podB.Name = "daemon-b"
	podB.UID = "pod-b"
	podB.Spec.NodeName = "node-b"
	nodeB := *f.k.Node.DeepCopy()
	nodeB.Name = "node-b"
	nodeB.UID = "node-b-uid"
	f.k.ExtraPods = []corev1.Pod{podB}
	f.k.OtherNodes = []corev1.Node{nodeB}
	reviewB := *f.k.Review.DeepCopy()
	reviewB.User.Extra["authentication.kubernetes.io/pod-name"] = authv1.ExtraValue{"daemon-b"}
	reviewB.User.Extra["authentication.kubernetes.io/pod-uid"] = authv1.ExtraValue{"pod-b"}
	f.k.Tokens = map[string]authv1.TokenReviewStatus{"bound-token-b": reviewB}
	f.k.DS.Status.DesiredNumberScheduled = 2
	f.k.Mu.Unlock()
	cfg := receipttest.Config(f.k, func(context.Context) (nodereceipt.Manifest, error) { return f.m, nil })
	cfg.RequiredNodes = []string{"node-a", "node-b"}
	var err error
	f.s, err = nodereceipt.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.http = httptest.NewTLSServer(f.s.Handler())
	defer f.http.Close()
	a := f.register(t, strings.Repeat("a", 64))
	if code := f.post(t, "/v1/node-receipts", "bound-token-a", a, nil); code != 204 {
		t.Fatal(code)
	}
	result, err := f.s.Aggregate(context.Background(), f.m)
	if err != nil || result.All || result.Required != 2 || result.Applied != 1 {
		t.Fatalf("one node satisfied two-node roster: %+v %v", result, err)
	}
	var b nodereceipt.Challenge
	if code := f.post(t, "/v1/node-receipts/register", "bound-token-b", nodereceipt.Registration{BootEpoch: strings.Repeat("b", 64)}, &b); code != 200 {
		t.Fatal(code)
	}
	// Even if node A learns B's challenge, the shared SA username does not
	// authorize A's bound token as B's Pod UID/node. No client identity args.
	receiptB := a
	receiptB.Challenge = b.Nonce
	receiptB.BootEpoch = b.BootEpoch
	receiptB.MeasuredAt = time.Now().UTC()
	if code := f.post(t, "/v1/node-receipts", "bound-token-a", receiptB, nil); code != 409 {
		t.Fatalf("shared SA claimed arbitrary node receipt: %d", code)
	}
	if code := f.post(t, "/v1/node-receipts", "bound-token-b", receiptB, nil); code != 204 {
		t.Fatal(code)
	}
	result, err = f.s.Aggregate(context.Background(), f.m)
	if err != nil || !result.All || result.Applied != 2 {
		t.Fatalf("complete roster not acknowledged: %+v %v", result, err)
	}
	f.k.Mu.Lock()
	f.k.OtherNodes[0].Status.Conditions[0].Status = corev1.ConditionUnknown
	f.k.Mu.Unlock()
	result, err = f.s.Aggregate(context.Background(), f.m)
	if err != nil || result.All || result.Required != 2 || result.Applied != 1 {
		t.Fatalf("offline node silently dropped from desired roster: %+v %v", result, err)
	}
}
