package nodereceipt

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/yasindce1998/warmor/internal/kube"
	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KubeAPI must use authoritative synchronous reads, not informer cache or
// unverified JWT claims. RESTKube implements the actual Kubernetes REST API.
type KubeAPI interface {
	Review(context.Context, string, string) (*authv1.TokenReview, error)
	Pod(context.Context, string, string) (*corev1.Pod, error)
	ServiceAccount(context.Context, string, string) (*corev1.ServiceAccount, error)
	DaemonSet(context.Context, string, string) (*appsv1.DaemonSet, error)
	Node(context.Context, string) (*corev1.Node, error)
	Pods(context.Context, string) (*corev1.PodList, error)
}

type RESTKube struct{ Client *kube.Client }

func (k RESTKube) Review(ctx context.Context, token, audience string) (*authv1.TokenReview, error) {
	out := new(authv1.TokenReview)
	err := k.Client.Create(ctx, "/apis/authentication.k8s.io/v1/tokenreviews", &authv1.TokenReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"},
		Spec:     authv1.TokenReviewSpec{Token: token, Audiences: []string{audience}},
	}, out)
	return out, err
}
func (k RESTKube) Pod(ctx context.Context, ns, name string) (*corev1.Pod, error) {
	out := new(corev1.Pod)
	err := k.Client.Get(ctx, "/api/v1/namespaces/"+url.PathEscape(ns)+"/pods/"+url.PathEscape(name), out)
	return out, err
}
func (k RESTKube) ServiceAccount(ctx context.Context, ns, name string) (*corev1.ServiceAccount, error) {
	out := new(corev1.ServiceAccount)
	err := k.Client.Get(ctx, "/api/v1/namespaces/"+url.PathEscape(ns)+"/serviceaccounts/"+url.PathEscape(name), out)
	return out, err
}
func (k RESTKube) DaemonSet(ctx context.Context, ns, name string) (*appsv1.DaemonSet, error) {
	out := new(appsv1.DaemonSet)
	err := k.Client.Get(ctx, "/apis/apps/v1/namespaces/"+url.PathEscape(ns)+"/daemonsets/"+url.PathEscape(name), out)
	return out, err
}
func (k RESTKube) Node(ctx context.Context, name string) (*corev1.Node, error) {
	out := new(corev1.Node)
	err := k.Client.Get(ctx, "/api/v1/nodes/"+url.PathEscape(name), out)
	return out, err
}
func (k RESTKube) Pods(ctx context.Context, ns string) (*corev1.PodList, error) {
	out := new(corev1.PodList)
	err := k.Client.Get(ctx, "/api/v1/namespaces/"+url.PathEscape(ns)+"/pods", out)
	return out, err
}

type principal struct {
	podName, podUID, nodeName, nodeUID, container, serviceAccountUID, daemonSetUID string
}

func (s *Server) authenticate(ctx context.Context, token string) (principal, error) {
	deny := fmt.Errorf("bound daemon pod identity could not be verified")
	r, err := s.cfg.Kube.Review(ctx, token, s.cfg.Audience)
	if err != nil || r == nil || !r.Status.Authenticated || r.Status.Error != "" {
		return principal{}, deny
	}
	audienceOK := false
	for _, a := range r.Status.Audiences {
		audienceOK = audienceOK || a == s.cfg.Audience
	}
	u := r.Status.User
	if !audienceOK || u.Username != "system:serviceaccount:"+s.cfg.Namespace+":"+s.cfg.ServiceAccount {
		return principal{}, deny
	}
	// These extras are returned by the authenticator after validating the bound
	// token. Legacy/unbound SA tokens and node-name JWT hints are never enough.
	name, uid := u.Extra["authentication.kubernetes.io/pod-name"], u.Extra["authentication.kubernetes.io/pod-uid"]
	if len(name) != 1 || len(uid) != 1 || name[0] == "" || uid[0] == "" {
		return principal{}, deny
	}
	sa, err := s.cfg.Kube.ServiceAccount(ctx, s.cfg.Namespace, s.cfg.ServiceAccount)
	if err != nil || sa == nil || sa.Name != s.cfg.ServiceAccount || sa.Namespace != s.cfg.Namespace || sa.DeletionTimestamp != nil || string(sa.UID) == "" || string(sa.UID) != u.UID {
		return principal{}, deny
	}
	ds, err := s.cfg.Kube.DaemonSet(ctx, s.cfg.Namespace, s.cfg.DaemonSet)
	if err != nil || ds == nil || !s.validDaemonSet(ds) {
		return principal{}, deny
	}
	p, err := s.cfg.Kube.Pod(ctx, s.cfg.Namespace, name[0])
	if err != nil || p == nil || p.Name != name[0] || string(p.UID) != uid[0] || !s.authorizedPod(p, ds) {
		return principal{}, deny
	}
	n, err := s.cfg.Kube.Node(ctx, p.Spec.NodeName)
	if err != nil || n == nil || n.Name != p.Spec.NodeName || n.UID == "" || n.DeletionTimestamp != nil {
		return principal{}, deny
	}
	c := s.containerEpoch(p)
	if c == "" {
		return principal{}, deny
	}
	return principal{p.Name, string(p.UID), n.Name, string(n.UID), c, string(sa.UID), string(ds.UID)}, nil
}

func (s *Server) validDaemonSet(ds *appsv1.DaemonSet) bool {
	return ds.Name == s.cfg.DaemonSet && ds.Namespace == s.cfg.Namespace && ds.UID != "" && ds.DeletionTimestamp == nil && ds.Spec.Template.Spec.ServiceAccountName == s.cfg.ServiceAccount
}

func (s *Server) authorizedPod(p *corev1.Pod, ds *appsv1.DaemonSet) bool {
	if p.Namespace != s.cfg.Namespace || p.UID == "" || p.DeletionTimestamp != nil || p.Spec.ServiceAccountName != s.cfg.ServiceAccount || p.Spec.NodeName == "" || p.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, owner := range p.OwnerReferences {
		if owner.Controller != nil && *owner.Controller && owner.APIVersion == "apps/v1" && owner.Kind == "DaemonSet" && owner.Name == ds.Name && owner.UID == ds.UID {
			return true
		}
	}
	return false
}

func (s *Server) containerEpoch(p *corev1.Pod) string {
	for _, c := range p.Status.ContainerStatuses {
		if c.Name == s.cfg.Container && c.ContainerID != "" && c.State.Running != nil {
			return fmt.Sprintf("%s/%d/%s", c.ContainerID, c.RestartCount, c.State.Running.StartedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"))
		}
	}
	return ""
}

func bearer(header string) string {
	parts := strings.Fields(header)
	if len(parts) != 2 || parts[0] != "Bearer" || len(parts[1]) > 16384 {
		return ""
	}
	return parts[1]
}
