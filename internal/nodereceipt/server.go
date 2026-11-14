package nodereceipt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
)

type Config struct {
	Kube                                                      KubeAPI
	Audience, Namespace, ServiceAccount, DaemonSet, Container string
	// RequiredNodes is an explicit operator-owned desired roster, NOT a list
	// derived from currently online reporting pods. Missing nodes never shrink it.
	RequiredNodes []string
	Desired       func(context.Context) (Manifest, error)
	MaxAge        time.Duration
}

type session struct {
	principal principal
	challenge Challenge
	sequence  uint64
	receipt   *Receipt
	received  time.Time
}

func (v *session) fresh(now time.Time, maxAge time.Duration) bool {
	return v != nil && v.receipt != nil && now.Before(v.challenge.ExpiresAt) && !now.Before(v.received) && now.Sub(v.received) < maxAge && now.Sub(v.receipt.MeasuredAt) < maxAge && !v.receipt.MeasuredAt.After(now.Add(5*time.Second))
}

type Server struct {
	cfg      Config
	mu       sync.Mutex
	sessions map[string]*session // pod UID; memory only, reset on controller restart
	now      func() time.Time
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.Kube == nil || cfg.Desired == nil || cfg.Audience == "" || cfg.Namespace == "" || cfg.ServiceAccount == "" || cfg.DaemonSet == "" || cfg.Container == "" || len(cfg.RequiredNodes) == 0 || cfg.MaxAge < 10*time.Second || cfg.MaxAge > 5*time.Minute {
		return nil, fmt.Errorf("receipts require API, audience, daemon identity, explicit nonempty node roster and max age 10s..5m")
	}
	seen := map[string]bool{}
	for _, n := range cfg.RequiredNodes {
		if n == "" || seen[n] {
			return nil, fmt.Errorf("invalid required node roster")
		}
		seen[n] = true
	}
	cfg.RequiredNodes = append([]string(nil), cfg.RequiredNodes...)
	return &Server{cfg: cfg, sessions: map[string]*session{}, now: time.Now}, nil
}

func RandomEpoch() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Handler must be served directly over TLS. Proxy headers cannot bypass this.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "TLS required", http.StatusUpgradeRequired)
			return
		}
		if r.Method != http.MethodPost || (r.URL.Path != "/v1/node-receipts/register" && r.URL.Path != "/v1/node-receipts") {
			http.NotFound(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		token := bearer(r.Header.Get("Authorization"))
		if token == "" {
			http.Error(w, "bound pod token required", http.StatusUnauthorized)
			return
		}
		p, err := s.authenticate(ctx, token)
		if err != nil {
			http.Error(w, "unauthorized daemon identity", http.StatusUnauthorized)
			return
		}
		required := false
		for _, n := range s.cfg.RequiredNodes {
			required = required || n == p.nodeName
		}
		if !required {
			http.Error(w, "node outside desired roster", http.StatusForbidden)
			return
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10))
		dec.DisallowUnknownFields()
		decode := func(v any) bool {
			if dec.Decode(v) != nil {
				return false
			}
			return dec.Decode(new(any)) == io.EOF
		}
		if r.URL.Path == "/v1/node-receipts/register" {
			m, err := s.cfg.Desired(ctx)
			if err != nil || m.Validate() != nil {
				http.Error(w, "no eligible desired publication", http.StatusServiceUnavailable)
				return
			}
			var registration Registration
			if !decode(&registration) || len(registration.BootEpoch) != 64 {
				http.Error(w, "invalid boot epoch", http.StatusBadRequest)
				return
			}
			nonce, err := RandomEpoch()
			if err != nil {
				http.Error(w, "challenge unavailable", http.StatusServiceUnavailable)
				return
			}
			challenge := Challenge{Nonce: nonce, BootEpoch: registration.BootEpoch, ExpiresAt: s.now().Add(s.cfg.MaxAge), Manifest: m}
			s.mu.Lock()
			for uid, old := range s.sessions {
				if old.principal.nodeName == p.nodeName || !s.now().Before(old.challenge.ExpiresAt) {
					delete(s.sessions, uid)
				}
			}
			// Registration ALWAYS fences the previous boot/session and clears
			// its applied claim, including identical bytes after a restart.
			s.sessions[p.podUID] = &session{principal: p, challenge: challenge}
			s.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(challenge)
			return
		}
		var receipt Receipt
		if !decode(&receipt) {
			http.Error(w, "invalid receipt", http.StatusBadRequest)
			return
		}
		// A withdrawal does not depend on a healthy desired-publication read.
		// Even for positive reports, an API/read error must not preserve older
		// evidence once a valid, increasing current-session report is received.
		var m Manifest
		var desiredErr error
		if !receipt.Withdrawn {
			m, desiredErr = s.cfg.Desired(ctx)
		}
		now := s.now()
		s.mu.Lock()
		defer s.mu.Unlock()
		v := s.sessions[p.podUID]
		// FIRST establish current authenticated session, strictly increasing
		// sequence and freshness. Old/replayed negative or contradictory reports
		// must not revoke newer evidence (including another registration).
		if v == nil || v.principal != p || v.challenge.Nonce != receipt.Challenge || v.challenge.BootEpoch != receipt.BootEpoch || !now.Before(v.challenge.ExpiresAt) || receipt.Sequence == 0 || receipt.Sequence <= v.sequence || !receipt.MeasuredAt.After(now.Add(-s.cfg.MaxAge)) || receipt.MeasuredAt.After(now.Add(5*time.Second)) {
			http.Error(w, "receipt is outside current session or sequence", http.StatusConflict)
			return
		}
		v.sequence, v.receipt, v.received = receipt.Sequence, nil, time.Time{}
		if receipt.Withdrawn {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if desiredErr != nil || m.Validate() != nil {
			http.Error(w, "no eligible desired publication; previous evidence withdrawn", http.StatusServiceUnavailable)
			return
		}
		if v.challenge.Manifest.ID() != m.ID() || receipt.Manifest.ID() != m.ID() || receipt.Active.ActivatedAt.IsZero() || receipt.Active.ActivatedAt.After(receipt.MeasuredAt) || receipt.Active.Digest != m.Digest || receipt.Active.ABI != m.ABI || receipt.Active.Posture != m.Posture {
			http.Error(w, "receipt does not prove current registered activation", http.StatusConflict)
			return
		}
		v.sequence, v.receipt, v.received = receipt.Sequence, &receipt, now
		w.WriteHeader(http.StatusNoContent)
	})
}

// Aggregate fails closed on unverifiable/incomplete desired rosters and stale,
// missing, offline, replaced, restarting or duplicate daemon pods. No token is
// persisted. Every count is re-bound to synchronous Kubernetes identity reads.
func (s *Server) Aggregate(ctx context.Context, m Manifest) (Result, error) {
	result := Result{Required: len(s.cfg.RequiredNodes)}
	if err := m.Validate(); err != nil {
		return result, err
	}
	ds, err := s.cfg.Kube.DaemonSet(ctx, s.cfg.Namespace, s.cfg.DaemonSet)
	if err != nil || ds == nil || !s.validDaemonSet(ds) || ds.Status.ObservedGeneration != ds.Generation || int(ds.Status.DesiredNumberScheduled) != result.Required {
		return result, fmt.Errorf("desired daemon roster is unverified")
	}
	sa, err := s.cfg.Kube.ServiceAccount(ctx, s.cfg.Namespace, s.cfg.ServiceAccount)
	if err != nil || sa == nil || sa.Name != s.cfg.ServiceAccount || sa.Namespace != s.cfg.Namespace || sa.UID == "" || sa.DeletionTimestamp != nil {
		return result, fmt.Errorf("daemon service account unavailable")
	}
	// Listing alone is insufficient: each assigned pod and node is re-read by
	// name below. Reject paginated partial lists instead of treating as complete.
	pods, err := s.cfg.Kube.Pods(ctx, s.cfg.Namespace)
	if err != nil || pods == nil || pods.Continue != "" {
		return result, fmt.Errorf("daemon pods unavailable")
	}
	var identities []principal
	for _, name := range s.cfg.RequiredNodes {
		n, err := s.cfg.Kube.Node(ctx, name)
		if err != nil || n == nil || n.Name != name || n.UID == "" || n.DeletionTimestamp != nil {
			continue
		}
		ready := false
		for _, c := range n.Status.Conditions {
			if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
				ready = true
			}
		}
		if !ready {
			continue
		}
		var names []string
		for i := range pods.Items {
			p := &pods.Items[i]
			if p.Spec.NodeName == name && s.authorizedPod(p, ds) {
				names = append(names, p.Name)
			}
		}
		if len(names) != 1 {
			continue
		}
		p, err := s.cfg.Kube.Pod(ctx, s.cfg.Namespace, names[0])
		if err != nil || p == nil || p.Name != names[0] || p.Spec.NodeName != name || !s.authorizedPod(p, ds) {
			continue
		}
		identity := principal{p.Name, string(p.UID), name, string(n.UID), s.containerEpoch(p), string(sa.UID), string(ds.UID)}
		identities = append(identities, identity)
	}
	// Evaluate all sessions together AFTER the API reads. A concurrent new
	// registration must not leave an already-counted old session in the result.
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for _, identity := range identities {
		v := s.sessions[identity.podUID]
		if identity.container != "" && v.fresh(now, s.cfg.MaxAge) && v.principal == identity && v.receipt.Manifest.ID() == m.ID() {
			result.Applied++
			if result.Oldest.IsZero() || v.receipt.MeasuredAt.Before(result.Oldest) {
				result.Oldest = v.receipt.MeasuredAt
			}
			for _, expiry := range []time.Time{v.challenge.ExpiresAt, v.received.Add(s.cfg.MaxAge), v.receipt.MeasuredAt.Add(s.cfg.MaxAge)} {
				if result.ExpiresAt.IsZero() || expiry.Before(result.ExpiresAt) {
					result.ExpiresAt = expiry
				}
			}
		}
	}
	result.All = result.Required > 0 && result.Applied == result.Required
	if !result.ExpiresAt.IsZero() && !s.now().Before(result.ExpiresAt) {
		result.All = false
		result.Applied = 0
	}
	return result, nil
}
