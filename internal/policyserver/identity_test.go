package policyserver

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAgentIdentityAuthorization(t *testing.T) {
	for _, method := range []string{"jwt", "certificate"} {
		t.Run(method, func(t *testing.T) {
			s := NewServer(ServerConfig{JWTSecret: testJWTSecret})
			s.Store().RegisterAgent(&RegisterRequest{ID: "victim"})
			token, err := newJWTIssuerFromSecret(testJWTSecret).Issue("attacker", RoleAgent, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct{ method, path, body string }{
				{http.MethodPost, "/api/v1/register", `{"id":"victim","labels":{"env":"changed"}}`},
				{http.MethodPost, "/api/v1/heartbeat", `{"agent_id":"victim","policy_version":999}`},
				{http.MethodGet, "/api/v1/policy?agent_id=victim", ""},
			} {
				r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
				if method == "jwt" {
					r.Header.Set("Authorization", "Bearer "+token)
				} else {
					r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{Subject: pkix.Name{CommonName: "attacker"}}}}}
				}
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, r)
				if w.Code != http.StatusForbidden {
					t.Fatalf("%s: got %d: %s", tc.path, w.Code, w.Body.String())
				}
			}
			victim, _ := s.Store().GetAgent("victim")
			if victim.PolicyVersion != 0 || len(victim.Labels) != 0 {
				t.Fatalf("victim changed: %+v", victim)
			}
		})
	}
}

func TestAgentCanOnlyDownloadAssignedRevision(t *testing.T) {
	s, ts := setupAuthServer(t)
	path := writeWASM(t, t.TempDir(), "p.wasm", "version1")
	if err := s.Store().CreatePolicy(&Policy{ID: "assigned", Priority: 1}, path); err != nil {
		t.Fatal(err)
	}
	if err := s.Store().AddVersion("assigned", path, nil, true); err != nil {
		t.Fatal(err)
	}
	if err := s.Store().CreatePolicy(&Policy{ID: "other"}, path); err != nil {
		t.Fatal(err)
	}
	s.Store().RegisterAgent(&RegisterRequest{ID: "tester"})
	token := issueToken(t, testJWTSecret, RoleAgent, time.Minute)
	for _, tc := range []struct {
		query  string
		status int
	}{
		{"policy_id=assigned", http.StatusOK},
		{"policy_id=assigned&version=2", http.StatusOK},
		{"policy_id=assigned&version=1", http.StatusForbidden},
		{"policy_id=other", http.StatusForbidden},
	} {
		resp := doAuthRequest(t, http.MethodGet, ts.URL+"/api/v1/policy/wasm?"+tc.query, "Bearer "+token)
		if resp.StatusCode != tc.status {
			t.Errorf("%s: got %d, want %d", tc.query, resp.StatusCode, tc.status)
		}
	}
}

func TestCredentialsCannotUseCertificateToBypassTokenChecks(t *testing.T) {
	s := NewServer(ServerConfig{JWTSecret: testJWTSecret})
	for _, tc := range []struct {
		name, subject, role string
		want                int
	}{
		{"admin override", "operator", RoleAdmin, http.StatusOK},
		{"different agent", "other", RoleAgent, http.StatusForbidden},
		{"missing subject", "", RoleAgent, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, err := newJWTIssuerFromSecret(testJWTSecret).Issue(tc.subject, tc.role, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "/api/v1/register", strings.NewReader(`{"id":"agent-1"}`))
			r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{Subject: pkix.Name{CommonName: "agent-1"}}}}}
			r.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func TestCertificateRequiresNamedAgent(t *testing.T) {
	s := NewServer(ServerConfig{})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/register", strings.NewReader(`{"id":"agent-1"}`))
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}
