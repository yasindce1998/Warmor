package policyserver

import (
	"crypto/tls"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/yasindce1998/warmor/internal/crypto"
)

// JWT roles accepted by the server.
const (
	RoleAdmin   = "admin"
	RoleAgent   = "agent"
	RoleRuntime = "runtime"
)

type jwtIssuer struct {
	inner *crypto.JWTIssuer
}

func newJWTIssuerFromSecret(secret []byte) *jwtIssuer {
	return &jwtIssuer{inner: crypto.NewJWTIssuer(secret)}
}

func (j *jwtIssuer) Issue(subject, role string, ttl time.Duration) (string, error) {
	return j.inner.Issue(subject, role, ttl)
}

func (j *jwtIssuer) Validate(token string) (*crypto.JWTClaims, error) {
	return j.inner.Validate(token)
}

// mtlsEnabled reports whether the server verifies client certificates.
func (s *Server) mtlsEnabled() bool {
	return s.tlsConfig != nil && s.tlsConfig.ClientCAs != nil &&
		(s.tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert || s.tlsConfig.ClientAuth == tls.VerifyClientCertIfGiven)
}

// checkAuthConfig refuses configurations that would leave the API
// unauthenticated unless insecure mode was explicitly requested.
func (s *Server) checkAuthConfig() error {
	if len(s.jwtSecret) > 0 || s.mtlsEnabled() || s.insecure {
		return nil
	}
	return errors.New("no authentication configured: set a JWT secret or a TLS config that verifies client certificates (or enable insecure mode for development only)")
}

// requireJWT restricts a handler to admin bearer tokens.
func (s *Server) requireJWT(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(false, []string{RoleAdmin}, next)
}

// requireAgent restricts a handler to agents: a verified client certificate
// or a bearer token with the agent (or admin) role.
func (s *Server) requireAgent(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(true, []string{RoleAgent, RoleAdmin}, next)
}

// requireRuntime restricts a handler to container runtimes: a verified
// client certificate or a bearer token with the runtime (or admin) role.
func (s *Server) requireRuntime(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(true, []string{RoleRuntime, RoleAdmin}, next)
}

func (s *Server) requireAuth(allowCert bool, roles []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if allowCert && r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
			next(w, r)
			return
		}

		if s.jwt == nil {
			// Without a JWT secret there is no way to present credentials
			// other than a client certificate.
			if s.insecure {
				next(w, r)
				return
			}
			unauthorized(w, "authentication required")
			return
		}

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			unauthorized(w, "missing authorization")
			return
		}

		claims, err := s.jwt.Validate(strings.TrimPrefix(auth, "Bearer "))
		if err != nil {
			unauthorized(w, "invalid token: "+err.Error())
			return
		}

		if !slices.Contains(roles, claims.Role) {
			http.Error(w, strings.Join(roles, " or ")+" role required", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}

func unauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, msg, http.StatusUnauthorized)
}
