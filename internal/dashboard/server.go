package dashboard

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	DefaultBind = "127.0.0.1"
	TokenEnv    = "WARMOR_DASHBOARD_TOKEN"
	maxTokenLen = 4096
)

// ServerConfig configures the optional dashboard listener. Bind must be a literal
// IP address (or localhost); wildcard/remote addresses are an explicit opt-in.
// Token, if nonempty, is the HTTP Basic password for the fixed user "warmor".
// TLS termination for remote access belongs on a trusted reverse proxy.
type ServerConfig struct {
	Bind  string
	Port  int
	Token string
}

// LoadToken reads an optional secret without exposing it in command-line arguments
// or URLs. Configured but empty/invalid sources fail closed. Restart to rotate it.
func LoadToken(file string) (string, error) {
	token, fromEnv := os.LookupEnv(TokenEnv)
	if file != "" {
		if fromEnv {
			return "", fmt.Errorf("set only one of %s and --dashboard-token-file", TokenEnv)
		}
		f, err := os.Open(file)
		if err != nil {
			return "", fmt.Errorf("open dashboard token file: %w", err)
		}
		defer f.Close()
		// Permit a trailing newline, but bound the amount read from a secret file.
		data, err := io.ReadAll(io.LimitReader(f, maxTokenLen+3))
		if err != nil {
			return "", fmt.Errorf("read dashboard token file: %w", err)
		}
		if len(data) > maxTokenLen+2 {
			return "", errors.New("dashboard token file is too large")
		}
		token = string(data)
		if strings.HasSuffix(token, "\n") {
			token = strings.TrimSuffix(strings.TrimSuffix(token, "\n"), "\r")
		}
	} else if !fromEnv {
		return "", nil
	}
	if err := validateToken(token); err != nil {
		return "", err
	}
	return token, nil
}

func validateToken(token string) error {
	if token == "" || len(token) > maxTokenLen || strings.IndexFunc(token, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0 {
		return errors.New("dashboard token must contain 1–4096 bytes with no whitespace or control characters")
	}
	return nil
}

// NewServer applies listener validation, optional browser-compatible authentication,
// and bounded request timeouts. WriteTimeout deliberately stays zero for SSE.
func NewServer(cfg ServerConfig, handler http.Handler) (*http.Server, error) {
	bind := cfg.Bind
	if bind == "localhost" {
		bind = DefaultBind
	}
	if net.ParseIP(bind) == nil {
		return nil, errors.New("dashboard bind must be an IP address or localhost (use 0.0.0.0 or :: explicitly for all interfaces)")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, errors.New("dashboard port must be between 1 and 65535")
	}
	if cfg.Token != "" {
		if err := validateToken(cfg.Token); err != nil {
			return nil, err
		}
	}
	return &http.Server{
		Addr:              net.JoinHostPort(bind, strconv.Itoa(cfg.Port)),
		Handler:           protect(handler, cfg.Token),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		// No WriteTimeout: /dashboard/events is a long-lived SSE stream.
	}, nil
}

func protect(next http.Handler, token string) http.Handler {
	want := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if token != "" {
			user, password, ok := r.BasicAuth()
			got := sha256.Sum256([]byte(password))
			matches := subtle.ConstantTimeCompare(got[:], want[:])
			if !ok || user != "warmor" || matches != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="Warmor dashboard", charset="UTF-8"`)
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
