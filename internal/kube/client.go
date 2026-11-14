// Package kube is a minimal Kubernetes API client built on net/http.
//
// The controller needs five operations (list/watch a custom resource,
// create/update a ConfigMap, update a status subresource) and the repo
// carries no Kubernetes Go dependencies; pulling in client-go (and its
// ~100 transitive modules) for that is not worth the dependency weight.
// The API server is just JSON over HTTPS, so this client speaks exactly
// the REST paths the controller uses and nothing more.
package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// serviceAccountDir is where the kubelet projects the pod's service
// account credentials (token, CA, namespace).
const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// Config holds everything needed to talk to an API server.
type Config struct {
	// BaseURL is the API server root, e.g. https://10.0.0.1:6443.
	BaseURL string
	// Token returns a bearer token. It is called for every request so
	// projected service account tokens (which rotate hourly) are picked
	// up without a restart.
	Token func() (string, error)
	// TLS configures the HTTPS transport (CA pool, client certificates).
	TLS *tls.Config
}

// InClusterConfig returns the configuration from the pod's service
// account, or ok=false when not running in a cluster.
func InClusterConfig() (cfg *Config, ok bool) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	tokenPath := filepath.Join(serviceAccountDir, "token")
	if host == "" || port == "" {
		return nil, false
	}
	if _, err := os.Stat(tokenPath); err != nil {
		return nil, false
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPEM, err := os.ReadFile(filepath.Join(serviceAccountDir, "ca.crt")); err == nil {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(caPEM) {
			tlsCfg.RootCAs = pool
		}
	}

	// The token file is re-read per request: projected tokens are
	// refreshed by the kubelet and the claims (and file) change over time.
	token := func() (string, error) {
		b, err := os.ReadFile(tokenPath)
		if err != nil {
			return "", fmt.Errorf("read service account token: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return &Config{
		BaseURL: "https://" + host + ":" + port,
		Token:   token,
		TLS:     tlsCfg,
	}, true
}

// PodNamespace returns the namespace the pod runs in ("default" when
// unknown, e.g. outside a cluster).
func PodNamespace() string {
	if b, err := os.ReadFile(filepath.Join(serviceAccountDir, "namespace")); err == nil {
		if ns := strings.TrimSpace(string(b)); ns != "" {
			return ns
		}
	}
	return "default"
}

// Client is a minimal Kubernetes REST client. Its methods are safe for
// concurrent use.
type Client struct {
	cfg  *Config
	http *http.Client
}

// New builds a client for cfg.
func New(cfg *Config) *Client {
	// No client-level timeout: watch requests stream for minutes. CRUD
	// callers pass per-request contexts instead. The dialer carries an
	// explicit timeout so a blackholed TCP connect (e.g. stale kube-proxy
	// rules after an apiserver restart, or a dead pod network) fails in
	// seconds instead of waiting out the kernel's SYN retries (~2 minutes
	// or more) while the controller looks hung.
	transport := &http.Transport{
		TLSClientConfig:       cfg.TLS,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	return &Client{cfg: cfg, http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		// Kubernetes REST resources never require redirects. In particular do
		// not redirect authentication operations or bearer credentials.
		return fmt.Errorf("Kubernetes API redirects refused")
	}}}
}

// StatusError is a non-2xx API server response.
type StatusError struct {
	Code    int
	Reason  string
	Message string
}

func (e *StatusError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("kube api: %s", e.Message)
	}
	return fmt.Sprintf("kube api: %d %s", e.Code, e.Reason)
}

// IsNotFound reports whether err is a 404 from the API server.
func IsNotFound(err error) bool {
	se, ok := err.(*StatusError)
	return ok && se.Code == http.StatusNotFound
}

// apiError is the API server's error payload (metav1.Status shape).
type apiError struct {
	Message string `json:"message"`
	Reason  string `json:"reason"`
	Code    int    `json:"code"`
}

// request performs one API call. body, when non-nil, is JSON-encoded as
// the request body; a 2xx response, when out is non-nil, is decoded into
// out.
func (c *Client) request(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cfg.Token != nil {
		token, err := c.cfg.Token()
		if err != nil {
			return err
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var se apiError
		_ = json.NewDecoder(resp.Body).Decode(&se)
		if se.Code == 0 {
			se.Code = resp.StatusCode
		}
		return &StatusError{Code: se.Code, Reason: se.Reason, Message: se.Message}
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// Get fetches the object at path into out.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.request(ctx, http.MethodGet, path, nil, out)
}

// Create posts body at path; the created object is decoded into out when
// non-nil.
func (c *Client) Create(ctx context.Context, path string, body, out any) error {
	return c.request(ctx, http.MethodPost, path, body, out)
}

// Update puts body at path; the stored object is decoded into out when
// non-nil.
func (c *Client) Update(ctx context.Context, path string, body, out any) error {
	return c.request(ctx, http.MethodPut, path, body, out)
}

// WatchEvent is one item from a watch stream.
type WatchEvent struct {
	// Type is ADDED, MODIFIED, DELETED, BOOKMARK or ERROR.
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

// Watch opens a watch on path (which must carry ?watch=true&resourceVersion=...)
// and calls fn for every event until the stream ends, fn returns an error,
// or ctx is done. The caller is expected to re-list and re-watch after it
// returns: this is a level-triggered helper, not an informer.
func (c *Client) Watch(ctx context.Context, path string, fn func(WatchEvent) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if c.cfg.Token != nil {
		token, err := c.cfg.Token()
		if err != nil {
			return err
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var se apiError
		_ = json.NewDecoder(resp.Body).Decode(&se)
		if se.Code == 0 {
			se.Code = resp.StatusCode
		}
		return &StatusError{Code: se.Code, Reason: se.Reason, Message: se.Message}
	}

	dec := json.NewDecoder(resp.Body)
	for {
		var ev WatchEvent
		if err := dec.Decode(&ev); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err == io.EOF {
				// The server closed the stream — normally its
				// timeoutSeconds deadline expiring. Callers re-list.
				return nil
			}
			return fmt.Errorf("watch stream: %w", err)
		}
		if err := fn(ev); err != nil {
			return err
		}
	}
}
