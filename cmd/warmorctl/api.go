package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// apiTLSConfig, when non-nil, is used for every admin API connection. main
// sets it from --ca-cert / --client-cert / --client-key.
var apiTLSConfig *tls.Config

// loadTLSConfig builds the client TLS config for the policy server: caFile
// pins the CA that signed the server certificate (otherwise the system pool
// is used) and certFile/keyFile present a client certificate for servers
// that require mTLS. It returns nil when no TLS flag is set.
func loadTLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	if caFile == "" && certFile == "" && keyFile == "" {
		return nil, nil
	}
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("--client-cert and --client-key must be set together")
	}

	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read ca cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no certificates found in %s", caFile)
		}
		cfg.RootCAs = pool
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client keypair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

type apiClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func newAPIClient(baseURL, token string) *apiClient {
	hc := &http.Client{Timeout: 10 * time.Second}
	if apiTLSConfig != nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = apiTLSConfig
		hc.Transport = tr
	}
	return &apiClient{
		baseURL: baseURL,
		token:   token,
		http:    hc,
	}
}

func (c *apiClient) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

type agentInfo struct {
	ID            string            `json:"id"`
	Hostname      string            `json:"hostname"`
	Labels        map[string]string `json:"labels"`
	Status        string            `json:"status"`
	PolicyVersion int64             `json:"policy_version"`
	LastHeartbeat time.Time         `json:"last_heartbeat"`
	RegisteredAt  time.Time         `json:"registered_at"`
}

type policyInfo struct {
	ID      string `json:"id"`
	Version int64  `json:"version"`
}

type rolloutInfo struct {
	ID         string `json:"id"`
	PolicyID   string `json:"policy_id"`
	Status     string `json:"status"`
	Percentage int    `json:"percentage"`
}
