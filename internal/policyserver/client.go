package policyserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// Client connects to the policy management server for policy distribution.
type Client struct {
	baseURL       string
	agentID       string
	hostname      string
	labels        map[string]string
	httpClient    *http.Client
	token         string
	policyVersion int64
	mu            sync.Mutex
	onUpdate      func(assignment *PolicyAssignment, wasmData []byte)
}

// ClientConfig configures the policy server client.
type ClientConfig struct {
	ServerURL string
	AgentID   string
	Hostname  string
	Labels    map[string]string
	// TLSConfig configures TLS to the server; include a client certificate
	// to authenticate with mTLS.
	TLSConfig *tls.Config
	// Token is a JWT bearer token with the agent role, sent on every request.
	Token    string
	OnUpdate func(assignment *PolicyAssignment, wasmData []byte)
}

// NewClient creates a policy server client.
func NewClient(cfg ClientConfig) *Client {
	transport := &http.Transport{}
	if cfg.TLSConfig != nil {
		transport.TLSClientConfig = cfg.TLSConfig
	}
	return &Client{
		baseURL:  cfg.ServerURL,
		agentID:  cfg.AgentID,
		hostname: cfg.Hostname,
		labels:   cfg.Labels,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
		token:    cfg.Token,
		onUpdate: cfg.OnUpdate,
	}
}

// do sends req with the agent's credentials attached.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return c.httpClient.Do(req)
}

// Register sends a registration request to the server.
func (c *Client) Register(ctx context.Context) error {
	req := RegisterRequest{
		ID:       c.agentID,
		Hostname: c.hostname,
		Labels:   c.labels,
	}

	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/register", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.do(httpReq)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register: status %d", resp.StatusCode)
	}
	return nil
}

// PollLoop starts polling the server for policy updates. Blocks until ctx is cancelled.
func (c *Client) PollLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.poll(ctx)
		}
	}
}

func (c *Client) poll(ctx context.Context) {
	c.mu.Lock()
	version := c.policyVersion
	c.mu.Unlock()

	q := url.Values{}
	q.Set("agent_id", c.agentID)
	q.Set("if_version", strconv.FormatInt(version, 10))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/policy?"+q.Encode(), nil)
	if err != nil {
		return
	}

	resp, err := c.do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return
	}

	var assignment PolicyAssignment
	if err := json.NewDecoder(resp.Body).Decode(&assignment); err != nil {
		return
	}

	// A different version (newer, or older after a rollback) is applied.
	if assignment.Version == version {
		return
	}

	// Fetch WASM binary
	wasmData, err := c.fetchWASM(ctx, assignment.PolicyID, assignment.Version)
	if err != nil {
		return
	}

	c.mu.Lock()
	c.policyVersion = assignment.Version
	c.mu.Unlock()

	if c.onUpdate != nil {
		c.onUpdate(&assignment, wasmData)
	}
}

func (c *Client) fetchWASM(ctx context.Context, policyID string, version int64) ([]byte, error) {
	q := url.Values{}
	q.Set("policy_id", policyID)
	q.Set("version", strconv.FormatInt(version, 10))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/policy/wasm?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch wasm: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch wasm: status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// SendHeartbeat sends a heartbeat to the server.
func (c *Client) SendHeartbeat(ctx context.Context) error {
	c.mu.Lock()
	version := c.policyVersion
	c.mu.Unlock()

	req := HeartbeatRequest{
		AgentID:       c.agentID,
		PolicyVersion: version,
	}

	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.do(httpReq)
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("heartbeat: status %d", resp.StatusCode)
	}
	return nil
}

// HeartbeatLoop sends periodic heartbeats. Blocks until ctx is cancelled.
func (c *Client) HeartbeatLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = c.SendHeartbeat(ctx)
		}
	}
}
