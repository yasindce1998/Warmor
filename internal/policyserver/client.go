package policyserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	signed "github.com/yasindce1998/warmor/internal/crypto/assignment"
	"github.com/yasindce1998/warmor/internal/drift"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/telemetry"
)

// Client connects to the policy management server for policy distribution.
type Client struct {
	baseURL            string
	agentID            string
	hostname           string
	labels             map[string]string
	httpClient         *http.Client
	token              string
	policyVersion      int64
	policyID           string
	policyHash         string
	activationError    string
	mu                 sync.Mutex
	pollMu             sync.Mutex
	onUpdate           func(assignment *PolicyAssignment, wasmData []byte) error
	verify             func(assignment *PolicyAssignment, wasmData []byte) error
	fingerprint        func() *drift.BehaviorFingerprint
	signed             bool
	deploymentSequence uint64
	envelopeHash       string
	telemetry          *telemetry.Collector
	telemetryRevision  telemetry.Revision // published only after OnUpdate succeeds
}

// MaxWASMDownloadSize bounds a policy module download.
const MaxWASMDownloadSize = 64 * 1024 * 1024

// ClientConfig configures the policy server client.
type ClientConfig struct {
	SignedAssignments bool
	// InitialAssignment must describe the successfully restored/loaded durable
	// record, not merely a received deployment. Signed mode requires it on boot.
	InitialAssignment *PolicyAssignment
	ServerURL         string
	AgentID           string
	Hostname          string
	Labels            map[string]string
	// TLSConfig configures TLS to the server; include a client certificate
	// to authenticate with mTLS.
	TLSConfig *tls.Config
	// Token is a JWT bearer token with the agent role, sent on every request.
	Token string
	// OnUpdate must wait for successful activation and durable publication.
	// Errors retain the previous identity and retry on the next poll. A nil
	// callback cannot acknowledge a downloaded revision.
	OnUpdate func(assignment *PolicyAssignment, wasmData []byte) error
	// Verify, if set, is called with each downloaded policy (and its
	// signature in assignment.Signature) before OnUpdate. If it returns an
	// error the download is discarded, OnUpdate is not called and the
	// client keeps reporting its previous version, so the policy is
	// fetched and checked again on the next poll.
	Verify func(assignment *PolicyAssignment, wasmData []byte) error
	// Fingerprint, if set, is called before each heartbeat to attach a
	// behavioral fingerprint for fleet drift detection. A nil return sends
	// a plain heartbeat. The returned fingerprint's AgentID is overwritten
	// with the client's own agent ID.
	Fingerprint func() *drift.BehaviorFingerprint
	// Telemetry is opt-in. OnUpdate must use the same collector at the drained
	// enforcer activation boundary. Call AuthorizeTelemetry after registration.
	// SignedAssignments disables/seals this collector: schema 1 does not bind
	// signed deployment sequences, envelope authorization or cohort evidence.
	Telemetry *telemetry.Collector
}

// NewClient creates a policy server client.
func NewClient(cfg ClientConfig) *Client {
	if cfg.SignedAssignments && cfg.Telemetry != nil {
		cfg.Telemetry.Seal()
		cfg.Telemetry = nil
	}
	transport := &http.Transport{}
	if cfg.TLSConfig != nil {
		transport.TLSClientConfig = cfg.TLSConfig
	}
	c := &Client{
		baseURL:  cfg.ServerURL,
		agentID:  cfg.AgentID,
		hostname: cfg.Hostname,
		labels:   cfg.Labels,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
		token:       cfg.Token,
		onUpdate:    cfg.OnUpdate,
		verify:      cfg.Verify,
		fingerprint: cfg.Fingerprint,
		telemetry:   cfg.Telemetry,
		signed:      cfg.SignedAssignments,
	}
	if cfg.InitialAssignment != nil {
		a := cfg.InitialAssignment
		c.policyID, c.policyVersion, c.policyHash = a.PolicyID, a.Version, a.WASMHash
		c.deploymentSequence, c.envelopeHash = a.DeploymentSequence, signed.Digest(a.Envelope)
	}
	return c
}

// do sends req with the agent's credentials attached.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return c.httpClient.Do(req)
}

// Register sends a registration request to the server.
func (c *Client) Register(ctx context.Context) (err error) {
	defer func() { metrics.RecordRegistration(err) }()
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
	_ = c.Poll(ctx)
}

// Poll performs one serialized fetch/verify/activation and reports errors.
func (c *Client) Poll(ctx context.Context) error {
	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	err := c.pollOnce(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.activationError = err.Error()
	} else {
		c.activationError = ""
	}
	return err
}

func (c *Client) pollOnce(ctx context.Context) error {
	if c.signed {
		return c.pollSigned(ctx)
	}
	c.mu.Lock()
	version := c.policyVersion
	id, digest := c.policyID, c.policyHash
	c.mu.Unlock()

	q := url.Values{}
	q.Set("agent_id", c.agentID)
	q.Set("if_version", strconv.FormatInt(version, 10))
	q.Set("if_policy_id", id)
	q.Set("if_hash", digest)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/policy?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	c.setTelemetryHeaders(req)

	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		// Legacy servers compare only version; request a full assignment
		// instead of trusting a potentially ambiguous 304.
		if resp.Header.Get(RevisionIdentityHeader) == "1" {
			// Telemetry-aware servers send 200 when an eligible assignment
			// exists, even for an unchanged artifact. A plain 304 supplies no
			// eligible activation/cohort evidence (including older servers).
			if c.telemetry != nil {
				c.telemetry.Seal()
			}
			return nil
		}
		q.Del("if_version")
		retry, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/policy?"+q.Encode(), nil)
		if err != nil {
			return err
		}
		c.setTelemetryHeaders(retry)
		full, err := c.do(retry)
		if err != nil {
			return err
		}
		defer full.Body.Close()
		resp = full
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("policy assignment: status %d", resp.StatusCode)
	}

	var assignment PolicyAssignment
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&assignment); err != nil {
		return err
	}
	if len(assignment.Envelope) != 0 || assignment.DeploymentSequence != 0 {
		if c.telemetry != nil {
			c.telemetry.Seal()
		}
		return fmt.Errorf("signed deployment cannot use legacy assignment/telemetry activation")
	}

	// A different version (newer, or older after a rollback) is applied.
	telemetryCurrent := assignment.Telemetry == nil || (c.telemetry != nil && c.telemetry.Matches(*assignment.Telemetry, assignment.PolicyID, assignment.Version, assignment.WASMHash))
	if assignment.PolicyID == id && assignment.Version == version && assignment.WASMHash == digest && telemetryCurrent {
		if assignment.Telemetry == nil && c.telemetry != nil {
			c.telemetry.Seal()
		}
		return nil
	}
	if assignment.PolicyID == "" || assignment.Version <= 0 {
		return fmt.Errorf("invalid policy assignment identity")
	}

	// Fetch WASM binary
	wasmData, sig, err := c.fetchWASM(ctx, assignment.PolicyID, assignment.Version)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(wasmData)
	if assignment.WASMHash != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("policy %s v%d: download digest mismatch", assignment.PolicyID, assignment.Version)
	}
	assignment.Signature = sig
	activeID, activeVersion, activeHash := assignment.PolicyID, assignment.Version, assignment.WASMHash
	if c.verify != nil {
		if err := c.verify(&assignment, wasmData); err != nil {
			return err
		}
	}
	if c.onUpdate == nil {
		return fmt.Errorf("policy activation callback is required")
	}
	if err := c.onUpdate(&assignment, wasmData); err != nil {
		return fmt.Errorf("activate policy %s v%d: %w", activeID, activeVersion, err)
	}

	c.mu.Lock()
	c.policyVersion = activeVersion
	c.policyID = activeID
	c.policyHash = activeHash
	c.activationError = ""
	c.telemetryRevision = telemetry.Revision{}
	if c.telemetry != nil && assignment.Telemetry != nil && c.telemetry.Matches(*assignment.Telemetry, activeID, activeVersion, activeHash) {
		c.telemetryRevision = c.telemetry.ActiveRevision()
	}
	c.mu.Unlock()
	return nil
}

// InvalidateActiveRevision forgets the fleet identity after an out-of-band reload.
func (c *Client) InvalidateActiveRevision() {
	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.signed {
		return
	} // signed mode has no out-of-band reload path
	c.policyID, c.policyHash, c.policyVersion = "", "", 0
	c.telemetryRevision = telemetry.Revision{}
	if c.telemetry != nil {
		c.telemetry.Seal()
	}
}

// fetchWASM downloads a policy version and its raw signature (nil if the
// server sent none).
func (c *Client) fetchWASM(ctx context.Context, policyID string, version int64) ([]byte, []byte, error) {
	q := url.Values{}
	q.Set("policy_id", policyID)
	q.Set("version", strconv.FormatInt(version, 10))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/policy/wasm?"+q.Encode(), nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch wasm: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("fetch wasm: status %d", resp.StatusCode)
	}

	var sig []byte
	if enc := resp.Header.Get(SignatureHeader); enc != "" {
		if sig, err = base64.StdEncoding.DecodeString(enc); err != nil {
			return nil, nil, fmt.Errorf("fetch wasm: decode signature header: %w", err)
		}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxWASMDownloadSize+1))
	if err != nil {
		return nil, nil, fmt.Errorf("fetch wasm: %w", err)
	}
	if len(data) > MaxWASMDownloadSize {
		return nil, nil, fmt.Errorf("fetch wasm: module exceeds %d bytes", MaxWASMDownloadSize)
	}
	return data, sig, nil
}

// SendHeartbeat sends a heartbeat to the server.
func (c *Client) SendHeartbeat(ctx context.Context) (err error) {
	defer func() { metrics.RecordHeartbeat(c.agentID, err) }()
	// Heartbeat liveness must not wait for OnUpdate. A full activation identity
	// match below excludes a collector swapped by an in-flight callback, even
	// when reactivating the same artifact for a different assignment generation.
	c.mu.Lock()
	version := c.policyVersion
	id, digest, activationError := c.policyID, c.policyHash, c.activationError
	activeTelemetry := c.telemetryRevision
	sequence, envelopeHash := c.deploymentSequence, c.envelopeHash
	c.mu.Unlock()

	req := HeartbeatRequest{
		AgentID:            c.agentID,
		PolicyVersion:      version,
		PolicyID:           id,
		PolicyHash:         digest,
		ActivationError:    activationError,
		DeploymentSequence: sequence,
		EnvelopeHash:       envelopeHash,
	}
	if !c.signed && c.telemetry != nil && activationError == "" {
		snapshot := c.telemetry.Snapshot()
		if snapshot != nil && snapshot.Revision == activeTelemetry && snapshot.Revision.PolicyID == id && snapshot.Revision.PolicyVersion == version && snapshot.Revision.PolicyHash == digest {
			req.Telemetry = snapshot
		}
	}
	if c.fingerprint != nil {
		if fp := c.fingerprint(); fp != nil {
			// The server keys the fleet comparison by agent; report this
			// client's own ID rather than whatever the source produced.
			fp.AgentID = c.agentID
			req.Fingerprint = fp
		}
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
