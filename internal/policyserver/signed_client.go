package policyserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"

	"github.com/yasindce1998/warmor/internal/crypto/assignment"
)

func (c *Client) pollSigned(ctx context.Context) error {
	c.mu.Lock()
	sequence, hash := c.deploymentSequence, c.envelopeHash
	c.mu.Unlock()
	q := url.Values{"agent_id": {c.agentID}, "if_sequence": {strconv.FormatUint(sequence, 10)}, "if_envelope_hash": {hash}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/deployment?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.Header.Get(assignment.ProtocolHeader) != "1" {
		return errors.New("server lacks signed assignment protocol; refusing legacy fallback")
	}
	if resp.StatusCode == http.StatusNotModified {
		if sequence == 0 || hash == "" {
			return errors.New("signed not-modified response without restored deployment identity")
		}
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("signed deployment: status %d", resp.StatusCode)
	}
	wire, err := io.ReadAll(io.LimitReader(resp.Body, assignment.MaxBundleBytes+1))
	if err != nil {
		return err
	}
	b, err := assignment.DecodeBundle(wire)
	if err != nil {
		return err
	}
	e, err := assignment.Decode(b.Envelope)
	if err != nil {
		return err
	}
	d := e.Deployment
	if d.Policy.Version > math.MaxInt64 {
		return assignment.ErrInvalid
	}
	if d.Sequence < sequence || (d.Sequence == sequence && assignment.Digest(b.Envelope) != hash) {
		return errors.New("signed deployment replay/equivocation")
	}
	if d.Sequence == sequence {
		return nil
	} // already loaded and durably acknowledged
	activeEnvelopeHash := assignment.Digest(b.Envelope)
	a := &PolicyAssignment{PolicyID: d.Policy.ID, Version: int64(d.Policy.Version), WASMHash: d.Policy.SHA256, Envelope: b.Envelope, DeploymentSequence: d.Sequence, Signature: b.ArtifactSignature}
	if c.verify == nil || c.onUpdate == nil {
		return errors.New("signed deployment requires verification and durable activation callbacks")
	}
	if err := c.verify(a, b.WASM); err != nil {
		return err
	}
	if err := c.onUpdate(a, b.WASM); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policyID, c.policyVersion, c.policyHash = d.Policy.ID, int64(d.Policy.Version), d.Policy.SHA256
	c.deploymentSequence, c.envelopeHash = d.Sequence, activeEnvelopeHash
	return nil
}

// MarshalDeploymentBundle produces the exact canonical upload/response body.
func MarshalDeploymentBundle(b assignment.Bundle) ([]byte, error) {
	wire, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	if _, err := assignment.DecodeBundle(wire); err != nil {
		return nil, err
	}
	return wire, nil
}
