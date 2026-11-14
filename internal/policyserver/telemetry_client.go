package policyserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/yasindce1998/warmor/internal/telemetry"
)

// AuthorizeTelemetry explicitly starts a new collector incarnation. It never
// registers a node or acknowledges an artifact. Re-registration does not call
// this implicitly. After a server epoch change the embedding agent must call
// it again, poll and successfully reactivate before any evidence is eligible.
func (c *Client) AuthorizeTelemetry(ctx context.Context) error {
	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	if c.telemetry == nil {
		return fmt.Errorf("no telemetry collector configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/telemetry/session", nil)
	if err != nil {
		return err
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authorize telemetry: status %d", resp.StatusCode)
	}
	var session telemetry.Session
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&session); err != nil {
		return err
	}
	return c.telemetry.SetSession(session)
}

func (c *Client) setTelemetryHeaders(req *http.Request) {
	if c.telemetry == nil {
		return
	}
	session := c.telemetry.Session()
	if session.Validate() != nil {
		return
	}
	req.Header.Set(telemetryEpochHeader, session.Epoch)
	req.Header.Set(telemetrySessionHeader, session.SessionID)
}
