package nodereceipt

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type ClientConfig struct {
	URL, TokenPath, ManifestPath string
	TLS                          *tls.Config
	Active                       func() (Activation, error)
}

// Client is owned by one daemon process/loop. Never persist or reuse its epoch,
// challenge or sequence across restarts. The token file is re-read per request.
type Client struct {
	cfg       ClientConfig
	http      *http.Client
	epoch     string
	challenge *Challenge
	sequence  uint64
}

func NewClient(cfg ClientConfig) (*Client, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || cfg.TokenPath == "" || cfg.ManifestPath == "" || cfg.Active == nil {
		return nil, fmt.Errorf("receipts require HTTPS origin, token file, mounted manifest and active evaluator callback")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TLS != nil {
		tlsCfg = cfg.TLS.Clone()
		if tlsCfg.InsecureSkipVerify || tlsCfg.VerifyConnection != nil || tlsCfg.VerifyPeerCertificate != nil {
			return nil, fmt.Errorf("receipt TLS verification cannot be bypassed")
		}
		tlsCfg.MinVersion = max(tlsCfg.MinVersion, tls.VersionTLS12)
	}
	epoch, err := RandomEpoch()
	if err != nil {
		return nil, err
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	return &Client{cfg: cfg, epoch: epoch, http: &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("receipt redirects refused") }}}, nil
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	token, err := os.ReadFile(c.cfg.TokenPath)
	if err != nil {
		return fmt.Errorf("read receipt token: %w", err)
	}
	if len(token) > 16384 || strings.TrimSpace(string(token)) == "" {
		return fmt.Errorf("invalid receipt token file")
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	r.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("receipt endpoint HTTP %d", resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 128<<10)).Decode(out)
	}
	return nil
}

// Report never treats download, file presence or pool preparation as activation.
// Local mounted manifest must match the controller's challenge AND the actual
// active runtime identity. Any failure after registration attempts an authenticated
// increasing-sequence withdrawal before forgetting the session. If the endpoint
// cannot be reached/authenticated, earlier evidence is bounded only by expiry.
func (c *Client) Report(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			if c.challenge != nil {
				c.sequence++
				withdrawErr := c.post(ctx, "/v1/node-receipts", Receipt{Challenge: c.challenge.Nonce, BootEpoch: c.epoch, Sequence: c.sequence, MeasuredAt: time.Now().UTC(), Withdrawn: true}, nil)
				if withdrawErr != nil {
					err = errors.Join(err, fmt.Errorf("previous receipt withdrawal unconfirmed (expiry bound only): %w", withdrawErr))
				}
			}
			c.challenge = nil
		}
	}()
	if c.challenge == nil || !time.Now().Before(c.challenge.ExpiresAt.Add(-5*time.Second)) {
		var challenge Challenge
		if err := c.post(ctx, "/v1/node-receipts/register", Registration{BootEpoch: c.epoch}, &challenge); err != nil {
			return err
		}
		if challenge.BootEpoch != c.epoch || len(challenge.Nonce) != 64 || challenge.Manifest.Validate() != nil || !time.Now().Before(challenge.ExpiresAt) {
			return fmt.Errorf("invalid receipt challenge")
		}
		c.challenge, c.sequence = &challenge, 0
	}
	f, err := os.Open(c.cfg.ManifestPath)
	if err != nil {
		return err
	}
	var mounted Manifest
	err = json.NewDecoder(io.LimitReader(f, 128<<10)).Decode(&mounted)
	_ = f.Close()
	if err != nil {
		return err
	}
	active, err := c.cfg.Active()
	if err != nil {
		return err
	}
	m := c.challenge.Manifest
	if mounted.ID() != m.ID() || active.Digest != m.Digest || active.ABI != m.ABI || active.Posture != m.Posture {
		return fmt.Errorf("mounted desired manifest is not the active evaluator identity")
	}
	c.sequence++
	return c.post(ctx, "/v1/node-receipts", Receipt{Challenge: c.challenge.Nonce, BootEpoch: c.epoch, Sequence: c.sequence, MeasuredAt: time.Now().UTC(), Manifest: mounted, Active: active}, nil)
}
