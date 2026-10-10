package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yasindce1998/warmor/internal/policyserver"
)

// serverTokenEnv supplies the policy server agent token when --server-token
// is not set, keeping the token out of the process arguments.
const serverTokenEnv = "WARMOR_SERVER_TOKEN"

// policyClientConfig holds the daemon's policy server settings.
type policyClientConfig struct {
	ServerURL string
	Token     string
	CAFile    string
	CertFile  string
	KeyFile   string
	AgentID   string
	Labels    map[string]string
}

// newPolicyClient builds a policy server client. The agent authenticates
// with an mTLS client certificate (CertFile/KeyFile), a JWT bearer token with
// the agent role (Token, or WARMOR_SERVER_TOKEN), or both.
func newPolicyClient(cfg policyClientConfig, onUpdate func(*policyserver.PolicyAssignment, []byte)) (*policyserver.Client, error) {
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, fmt.Errorf("--tls-cert and --tls-key must be given together")
	}
	if cfg.Token == "" {
		cfg.Token = os.Getenv(serverTokenEnv)
	}
	https := strings.HasPrefix(cfg.ServerURL, "https://")
	if !https && !strings.HasPrefix(cfg.ServerURL, "http://") {
		return nil, fmt.Errorf("--server must be an http:// or https:// URL, got %q", cfg.ServerURL)
	}
	if !https && (cfg.CAFile != "" || cfg.CertFile != "") {
		return nil, fmt.Errorf("--tls-ca/--tls-cert/--tls-key require an https:// --server URL")
	}

	var tlsCfg *tls.Config
	if https {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CAFile != "" {
			caPEM, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, fmt.Errorf("read tls ca: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return nil, fmt.Errorf("no certificates found in %s", cfg.CAFile)
			}
			tlsCfg.RootCAs = pool
		}
		if cfg.CertFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("load client certificate: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
	}

	switch {
	case cfg.Token == "" && cfg.CertFile == "":
		log.Printf("⚠️  No policy server credentials (--tls-cert/--tls-key or --server-token / %s); the server will reject requests unless it runs with --insecure", serverTokenEnv)
	case cfg.Token != "" && !https:
		log.Printf("⚠️  Sending the policy server token over plaintext HTTP")
	}

	if cfg.AgentID == "" {
		host, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("determine agent id: %w (set --agent-id)", err)
		}
		cfg.AgentID = host
	}
	hostname, _ := os.Hostname()

	return policyserver.NewClient(policyserver.ClientConfig{
		ServerURL: strings.TrimRight(cfg.ServerURL, "/"),
		AgentID:   cfg.AgentID,
		Hostname:  hostname,
		Labels:    cfg.Labels,
		TLSConfig: tlsCfg,
		Token:     cfg.Token,
		OnUpdate:  onUpdate,
	}), nil
}

// runPolicyClient registers with the policy server (retrying until it
// succeeds) and then polls for policy updates and sends heartbeats until ctx
// is cancelled.
func runPolicyClient(ctx context.Context, c *policyserver.Client, interval time.Duration) {
	for {
		err := c.Register(ctx)
		if err == nil {
			break
		}
		log.Printf("❌ Policy server: %v (retrying in %v)", err, interval)
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
	log.Println("✓ Registered with policy server")
	go c.HeartbeatLoop(ctx, interval)
	c.PollLoop(ctx, interval)
}

// writePolicyFile atomically replaces the policy file at path with data so
// a concurrent reload never sees a partially written module.
func writePolicyFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
