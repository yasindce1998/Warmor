package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/yasindce1998/warmor/internal/enforcer"
	"github.com/yasindce1998/warmor/internal/nodereceipt"
)

var (
	receiptURL      = flag.String("receipt-controller", "", "Opt-in authenticated node receipts: HTTPS controller origin (disabled by default)")
	receiptToken    = flag.String("receipt-token-file", "", "Projected pod-bound token with controller receipt audience; never use node labels or a shared static token")
	receiptCA       = flag.String("receipt-ca", "", "Trusted CA PEM for the HTTPS receipt controller (required when enabled)")
	receiptManifest = flag.String("receipt-manifest", "", "Mounted activation-manifest.json from the effective policy ConfigMap")
)

func newNodeReceiptClient(enf *enforcer.Enforcer) (*nodereceipt.Client, error) {
	if *receiptURL == "" {
		return nil, nil
	}
	if *receiptCA == "" {
		return nil, fmt.Errorf("--receipt-ca is required: explicit controller trust must be provisioned")
	}
	b, err := os.ReadFile(*receiptCA)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("invalid receipt controller CA")
	}
	return nodereceipt.NewClient(nodereceipt.ClientConfig{URL: *receiptURL, TokenPath: *receiptToken, ManifestPath: *receiptManifest, TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, Active: enf.ActiveReceipt})
}

func runNodeReceipts(ctx context.Context, client *nodereceipt.Client) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		if err := client.Report(ctx); err != nil && ctx.Err() == nil {
			log.Printf("Node activation receipt withheld: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
