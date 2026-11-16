package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/yasindce1998/warmor/internal/controller"
	"github.com/yasindce1998/warmor/internal/kube"
	"github.com/yasindce1998/warmor/internal/nodereceipt"
)

var (
	receiptsEnabled   = flag.Bool("node-receipts", false, "Opt in to authenticated activation self-reports (not attestation); requires TLS, explicit roster and daemon identity")
	receiptsAddress   = flag.String("receipts-address", ":9443", "Separate HTTPS-only receipt listener")
	receiptsCert      = flag.String("receipts-tls-cert", "", "Provisioned receipt server certificate PEM")
	receiptsKey       = flag.String("receipts-tls-key", "", "Provisioned receipt server key PEM")
	receiptsAudience  = flag.String("receipts-audience", "", "Dedicated projected bound-pod token audience")
	receiptsNS        = flag.String("receipts-namespace", "", "Authorized daemon namespace")
	receiptsSA        = flag.String("receipts-service-account", "", "Authorized daemon ServiceAccount")
	receiptsDS        = flag.String("receipts-daemonset", "", "Authorized daemon DaemonSet name")
	receiptsContainer = flag.String("receipts-container", "warmor", "Daemon container whose Kubernetes restart epoch is fenced")
	receiptsNodes     = flag.String("receipts-required-nodes", "", "Explicit complete desired node roster (comma-separated; never just online nodes)")
	receiptsAge       = flag.Duration("receipts-max-age", time.Minute, "Receipt and challenge freshness (10s..5m)")
	receiptsAudit     = flag.Bool("receipts-audit", true, "Expected actual daemon audit posture")
	receiptsLSM       = flag.Bool("receipts-lsm-enforcement", false, "Expected actual kernel LSM enforcement posture")
	receiptsDD        = flag.Bool("receipts-default-deny-requested", false, "Expected default-deny request (not eligibility/coverage proof)")
)

func startReceipts(ctl *controller.Controller, api *kube.Client, stop context.CancelFunc) (*http.Server, error) {
	if !*receiptsEnabled {
		return nil, nil
	}
	if *receiptsCert == "" || *receiptsKey == "" {
		return nil, fmt.Errorf("node receipts require provisioned TLS certificate and key")
	}
	cert, err := tls.LoadX509KeyPair(*receiptsCert, *receiptsKey)
	if err != nil {
		return nil, err
	}
	err = ctl.EnableReceipts(nodereceipt.Config{Kube: nodereceipt.RESTKube{Client: api}, Audience: *receiptsAudience, Namespace: *receiptsNS, ServiceAccount: *receiptsSA, DaemonSet: *receiptsDS, Container: *receiptsContainer, RequiredNodes: strings.Split(*receiptsNodes, ","), MaxAge: *receiptsAge}, nodereceipt.Posture{Audit: *receiptsAudit, LSMEnforcement: *receiptsLSM, DefaultDenyRequested: *receiptsDD})
	if err != nil {
		return nil, err
	}
	listener, err := tls.Listen("tcp", *receiptsAddress, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}})
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: ctl.ReceiptHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 32 << 10}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("receipt listener failed")
			stop()
		}
	}()
	return server, nil
}
