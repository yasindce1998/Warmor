package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/policyserver"
)

var (
	addr              = flag.String("addr", ":8443", "Server listen address")
	caCert            = flag.String("ca-cert", "", "CA certificate PEM path used to verify agent client certificates (enables mTLS; requires --tls-cert and --tls-key)")
	tlsCert           = flag.String("tls-cert", "", "Server TLS certificate PEM path")
	tlsKey            = flag.String("tls-key", "", "Server TLS private key PEM path")
	jwtSecret         = flag.String("jwt-secret", "", "JWT secret for bearer-token auth (env WARMOR_JWT_SECRET); required for the admin API")
	policyDir         = flag.String("policy-dir", "", "Directory admin requests may load policy WASM files from")
	insecure          = flag.Bool("insecure", false, "Allow serving without any authentication (development only)")
	verifyKey         = flag.String("verify-key", "", "ed25519 public key PEM (PKIX); refuse policy uploads without a detached signature (<wasm>.sig or the request's \"signature\") that verifies against it")
	driftThreshold    = flag.Float64("drift-threshold", 3.0, "Z-score threshold for fleet drift anomalies computed from fingerprints in agent heartbeats")
	serverMetricsPort = flag.Int("metrics-port", 0, "Prometheus metrics port for the server itself, e.g. fleet drift gauges (0 = off)")
	stateFile         = flag.String("state-file", "", "Durable single-writer state snapshot path (required unless --insecure); parent directory must exist and be private")
	stateMaxBytes     = flag.Int64("state-max-bytes", 256<<20, "Maximum retained state snapshot bytes (mutations exceeding this limit are rejected)")
	stateMaxWASMBytes = flag.Int64("state-max-wasm-bytes", 128<<20, "Maximum total retained policy WASM bytes")
	stateMaxAgents    = flag.Int("state-max-agents", 10000, "Maximum retained agent registrations")
)

func main() {
	flag.Parse()

	cfg := policyserver.ServerConfig{
		Addr:           *addr,
		PolicyDir:      *policyDir,
		Insecure:       *insecure,
		DriftThreshold: *driftThreshold,
	}

	if *jwtSecret == "" {
		*jwtSecret = os.Getenv("WARMOR_JWT_SECRET")
	}

	switch {
	case *tlsCert == "" && *tlsKey == "" && *caCert == "":
		// Plaintext.
	case *tlsCert == "" || *tlsKey == "":
		log.Fatalf("--tls-cert and --tls-key must be given together (and are required by --ca-cert)")
	case *caCert == "":
		// TLS without client certificates: callers authenticate with JWTs.
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("configure TLS: %v", err)
		}
		cfg.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
		log.Println("TLS enabled (no client certificates; JWT auth required)")
	default:
		certPEM, err := os.ReadFile(*tlsCert)
		if err != nil {
			log.Fatalf("read tls cert: %v", err)
		}
		keyPEM, err := os.ReadFile(*tlsKey)
		if err != nil {
			log.Fatalf("read tls key: %v", err)
		}
		caPEM, err := os.ReadFile(*caCert)
		if err != nil {
			log.Fatalf("read ca cert: %v", err)
		}

		tlsCfg, err := crypto.NewServerTLSConfig(certPEM, keyPEM, caPEM)
		if err != nil {
			log.Fatalf("configure mTLS: %v", err)
		}
		cfg.TLSConfig = tlsCfg
		log.Println("mTLS enabled")
	}

	if *jwtSecret != "" {
		cfg.JWTSecret = []byte(*jwtSecret)
		log.Println("JWT auth enabled")
	}

	if cfg.JWTSecret == nil && *caCert == "" && !*insecure {
		log.Fatalf("refusing to start without authentication: set --jwt-secret and/or --ca-cert with --tls-cert/--tls-key (or --insecure for development only)")
	}
	if cfg.TLSConfig == nil && !*insecure {
		log.Fatal("refusing plaintext transport: set --tls-cert/--tls-key (or --insecure for development only)")
	}
	if *stateFile == "" && !*insecure {
		log.Fatal("--state-file is required outside explicit --insecure development mode")
	}
	if *stateMaxBytes <= 0 || *stateMaxWASMBytes <= 0 || *stateMaxAgents <= 0 {
		log.Fatal("state resource limits must be positive")
	}

	if *policyDir == "" {
		log.Println("no --policy-dir set; creating or updating policies via the admin API is disabled")
	} else if info, err := os.Stat(*policyDir); err != nil || !info.IsDir() {
		log.Fatalf("--policy-dir %s is not a directory", *policyDir)
	}

	if *verifyKey != "" {
		pub, err := crypto.LoadPublicKey(*verifyKey)
		if err != nil {
			log.Fatalf("--verify-key: %v", err)
		}
		cfg.VerifyKey = pub
		log.Printf("policy uploads must be signed by %s", *verifyKey)
	}
	if *stateFile != "" {
		store, err := policyserver.OpenStore(*stateFile, policyserver.StoreOptions{VerifyKey: cfg.VerifyKey, Limits: policyserver.StoreLimits{
			MaxSnapshotBytes: *stateMaxBytes, MaxRetainedWASMBytes: *stateMaxWASMBytes, MaxAgents: *stateMaxAgents,
		}})
		if err != nil {
			log.Fatalf("open policy state: %v", err)
		}
		defer store.Close()
		cfg.Store = store
		log.Printf("durable policy state: %s", *stateFile)
	} else {
		log.Println("WARNING: ephemeral development state; policies, registrations, and rollouts will be lost on restart")
	}

	srv := policyserver.NewServer(cfg)

	// The server's own metrics (fleet drift gauges) are served on a
	// separate, unauthenticated port, like the daemon's; bind it to
	// localhost or a protected network if that matters.
	if *serverMetricsPort > 0 {
		go func() {
			addr := fmt.Sprintf(":%d", *serverMetricsPort)
			log.Printf("metrics listening on %s", addr)
			if err := metrics.ListenAndServe(addr); err != nil {
				log.Fatalf("metrics server: %v", err)
			}
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("shutting down policy server...")
		_ = srv.Shutdown(ctx)
		cancel()
	}()

	if err := srv.Start(); err != nil {
		log.Fatalf("policy server: %v", err)
	}
}
