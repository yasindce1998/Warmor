package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/policyserver"
)

var (
	addr      = flag.String("addr", ":8443", "Server listen address")
	caCert    = flag.String("ca-cert", "", "CA certificate PEM path used to verify agent client certificates (enables mTLS; requires --tls-cert and --tls-key)")
	tlsCert   = flag.String("tls-cert", "", "Server TLS certificate PEM path")
	tlsKey    = flag.String("tls-key", "", "Server TLS private key PEM path")
	jwtSecret = flag.String("jwt-secret", "", "JWT secret for bearer-token auth (env WARMOR_JWT_SECRET); required for the admin API")
	policyDir = flag.String("policy-dir", "", "Directory admin requests may load policy WASM files from")
	insecure  = flag.Bool("insecure", false, "Allow serving without any authentication (development only)")
)

func main() {
	flag.Parse()

	cfg := policyserver.ServerConfig{
		Addr:      *addr,
		PolicyDir: *policyDir,
		Insecure:  *insecure,
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

	if *policyDir == "" {
		log.Println("no --policy-dir set; creating or updating policies via the admin API is disabled")
	} else if info, err := os.Stat(*policyDir); err != nil || !info.IsDir() {
		log.Fatalf("--policy-dir %s is not a directory", *policyDir)
	}

	srv := policyserver.NewServer(cfg)

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
