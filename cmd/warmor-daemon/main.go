package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yasindce1998/warmor/internal/dashboard"
	"github.com/yasindce1998/warmor/internal/enforcer"
	"github.com/yasindce1998/warmor/internal/policyserver"
	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/internal/version"
)

var (
	policyPath               = flag.String("policy", "policies/example/policy.wasm", "Path to WASM policy file")
	policyFallback           = flag.String("policy-fallback", "", "If --policy does not exist at startup, seed it from this file (e.g. the policy baked into the container image) so server-managed deployments can bootstrap before the first download; cannot be combined with --verify-key")
	statsInterval            = flag.Duration("stats-interval", 30*time.Second, "Statistics reporting interval")
	logLevel                 = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	metricsPort              = flag.Int("metrics-port", 9090, "Prometheus metrics port")
	auditMode                = flag.Bool("audit", false, "Audit mode: log deny decisions without enforcing")
	cgroupFilter             = flag.String("cgroup-filter", "", "Cgroup paths to filter (comma-separated, or 'auto' for K8s pod discovery)")
	lsmEnforce               = flag.Bool("lsm-enforce", false, "Enable LSM-BPF kernel-level blocking (requires CONFIG_BPF_LSM)")
	requireLSM               = flag.Bool("require-lsm", false, "Fail to start unless BPF-LSM kernel enforcement can be loaded (fail-closed; default is to degrade to observe-only)")
	noLSM                    = flag.Bool("no-lsm", false, "Skip LSM-BPF loading entirely (tracepoint-only observe mode)")
	defaultDeny              = flag.Bool("default-deny", false, "Refuse in-kernel (EPERM) what the policy does not allow: preload the policy's static allow rules and deny policy-map misses (requires --lsm-enforce and an allowlist policy: default_action deny + exact eq rules; see docs/design/kernel-default-deny.md)")
	eventSink                = flag.String("event-sink", "", "Event sinks: stdout, file:<path>, webhook:<url>, syslog:[udp|tcp://]host:port (comma-separated)")
	eventFileMax             = flag.Int64("event-file-max", 100*1024*1024, "Max event file size before rotation (bytes)")
	webhookHeader            = flag.String("webhook-header", "", "Webhook auth header (format: Key:Value)")
	eventLabels              = flag.String("event-labels", "", "Labels to attach to streamed events and report to the policy server (format: k=v,k2=v2)")
	attackGraph              = flag.Bool("attack-graph", false, "Build the MITRE attack graph and blast-radius metrics from observed events (labels streamed events with technique IDs)")
	dashboardPort            = flag.Int("dashboard-port", 0, "Serve the web dashboard (SSE) on this port (0 = off)")
	driftEnabled             = flag.Bool("drift", false, "Collect bounded local host behavior rates; fleet submission is withheld until real workload identity is available")
	driftImageKey            = flag.String("drift-image-key", "", "Deprecated and ignored: arbitrary grouping keys are not workload image identity; --drift currently collects locally only")
	showVersion              = flag.Bool("version", false, "Show version and exit")
	evalTimeout              = flag.Duration("eval-timeout", 50*time.Millisecond, "Deadline for one WASM policy evaluation; a policy exceeding it is denied (fail closed)")
	atomicGenerations        = flag.Bool("experimental-atomic-generations", false, "Opt into experimental Linux generation activation (requires --require-lsm; not production validated)")
	supervisedPolicyHost     = flag.Bool("experimental-supervised-policy-host", false, "Run all policy decoding/compilation/evaluation in a pinned child process (Linux, requires --verify-key; experimental)")
	policyHostPath           = flag.String("policy-host", "", "Absolute path to trusted warmor-policy-host executable (requires explicit experimental opt-in)")
	policyHostSHA256         = flag.String("policy-host-sha256", "", "Lowercase SHA-256 pin of trusted policy host executable")
	policyDeclarationDigests = flag.String("policy-declaration-digests", "", "Administrator-attested deterministic/exhaustive module SHA-256 digests, comma-separated; empty disables supervised caches/static rules")

	integrityDB   = flag.String("integrity-db", "", "Integrity database from warmor-integrity-scan; its SHA-256 digests become the kernel exec allowlist")
	lsmRingSize   = flag.String("lsm-ringbuf-size", "4MiB", "LSM event ring buffer size (power of two, e.g. 1MiB, 4MiB, 16MiB); a larger ring absorbs bigger bursts before events are dropped")
	onEventLoss   = flag.String("on-event-loss", "log", "When the LSM event ring is full: log (allow the operation, count the drop) or deny (refuse unknown exec/connect in enforce mode)")
	escapeDetect  = flag.String("escape-detect", "off", "Container escape detection: off, alert (log, count and stream matches) or deny (also terminate the process)")
	integrityMode = flag.String("integrity-mode", "off", "Exec integrity check: off, audit (report unlisted binaries) or enforce (refuse them in-kernel)")

	serverURL    = flag.String("server", "", "Policy server URL (e.g. https://warmor-server:8443); downloaded policies replace --policy")
	serverToken  = flag.String("server-token", "", "Agent JWT (role agent) for the policy server (default: $"+serverTokenEnv+")")
	tlsCA        = flag.String("tls-ca", "", "CA certificate PEM used to verify the policy server")
	tlsCert      = flag.String("tls-cert", "", "Client certificate PEM for mTLS to the policy server")
	tlsKey       = flag.String("tls-key", "", "Client private key PEM for mTLS to the policy server")
	agentID      = flag.String("agent-id", "", "Agent ID reported to the policy server (default: hostname)")
	pollInterval = flag.Duration("poll-interval", 30*time.Second, "Policy server poll and heartbeat interval")

	verifyKey      = flag.String("verify-key", "", "ed25519 public key PEM (PKIX, from warmor-policy-bundle --keygen); refuse any policy (startup, reload, server download) without a valid detached signature (<policy>.sig)")
	validatePolicy = flag.String("validate-policy", "", "Validate the policy at this path in the WASM runtime (and its signature with --verify-key), print the result and exit 0/1; needs no root or BPF")
)

var (
	cgroupRoot              = flag.String("cgroup-root", "/sys/fs/cgroup", "Host cgroup v2 mount visible to the daemon (automatic discovery and container resolution)")
	cgroupReconcileInterval = flag.Duration("cgroup-reconcile-interval", time.Second, "Automatic discovery interval; new pods are not covered until discovery")
	metricsBindAddress      = flag.String("metrics-bind-address", "", "Metrics/probe bind IP (empty listens on all interfaces; hostNetwork exposure is CNI-dependent)")
	dashboardBind           = flag.String("dashboard-bind", dashboard.DefaultBind, "Dashboard listen IP (remote/all-interface access requires an explicit address; use a TLS reverse proxy)")
	dashboardTokenFile      = flag.String("dashboard-token-file", "", "Dashboard HTTP Basic password file (user: warmor); alternatively set $"+dashboard.TokenEnv)
)

func main() {
	flag.Parse()

	// Handle service subcommands (Windows: install/uninstall)
	if handleServiceCommand(flag.Args()) {
		return
	}

	// Handle version flag
	if *showVersion {
		log.Printf("warmor version %s", version.Version)
		return
	}

	if *validatePolicy != "" {
		if *supervisedPolicyHost || *policyHostPath != "" || *policyHostSHA256 != "" || *policyDeclarationDigests != "" {
			log.Fatal("--validate-policy uses the legacy in-process validator; do not combine with supervised backend flags")
		}
		os.Exit(runValidatePolicy(*validatePolicy, *verifyKey, os.Stdout, os.Stderr))
	}

	// Run as Windows Service if launched by SCM
	if isWindowsService() {
		runService(runDaemon)
		return
	}

	runDaemon(nil)
}

// runDaemon runs the enforcer until a shutdown signal arrives or stop is
// closed (the Windows service manager's stop request).
func runDaemon(stop <-chan struct{}) {
	hostConfig, err := supervisedBackendConfig(*supervisedPolicyHost, *policyHostPath, *policyHostSHA256, *policyDeclarationDigests, *evalTimeout)
	if err != nil {
		log.Fatal(err)
	}
	// Reject an unsupported fleet publication mode before loading monitors,
	// seeding a fallback, creating aliases, or starting any network client.
	if *serverURL != "" {
		if err := checkPolicyRevisionSupport(); err != nil {
			log.Fatal(err)
		}
	}
	// Print banner
	printBanner()

	// Check for elevated privileges (root on Unix, Administrator on Windows)
	if !isElevated() {
		log.Fatal("❌ This program must be run with elevated privileges (root on Linux/macOS, Administrator on Windows)")
	}

	pub, err := loadVerifyKey(*verifyKey)
	if err != nil {
		log.Fatalf("❌ %v", err)
	}

	log.Printf("Policy: %s", *policyPath)
	if pub != nil {
		log.Printf("Policy Signature Key: %s (unsigned or invalid policies are refused)", *verifyKey)
	}
	log.Printf("Stats Interval: %v", *statsInterval)
	log.Printf("Log Level: %s", *logLevel)
	log.Printf("Metrics Port: %d", *metricsPort)
	log.Printf("Audit Mode: %v", *auditMode)
	log.Printf("LSM Enforce: %v", *lsmEnforce)
	log.Printf("Require LSM: %v", *requireLSM)
	if *defaultDeny {
		log.Printf("Default-Deny: requested (kernel refuses exec/connect the policy does not allow)")
	}
	if *cgroupFilter != "" {
		log.Printf("Cgroup Filter: %s", *cgroupFilter)
	}
	log.Println("")

	ctx := context.Background()

	// Build cgroup filter list
	var cgroupPaths []string
	if *cgroupFilter != "" {
		for _, p := range strings.Split(*cgroupFilter, ",") {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				cgroupPaths = append(cgroupPaths, trimmed)
			}
		}
	}

	// Build streaming sinks from --event-sink flag
	var sinks []streaming.Sink
	if *eventSink != "" {
		for _, spec := range strings.Split(*eventSink, ",") {
			spec = strings.TrimSpace(spec)
			switch {
			case spec == "stdout":
				sinks = append(sinks, streaming.NewStdoutSink())
			case strings.HasPrefix(spec, "file:"):
				path := strings.TrimPrefix(spec, "file:")
				s, err := streaming.NewFileSink(path, *eventFileMax)
				if err != nil {
					log.Fatalf("event sink %s: %v", spec, err)
				}
				sinks = append(sinks, s)
			case strings.HasPrefix(spec, "webhook:"):
				url := strings.TrimPrefix(spec, "webhook:")
				headers := make(map[string]string)
				if *webhookHeader != "" {
					parts := strings.SplitN(*webhookHeader, ":", 2)
					if len(parts) == 2 {
						headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
					}
				}
				sinks = append(sinks, streaming.NewWebhookSink(streaming.WebhookConfig{
					URL:     url,
					Headers: headers,
				}))
			case strings.HasPrefix(spec, "syslog:"):
				rest := strings.TrimPrefix(spec, "syslog:")
				network := "udp"
				if i := strings.Index(rest, "://"); i >= 0 {
					network = rest[:i]
					rest = rest[i+3:]
				}
				if network != "udp" && network != "tcp" {
					log.Fatalf("event sink %s: network must be udp or tcp", spec)
				}
				if rest == "" {
					log.Fatalf("event sink %s: missing host:port", spec)
				}
				s, err := streaming.NewSyslogSink(streaming.SyslogConfig{Network: network, Addr: rest})
				if err != nil {
					log.Fatalf("event sink %s: %v", spec, err)
				}
				sinks = append(sinks, s)
			default:
				log.Fatalf("unknown event sink: %s (valid: stdout, file:<path>, webhook:<url>, syslog:[udp|tcp://]host:port)", spec)
			}
		}
		log.Printf("Event Sinks: %s", *eventSink)
	}

	// Web dashboard (--dashboard-port): served on its own HTTP server so
	// the SSE stream is not cut by the metrics server's write timeout.
	if *dashboardPort < 0 || *dashboardPort > 65535 {
		log.Fatal("dashboard port must be between 0 (off) and 65535")
	}
	if *dashboardPort != 0 {
		token, err := dashboard.LoadToken(*dashboardTokenFile)
		if err != nil {
			log.Fatalf("dashboard authentication: %v", err)
		}
		dashHandler := dashboard.New(200)
		dashboardServer, err := dashboard.NewServer(dashboard.ServerConfig{
			Bind: *dashboardBind, Port: *dashboardPort, Token: token,
		}, dashHandler)
		if err != nil {
			log.Fatalf("dashboard server: %v", err)
		}
		listener, err := net.Listen("tcp", dashboardServer.Addr)
		if err != nil {
			log.Fatalf("dashboard listen: %v", err)
		}
		defer dashboardServer.Close()
		sinks = append(sinks, dashboard.NewSink(dashHandler))
		go func() {
			if err := dashboardServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("dashboard server: %v", err)
			}
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = dashboardServer.Shutdown(shutdownCtx)
		}()
		log.Printf("✓ Web dashboard listening on http://%s/dashboard (authentication enabled: %t)", listener.Addr(), token != "")
		if addr, ok := listener.Addr().(*net.TCPAddr); !ok || !addr.IP.IsLoopback() {
			log.Print("⚠ Dashboard remote access explicitly enabled; restrict network access and use a trusted TLS/authenticating reverse proxy (dashboard HTTP is plaintext)")
		}
	}

	// Parse event labels
	labels := make(map[string]string)
	if *eventLabels != "" {
		for _, kv := range strings.Split(*eventLabels, ",") {
			parts := strings.SplitN(strings.TrimSpace(kv), "=", 2)
			if len(parts) == 2 {
				labels[parts[0]] = parts[1]
			}
		}
	}

	ringSize, err := parseByteSize(*lsmRingSize)
	if err != nil {
		log.Fatalf("❌ --lsm-ringbuf-size: %v", err)
	}
	if *onEventLoss != "log" && *onEventLoss != "deny" {
		log.Fatalf("❌ invalid --on-event-loss %q (valid: log, deny)", *onEventLoss)
	}

	digests, err := loadIntegrityDigests(*integrityMode, *integrityDB)
	if err != nil {
		log.Fatalf("❌ %v", err)
	}

	// Bootstrap server-managed deployments: seed the policy path from the
	// fallback if nothing is there yet (see seedPolicyFile).
	if err := seedPolicyFile(*policyPath, *policyFallback, pub != nil); err != nil {
		log.Fatalf("❌ %v", err)
	}

	// Create enforcer with options
	enf, err := enforcer.New(ctx, *policyPath, &enforcer.Options{
		AuditMode:               *auditMode,
		CgroupFilter:            cgroupPaths,
		CgroupRoot:              *cgroupRoot,
		CgroupReconcileInterval: *cgroupReconcileInterval,
		MetricsBindAddress:      *metricsBindAddress,
		MetricsPort:             *metricsPort,
		LogLevel:                *logLevel,
		LSMEnforce:              *lsmEnforce,
		RequireLSM:              *requireLSM,
		SkipLSM:                 *noLSM,
		StreamSinks:             sinks,
		Labels:                  labels,

		PolicyVerifyKey:  pub,
		EvalTimeout:      *evalTimeout,
		IntegrityMode:    *integrityMode,
		IntegrityDigests: digests,
		EscapeDetect:     *escapeDetect,

		LSMRingBufferSize: ringSize,
		OnEventLoss:       *onEventLoss,
		DefaultDeny:       *defaultDeny,
		AtomicGenerations: *atomicGenerations,
		SupervisedBackend: hostConfig,
		AttackGraph:       *attackGraph,
		Drift:             *driftEnabled,
	})
	if err != nil {
		log.Fatalf("❌ Failed to create enforcer: %v", err)
	}
	defer enf.Close()

	if *driftImageKey != "" {
		log.Printf("⚠️  --drift-image-key is deprecated and ignored: policy hashes and operator grouping keys are not workload image identity")
	}
	if *driftEnabled {
		log.Printf("Drift: bounded local host collection enabled; fingerprints omitted from heartbeats until real workload identity is available")
	}
	// Do not label the host aggregate with a policy hash or operator key.
	// Ordinary heartbeats must still succeed when workload identity is absent.
	var policyClient *policyserver.Client
	if *serverURL != "" {
		clientCfg := policyClientConfig{
			ServerURL: *serverURL,
			Token:     *serverToken,
			CAFile:    *tlsCA,
			CertFile:  *tlsCert,
			KeyFile:   *tlsKey,
			AgentID:   *agentID,
			Labels:    labels,
			Verify:    verifyDownload(pub),
		}
		if *driftEnabled {
			clientCfg.Fingerprint = identifiedDriftFingerprint(enf.DriftFingerprint)
		}
		var err error
		policyClient, err = newPolicyClient(clientCfg, policyUpdateHandler(*policyPath, pub, enf.ActivatePolicy))
		if err != nil {
			log.Fatalf("❌ Policy server: %v", err)
		}
		log.Printf("Policy Server: %s", *serverURL)
	}

	log.Println("")
	log.Println("✓ warmor enforcer initialized successfully")
	log.Println("")

	// Start enforcer
	if err := enf.Start(); err != nil {
		log.Fatalf("❌ Failed to start enforcer: %v", err)
	}

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	notifySignals(sigChan)

	// Fleet mode owns activation; do not run a second competing file writer.
	stopWatcher := func() {}
	if policyClient == nil {
		stopWatcher = watchPolicyActivation(*policyPath, enf.ReloadPolicy, policyWatchInterval)
	}
	defer stopWatcher()

	if policyClient != nil {
		clientCtx, stopClient := context.WithCancel(ctx)
		defer stopClient()
		go runPolicyClient(clientCtx, policyClient, *pollInterval)
	}

	// Print stats periodically
	statsTicker := time.NewTicker(*statsInterval)
	defer statsTicker.Stop()

	log.Println("🚀 warmor is running. Press Ctrl+C to stop.")
	log.Println("")

	for {
		select {
		case sig := <-sigChan:
			if isReloadSignal(sig) {
				log.Println("")
				log.Println("📥 Received reload signal")
				if err := reloadLocalPolicy(policyClient != nil, enf.ReloadPolicy); err != nil {
					log.Printf("❌ Failed to reload policy: %v", err)
				}
				log.Println("")
			} else if isShutdownSignal(sig) {
				log.Println("")
				log.Println("📥 Received shutdown signal")
				shutdown(enf)
				return
			}

		case <-stop:
			log.Println("")
			log.Println("📥 Service stop requested")
			shutdown(enf)
			return

		case <-statsTicker.C:
			log.Println("")
			enf.PrintStats()
			log.Println("")
		}
	}
}

func shutdown(enf *enforcer.Enforcer) {
	enf.Stop()
	log.Println("")
	log.Println("=== Final Statistics ===")
	enf.PrintStats()
	log.Println("")
	log.Println("👋 warmor shutdown complete")
}

func printBanner() {
	banner := fmt.Sprintf(`
╦ ╦╔═╗╦═╗╔╦╗╔═╗╦═╗
║║║╠═╣╠╦╝║║║║ ║╠╦╝
╚╩╝╩ ╩╩╚═╩ ╩╚═╝╩╚═
WASM-Powered Security Enforcer
Version: %s
`, version.Version)
	log.Println(banner)
}
