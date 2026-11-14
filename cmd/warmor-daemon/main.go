package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yasindce1998/warmor/internal/dashboard"
	"github.com/yasindce1998/warmor/internal/drift"
	"github.com/yasindce1998/warmor/internal/enforcer"
	"github.com/yasindce1998/warmor/internal/policyserver"
	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/internal/version"
)

var (
	policyPath     = flag.String("policy", "policies/example/policy.wasm", "Path to WASM policy file")
	policyFallback = flag.String("policy-fallback", "", "If --policy does not exist at startup, seed it from this file (e.g. the policy baked into the container image) so server-managed deployments can bootstrap before the first download; cannot be combined with --verify-key")
	statsInterval  = flag.Duration("stats-interval", 30*time.Second, "Statistics reporting interval")
	logLevel       = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	metricsPort    = flag.Int("metrics-port", 9090, "Prometheus metrics port")
	auditMode      = flag.Bool("audit", false, "Audit mode: log deny decisions without enforcing")
	cgroupFilter   = flag.String("cgroup-filter", "", "Cgroup paths to filter (comma-separated, or 'auto' for K8s pod discovery)")
	lsmEnforce     = flag.Bool("lsm-enforce", false, "Enable LSM-BPF kernel-level blocking (requires CONFIG_BPF_LSM)")
	requireLSM     = flag.Bool("require-lsm", false, "Fail to start unless BPF-LSM kernel enforcement can be loaded (fail-closed; default is to degrade to observe-only)")
	noLSM          = flag.Bool("no-lsm", false, "Skip LSM-BPF loading entirely (tracepoint-only observe mode)")
	defaultDeny    = flag.Bool("default-deny", false, "Refuse in-kernel (EPERM) what the policy does not allow: preload the policy's static allow rules and deny policy-map misses (requires --lsm-enforce and an allowlist policy: default_action deny + exact eq rules; see docs/design/kernel-default-deny.md)")
	eventSink      = flag.String("event-sink", "", "Event sinks: stdout, file:<path>, webhook:<url>, syslog:[udp|tcp://]host:port (comma-separated)")
	eventFileMax   = flag.Int64("event-file-max", 100*1024*1024, "Max event file size before rotation (bytes)")
	webhookHeader  = flag.String("webhook-header", "", "Webhook auth header (format: Key:Value)")
	eventLabels    = flag.String("event-labels", "", "Labels to attach to streamed events and report to the policy server (format: k=v,k2=v2)")
	attackGraph    = flag.Bool("attack-graph", false, "Build the MITRE attack graph and blast-radius metrics from observed events (labels streamed events with technique IDs)")
	dashboardPort  = flag.Int("dashboard-port", 0, "Serve the web dashboard (SSE) on this port (0 = off)")
	driftEnabled   = flag.Bool("drift", false, "Fingerprint observed behavior (event-type+comm rates) and ship it in policy server heartbeats for fleet drift detection (requires --server)")
	driftImageKey  = flag.String("drift-image-key", "", "Grouping key for the fleet drift comparison: agents reporting the same key are compared (default: SHA-256 of the policy file)")
	showVersion    = flag.Bool("version", false, "Show version and exit")
	evalTimeout    = flag.Duration("eval-timeout", 50*time.Millisecond, "Deadline for one WASM policy evaluation; a policy exceeding it is denied (fail closed)")

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
	var dashboardServer *http.Server
	if *dashboardPort > 0 {
		dashHandler := dashboard.New(200)
		sinks = append(sinks, dashboard.NewSink(dashHandler))
		mux := http.NewServeMux()
		mux.Handle("/dashboard", dashHandler)
		mux.Handle("/dashboard/events", dashHandler)
		dashboardServer = &http.Server{
			Addr:    fmt.Sprintf(":%d", *dashboardPort),
			Handler: mux,
			// No WriteTimeout: /dashboard/events is a long-lived SSE stream.
		}
		go func() {
			if err := dashboardServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("dashboard server: %v", err)
			}
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = dashboardServer.Shutdown(shutdownCtx)
		}()
		log.Printf("✓ Web dashboard on http://localhost:%d/dashboard", *dashboardPort)
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

	// Policy updates from the server and file changes both trigger a reload.
	reloadCh := make(chan struct{}, 1)

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
		AttackGraph:       *attackGraph,
		Drift:             *driftEnabled,
	})
	if err != nil {
		log.Fatalf("❌ Failed to create enforcer: %v", err)
	}
	defer enf.Close()

	// The policy server client is created after the enforcer so that,
	// with --drift, each heartbeat can attach the enforcer's current
	// behavioral fingerprint.
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
			clientCfg.Fingerprint = func() *drift.BehaviorFingerprint {
				fp := enf.DriftFingerprint()
				if fp == nil {
					return nil
				}
				fp.ImageHash = resolveDriftImageKey(*policyPath, *driftImageKey)
				return fp
			}
		}
		var err error
		policyClient, err = newPolicyClient(clientCfg, policyUpdateHandler(*policyPath, reloadCh))
		if err != nil {
			log.Fatalf("❌ Policy server: %v", err)
		}
		log.Printf("Policy Server: %s", *serverURL)
		if *driftEnabled {
			log.Printf("Drift Detection: fingerprints shipped in heartbeats (image key: %s)", resolveDriftImageKey(*policyPath, *driftImageKey))
		}
	} else if *driftEnabled {
		log.Printf("⚠️  --drift requires --server; fingerprints are only shipped in policy server heartbeats")
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

	// Start policy file watcher (active on Windows; no-op on Unix where SIGHUP is used)
	stopWatcher := startPolicyWatcher(*policyPath, reloadCh)
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
				log.Println("📥 Received reload signal, reloading policy...")
				if err := enf.ReloadPolicy(); err != nil {
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

		case <-reloadCh:
			log.Println("")
			log.Println("📥 Policy file changed, reloading...")
			if err := enf.ReloadPolicy(); err != nil {
				log.Printf("❌ Failed to reload policy: %v", err)
			}
			log.Println("")

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
