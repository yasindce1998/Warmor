package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/yasindce1998/warmor/internal/enforcer"
	"github.com/yasindce1998/warmor/internal/policyserver"
	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/internal/version"
)

var (
	policyPath    = flag.String("policy", "policies/example/policy.wasm", "Path to WASM policy file")
	statsInterval = flag.Duration("stats-interval", 30*time.Second, "Statistics reporting interval")
	logLevel      = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	metricsPort   = flag.Int("metrics-port", 9090, "Prometheus metrics port")
	auditMode     = flag.Bool("audit", false, "Audit mode: log deny decisions without enforcing")
	cgroupFilter  = flag.String("cgroup-filter", "", "Cgroup paths to filter (comma-separated, or 'auto' for K8s pod discovery)")
	lsmEnforce    = flag.Bool("lsm-enforce", false, "Enable LSM-BPF kernel-level blocking (requires CONFIG_BPF_LSM)")
	requireLSM    = flag.Bool("require-lsm", false, "Fail to start unless BPF-LSM kernel enforcement can be loaded (fail-closed; default is to degrade to observe-only)")
	noLSM         = flag.Bool("no-lsm", false, "Skip LSM-BPF loading entirely (tracepoint-only observe mode)")
	eventSink     = flag.String("event-sink", "", "Event sinks: stdout, file:<path>, webhook:<url> (comma-separated)")
	eventFileMax  = flag.Int64("event-file-max", 100*1024*1024, "Max event file size before rotation (bytes)")
	webhookHeader = flag.String("webhook-header", "", "Webhook auth header (format: Key:Value)")
	eventLabels   = flag.String("event-labels", "", "Labels to attach to streamed events and report to the policy server (format: k=v,k2=v2)")
	showVersion   = flag.Bool("version", false, "Show version and exit")
	evalTimeout   = flag.Duration("eval-timeout", 50*time.Millisecond, "Deadline for one WASM policy evaluation; a policy exceeding it is denied (fail closed)")

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
			default:
				log.Fatalf("unknown event sink: %s (valid: stdout, file:<path>, webhook:<url>)", spec)
			}
		}
		log.Printf("Event Sinks: %s", *eventSink)
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

	var policyClient *policyserver.Client
	if *serverURL != "" {
		var err error
		policyClient, err = newPolicyClient(policyClientConfig{
			ServerURL: *serverURL,
			Token:     *serverToken,
			CAFile:    *tlsCA,
			CertFile:  *tlsCert,
			KeyFile:   *tlsKey,
			AgentID:   *agentID,
			Labels:    labels,
			Verify:    verifyDownload(pub),
		}, policyUpdateHandler(*policyPath, reloadCh))
		if err != nil {
			log.Fatalf("❌ Policy server: %v", err)
		}
		log.Printf("Policy Server: %s", *serverURL)
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

	// Create enforcer with options
	enf, err := enforcer.New(ctx, *policyPath, &enforcer.Options{
		AuditMode:    *auditMode,
		CgroupFilter: cgroupPaths,
		MetricsPort:  *metricsPort,
		LogLevel:     *logLevel,
		LSMEnforce:   *lsmEnforce,
		RequireLSM:   *requireLSM,
		SkipLSM:      *noLSM,
		StreamSinks:  sinks,
		Labels:       labels,

		PolicyVerifyKey:  pub,
		EvalTimeout:      *evalTimeout,
		IntegrityMode:    *integrityMode,
		IntegrityDigests: digests,
		EscapeDetect:     *escapeDetect,

		LSMRingBufferSize: ringSize,
		OnEventLoss:       *onEventLoss,
	})
	if err != nil {
		log.Fatalf("❌ Failed to create enforcer: %v", err)
	}
	defer enf.Close()

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
