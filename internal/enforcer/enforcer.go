package enforcer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/yasindce1998/warmor/internal/cache"
	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/container"
	"github.com/yasindce1998/warmor/internal/crypto/assignment"
	"github.com/yasindce1998/warmor/internal/drift"
	"github.com/yasindce1998/warmor/internal/escape"
	"github.com/yasindce1998/warmor/internal/kernelmap"
	"github.com/yasindce1998/warmor/internal/lineage"
	"github.com/yasindce1998/warmor/internal/logging"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/platform"
	"github.com/yasindce1998/warmor/internal/policyhost"
	"github.com/yasindce1998/warmor/internal/policymeta"
	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/internal/telemetry"
	"github.com/yasindce1998/warmor/internal/version"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Options configures the enforcer at startup
type Options struct {
	// Platform injects an embedded monitor implementation. Nil uses the native
	// platform. Capability/posture checks still apply; no daemon flag exposes it.
	Platform                platform.Platform
	AuditMode               bool
	LearningMode            bool
	CgroupFilter            []string
	CgroupRoot              string
	CgroupReconcileInterval time.Duration
	MetricsBindAddress      string
	MetricsPort             int
	LogLevel                string
	LSMEnforce              bool
	// RequireLSM refuses to start unless BPF-LSM kernel enforcement can be
	// established (fail-closed startup). Without it, an unsupported kernel
	// degrades to tracepoint-only observation.
	RequireLSM bool
	SkipLSM    bool

	// PolicyVerifyKey, when set, makes every policy load (startup and
	// ReloadPolicy) require a valid detached ed25519 signature at
	// <policy>.sig. The policy file is read once, verified, and loaded from
	// memory; YAML policies are refused.
	PolicyVerifyKey ed25519.PublicKey
	// SignedAssignment is the standalone signed-daemon mode. It enables strict
	// artifact/ABI/posture checks and refuses Host/generation combinations before
	// side effects until their sole-store commit model is validated.
	SignedAssignment *assignment.Policy
	// EvalTimeout bounds each WASM policy evaluation; an evaluation that
	// exceeds it is denied (fail closed) and its instance replaced. Zero
	// means wasm.DefaultEvalTimeout.
	EvalTimeout time.Duration
	// IntegrityMode ("off", "audit", "enforce") and IntegrityDigests (hex
	// SHA-256 allowlist) configure the kernel content-hash exec check.
	IntegrityMode    string
	IntegrityDigests []string

	// EscapeDetect is the container escape detection mode: "off", "alert"
	// (log, count and stream matches) or "deny" (also terminate the process).
	EscapeDetect string

	// LSMRingBufferSize (bytes, 0 = default) and OnEventLoss ("log" or
	// "deny") configure the kernel event ring; see platform.Config.
	LSMRingBufferSize uint32
	OnEventLoss       string

	// DefaultDeny preloads the policy's static allow rules into the kernel
	// policy map and marks the eligible domains default-deny, so the BPF
	// LSM hooks refuse (EPERM) what the policy does not allow instead of
	// allowing what they have not seen. Requires an eligible policy
	// (default_action: deny, exact eq rules on the kernel key); see
	// docs/design/kernel-default-deny.md.
	DefaultDeny bool
	// AtomicGenerations opts into experimental Linux generation activation.
	// Off by default pending supported-kernel combined VM validation.
	AtomicGenerations bool
	// SupervisedBackend explicitly opts into the experimental pinned child
	// backend. Requires PolicyVerifyKey; nil preserves the in-process default.
	SupervisedBackend *policyhost.Config
	// ExpectedAssignment is the existing embedded metadata-validation seam.
	// The caller owns verification/commit; it cannot combine with generations
	// or SignedAssignment. It does not opt into signed-daemon Host support.
	ExpectedAssignment *assignment.Policy

	// AttackGraph enables the node-side intelligence chain: MITRE
	// correlation, the per-container attack graph and blast-radius
	// metrics (see docs/design/intelligence-chain.md).
	AttackGraph bool

	// Drift enables bounded local event-type+comm rates in the streaming
	// pipeline. Host aggregates are not submitted for fleet comparison until
	// genuine workload identity and scoped collection are available (see
	// docs/design/fleet-drift.md); no server is required for local collection.
	Drift bool
	// Telemetry is an optional bounded per-activation collector. No fleet gate
	// is enabled by supplying it; activation must use ActivatePolicyTelemetry.
	// SignedAssignment seals/disables legacy telemetry until a signed attribution
	// contract exists; it cannot authorize a signed deployment's collector.
	Telemetry *telemetry.Collector

	// Streaming pipeline configuration
	StreamSinks []streaming.Sink
	Labels      map[string]string

	// Advanced enforcement
	NetFilterConfig *NetFilterConfig
	SandboxProfiles []*SandboxProfile
}

// PolicyMapSyncer compiles WASM policy decisions into a kernel BPF map for fast-path enforcement.
type PolicyMapSyncer interface {
	SetRule(cgroupID uint64, eventType uint8, pattern string, action uint8, audit bool) error
	// Clear removes every decision from the kernel map. It is called after a
	// successful policy reload so the kernel never keeps enforcing decisions
	// made by the previous policy.
	Clear() error
}

// Enforcer integrates platform-specific event capture (eBPF/ETW/ESF) with
// WASM policy evaluation.
type Enforcer struct {
	platform    platform.Platform
	eventChan   chan *api.Event
	wasmRuntime *wasm.Runtime
	evaluatorMu sync.RWMutex
	// An event holds the drain barrier through cache lookup, evaluation,
	// persistence, action and reporting. Reload/close retire only drained pools.
	activationMu     sync.Mutex
	eventMu          sync.RWMutex
	closed           bool
	evaluator        Evaluator
	backend          *policyBackend
	supervisor       *policyhost.Supervisor
	signedAssignment bool
	kernelEnforce    bool
	requireLSM       bool
	pool             *wasm.Pool
	cache            *cache.DecisionCache
	actionHandler    *ActionHandler
	logger           *logging.Logger
	metricsServer    *metrics.Server
	policyMap        PolicyMapSyncer
	// decisionMu orders persisting decisions (decision cache and kernel
	// map) against the reset on reload: persistDecision holds it shared,
	// ReloadPolicy holds it exclusively while clearing both.
	decisionMu sync.RWMutex
	// policyGen is bumped (under evaluatorMu) every time a new policy is
	// swapped in. A decision is only written to the kernel map if the policy
	// that made it is still current, so an evaluation that was in flight
	// during a reload cannot repopulate the map with a stale decision after
	// it was cleared.
	policyGen      atomic.Uint64
	generations    *generationDispatch
	pipeline       *streaming.Pipeline
	lineageTracker *lineage.Tracker
	// intelligence is non-nil when --attack-graph is set (MITRE attack
	// graph + blast radius).
	intelligence *intelligence
	// driftCollector is non-nil when --drift is set (local host observations;
	// fleet submission requires real workload identity, not a policy hash).
	driftCollector *drift.FingerprintCollector
	telemetry      *telemetry.Collector
	netFilter      *NetFilter
	sandbox        *SandboxManager
	escape         *escape.Detector
	// containerStarts dates the container of an event's cgroup for
	// policies that read container age (nil: always unknown).
	containerStarts containerStarter
	policyPath      string
	verifyKey       ed25519.PublicKey
	evalTimeout     time.Duration
	policyID        string // metrics label (see policyID()); guarded by evaluatorMu
	syncFailLog     logLimiter
	auditMode       bool
	learningMode    bool
	defaultDeny     bool
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	stopOnce        sync.Once
	processing      atomic.Bool
}

// newPlatform constructs the platform monitor. It is a variable so tests can
// substitute a fake that does not require root or kernel support.
var newPlatform = platform.New

// New creates a new enforcer instance with Phase 2 features
func New(ctx context.Context, policyPath string, opts *Options) (*Enforcer, error) {
	if opts == nil {
		opts = &Options{}
	}
	// Normalize once before loading any hooks. Audit/learning are global
	// dry runs, including independent integrity enforcement. Copy options
	// so the caller's requested posture remains unchanged.
	effective := *opts
	if effective.SignedAssignment != nil && effective.ExpectedAssignment != nil {
		return nil, errors.New("specify only SignedAssignment or ExpectedAssignment, not both")
	}
	if effective.SignedAssignment != nil {
		if effective.SupervisedBackend != nil {
			return nil, errors.New("signed daemon mode with supervised backend is unsupported until its sole-store commit model is tested")
		}
		effective.ExpectedAssignment = effective.SignedAssignment
	}
	if effective.AuditMode || effective.LearningMode {
		effective.LSMEnforce = false
		if effective.IntegrityMode == "enforce" {
			effective.IntegrityMode = "audit"
		}
	}
	opts = &effective
	if opts.AtomicGenerations && opts.Telemetry != nil {
		return nil, errors.New("legacy telemetry attribution with atomic generations is unsupported")
	}
	if opts.ExpectedAssignment != nil && opts.AtomicGenerations {
		return nil, errors.New("signed assignments with atomic generations are unsupported until one commit/recovery model is validated")
	}
	if opts.AtomicGenerations && (runtime.GOOS != "linux" || opts.SkipLSM || !opts.RequireLSM) {
		return nil, errors.New("atomic generations require Linux --require-lsm without --no-lsm")
	}
	if opts.AtomicGenerations && wasm.IsYAMLPolicy(policyPath) {
		return nil, errors.New("atomic generations require a compiled WASM startup policy")
	}
	var supervisor *policyhost.Supervisor
	if opts.SupervisedBackend != nil {
		if len(opts.PolicyVerifyKey) != ed25519.PublicKeySize || wasm.IsYAMLPolicy(policyPath) {
			return nil, errors.New("supervised backend requires a verification key and compiled signed WASM")
		}
		var err error
		supervisor, err = policyhost.New(*opts.SupervisedBackend)
		if err != nil {
			return nil, fmt.Errorf("supervised backend: %w", err)
		}
	}
	if opts.ExpectedAssignment != nil && len(opts.PolicyVerifyKey) != ed25519.PublicKeySize {
		return nil, errors.New("signed assignment mode requires an artifact verification key")
	}
	if opts.ExpectedAssignment != nil && opts.Telemetry != nil {
		// Schema-1 attribution requires a fully drained legacy activation.
		// Neither signed deployment nor overlapping captured generations may
		// reuse that single collector without its own reviewed identity model.
		opts.Telemetry.Seal()
		opts.Telemetry = nil
	}

	port := opts.MetricsPort
	if port == 0 {
		port = 9090
	}

	// Initialize logger at the requested level (--log-level). An empty
	// level means the default; an unknown one is a configuration error
	// rather than something to silently ignore.
	logLevel := opts.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	if _, err := zerolog.ParseLevel(logLevel); err != nil {
		return nil, fmt.Errorf("invalid log level %q: %w", opts.LogLevel, err)
	}
	logger := logging.NewLogger(logLevel)
	logger.LogStartup(policyPath)
	if opts.AuditMode || opts.LearningMode {
		logger.LogInfo("Dry-run posture: kernel blocking and userspace termination disabled; integrity checks audit-only")
	}

	// Initialize network filter if configured. This only validates config,
	// so do it before acquiring the platform, WASM runtime, pool or pipeline
	// and a bad CIDR can't leak any of them.
	var netFilter *NetFilter
	if opts.NetFilterConfig != nil {
		nf, err := NewNetFilter(*opts.NetFilterConfig)
		if err != nil {
			return nil, fmt.Errorf("initialize net filter: %w", err)
		}
		netFilter = nf
		logger.LogInfo(fmt.Sprintf("✓ Network filter active (%d CIDRs blocked, rate limit=%d/window)",
			nf.BlocklistSize(), opts.NetFilterConfig.RateLimit))
	}

	// Verify the policy signature before acquiring any platform resource, so
	// an unsigned or tampered policy never gets as far as loading BPF.
	var verifiedPolicy []byte
	if opts.PolicyVerifyKey != nil && supervisor == nil {
		data, err := ReadVerifiedPolicy(policyPath, opts.PolicyVerifyKey)
		if err != nil {
			return nil, fmt.Errorf("verify policy: %w", err)
		}
		verifiedPolicy = data
		logger.LogInfo("✓ Policy signature verified")
	}

	// One resolver maps cgroup ids to containers for escape detection
	// (which only applies to container cgroups) and dates containers for
	// temporal policies. The detector is built before the platform so a bad
	// mode can't leak it.
	cgroupRoot := opts.CgroupRoot
	if cgroupRoot == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}
	cgroups := container.NewCgroupResolver(cgroupRoot)
	escapeDetector, err := newEscapeDetector(opts.EscapeDetect, cgroups.IsContainer)
	if err != nil {
		return nil, err
	}
	var unixWatch []string
	if escapeDetector != nil {
		unixWatch = escape.RuntimeSockets
	}
	var backend *policyBackend
	if supervisor != nil {
		backend, err = startSupervisedBackend(ctx, supervisor, policyPath, opts.PolicyVerifyKey)
		if err != nil {
			return nil, err
		}
		// Any startup failure before ownership transfer retires/reaps our child.
		defer func() {
			if backend != nil {
				backend.close()
			}
		}()
	}

	// Initialize the platform-specific monitor (eBPF on Linux, ETW on
	// Windows, ESF on macOS).
	plat := opts.Platform
	if plat == nil {
		plat, err = newPlatform(platform.Config{
			CgroupFilter:            opts.CgroupFilter,
			CgroupRoot:              cgroupRoot,
			CgroupReconcileInterval: opts.CgroupReconcileInterval,
			LSMEnforce:              opts.LSMEnforce,
			RequireLSM:              opts.RequireLSM,
			SkipLSM:                 opts.SkipLSM,
			AuditMode:               opts.AuditMode || opts.LearningMode,

			IntegrityMode:    opts.IntegrityMode,
			IntegrityDigests: opts.IntegrityDigests,
			UnixWatch:        unixWatch,

			LSMRingBufferSize: opts.LSMRingBufferSize,
			OnEventLoss:       opts.OnEventLoss,
		})
	}
	if err != nil {
		return nil, fmt.Errorf("initialize platform: %w", err)
	}
	logger.LogInfo(fmt.Sprintf("Loading %s platform monitor...", plat.Name()))
	if err := plat.Load(ctx); err != nil {
		plat.Close()
		return nil, fmt.Errorf("load platform: %w", err)
	}
	logger.LogInfo(fmt.Sprintf("✓ %s platform loaded", plat.Name()))

	caps := plat.Capabilities()
	// Loaded LSM hooks are not proof that their blocking toggle was enabled.
	// Require an explicit initialized status for signed default-deny claims.
	kernelBlocking := false
	if status, ok := plat.(platform.LSMBlocking); ok {
		kernelBlocking = opts.LSMEnforce && caps.LSMEnforcement && status.LSMBlocking()
	}
	// Degraded if kernel LSM enforcement was asked for but is not active
	// (RequireLSM already failed Load in that case).
	metrics.SetEBPFLoaderStatus(caps.LSMEnforcement || !opts.LSMEnforce)
	var policyMapSyncer PolicyMapSyncer
	if caps.LSMEnforcement {
		if kernelBlocking {
			logger.LogInfo("✓ LSM-BPF kernel blocking initialized")
		} else {
			logger.LogInfo("LSM-BPF hooks loaded; kernel blocking is not established")
		}
		if pm, ok := plat.PolicyMap().(PolicyMapSyncer); ok {
			policyMapSyncer = pm
		}
	}

	// Supervised readiness includes child-observed metadata and precedes any
	// kernel preparation. This branch never constructs a parent WASM runtime.
	if supervisor == nil {
		// Create WASM runtime with compilation cache
		logger.LogInfo("Creating WASM runtime...")
		wasmRuntime, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{
			CacheDir: wasm.DefaultCacheDir(),
			PoolSize: runtime.NumCPU(),
		})
		if err != nil {
			plat.Close()
			return nil, fmt.Errorf("create WASM runtime: %w", err)
		}
		logger.LogInfo("✓ WASM runtime created (compilation cache enabled)")

		// Load policy (supports both .wasm and .yaml/.yml)
		pid := policyID(policyPath)
		logger.LogInfo(fmt.Sprintf("Loading policy from: %s", policyPath))
		if verifiedPolicy != nil {
			if err := wasmRuntime.LoadPolicyBytes(ctx, verifiedPolicy); err != nil {
				wasmRuntime.Close(ctx)
				plat.Close()
				return nil, fmt.Errorf("load policy: %w", err)
			}
		} else if wasm.IsYAMLPolicy(policyPath) {
			logger.LogInfo("Detected YAML policy, compiling...")
			if err := wasmRuntime.LoadPolicyFromYAML(ctx, policyPath); err != nil {
				metrics.RecordPolicyLoad(pid, err)
				wasmRuntime.Close(ctx)
				plat.Close()
				return nil, fmt.Errorf("load YAML policy: %w", err)
			}
		} else {
			if err := wasmRuntime.LoadPolicy(ctx, policyPath); err != nil {
				metrics.RecordPolicyLoad(pid, err)
				wasmRuntime.Close(ctx)
				plat.Close()
				return nil, fmt.Errorf("load policy: %w", err)
			}
		}
		logger.LogInfo("✓ Policy loaded")

		backend, err = inProcessBackend(ctx, wasmRuntime, opts.EvalTimeout)
		metrics.RecordPolicyLoad(pid, err)
		if err != nil {
			plat.Close()
			return nil, fmt.Errorf("create policy pool: %w", err)
		}
	}
	evaluator := backend.evaluator
	pid := policyID(policyPath)

	// Initialize decision cache (10k entries, 5min TTL)
	decisionCache := cache.NewDecisionCache(10000, 5*time.Minute)
	setCacheDependencies(decisionCache, evaluator)
	logger.LogInfo("✓ Decision cache initialized (10k-entry LRU, 5min TTL)")

	// Initialize action handler
	actionHandler := NewActionHandler(opts.AuditMode)

	// Initialize metrics server
	metricsServer := metrics.NewServer(port)
	if opts.MetricsBindAddress != "" {
		metricsServer = metrics.NewServerAddress(net.JoinHostPort(opts.MetricsBindAddress, strconv.Itoa(port)))
	}
	metrics.SetPolicyInfo(policyPath, version.Version)
	logger.LogInfo(fmt.Sprintf("✓ Metrics server initialized on :%d", port))

	// Initialize process lineage tracker
	tracker := lineage.NewTracker(lineage.TrackerConfig{})

	// Initialize streaming pipeline if sinks configured
	var pipeline *streaming.Pipeline
	var intel *intelligence
	var driftCollector *drift.FingerprintCollector
	if len(opts.StreamSinks) > 0 || opts.AttackGraph || opts.Drift {
		enrichers := []streaming.Enricher{lineage.NewEnricher(tracker)}
		if escapeDetector != nil {
			enrichers = append(enrichers, escapeDetector)
		}
		if opts.AttackGraph {
			var intelEnrichers []streaming.Enricher
			intel, intelEnrichers = newIntelligence()
			enrichers = append(enrichers, intelEnrichers...)
		}
		if opts.Drift {
			var driftEnricher streaming.Enricher
			driftCollector, driftEnricher = newDriftCollector()
			enrichers = append(enrichers, driftEnricher)
		}
		pipeline = streaming.NewPipeline(streaming.PipelineConfig{
			Sinks:     opts.StreamSinks,
			Labels:    opts.Labels,
			Enrichers: enrichers,
		})
		logger.LogInfo(fmt.Sprintf("✓ Streaming pipeline active (%d sinks)", len(opts.StreamSinks)))
		if intel != nil {
			logger.LogInfo("✓ Attack graph active (MITRE correlation, blast radius)")
		}
		if driftCollector != nil {
			logger.LogInfo("✓ Drift fingerprinting active (shipped in policy server heartbeats)")
		}
	}

	// Initialize sandbox manager
	sandboxProfiles := opts.SandboxProfiles
	if sandboxProfiles == nil {
		sandboxProfiles = DefaultProfiles()
	}
	sandboxMgr := NewSandboxManager(sandboxProfiles...)
	logger.LogInfo(fmt.Sprintf("✓ Sandbox manager active (%d profiles)", len(sandboxMgr.ListProfiles())))

	ctx, cancel := context.WithCancel(ctx)

	e := &Enforcer{
		platform:         plat,
		wasmRuntime:      backend.runtime,
		evaluator:        evaluator,
		pool:             backend.pool,
		backend:          backend,
		supervisor:       supervisor,
		signedAssignment: opts.ExpectedAssignment != nil,
		kernelEnforce:    kernelBlocking,
		requireLSM:       opts.RequireLSM,
		cache:            decisionCache,
		actionHandler:    actionHandler,
		logger:           logger,
		metricsServer:    metricsServer,
		policyMap:        policyMapSyncer,
		pipeline:         pipeline,
		lineageTracker:   tracker,
		intelligence:     intel,
		driftCollector:   driftCollector,
		telemetry:        opts.Telemetry,
		netFilter:        netFilter,
		sandbox:          sandboxMgr,
		escape:           escapeDetector,
		containerStarts:  cgroups,
		policyPath:       policyPath,
		verifyKey:        append(ed25519.PublicKey(nil), opts.PolicyVerifyKey...),
		policyID:         pid,
		evalTimeout:      opts.EvalTimeout,
		auditMode:        opts.AuditMode,
		learningMode:     opts.LearningMode,
		defaultDeny:      opts.DefaultDeny,
		ctx:              ctx,
		cancel:           cancel,
	}
	backend = nil // e now owns the complete backend lifetime
	if opts.ExpectedAssignment != nil {
		if opts.SignedAssignment != nil && opts.SignedAssignment.Posture.Mode == "enforce" && !caps.Enforcement {
			_ = e.Close()
			return nil, fmt.Errorf("%w: platform enforcement unavailable", assignment.ErrCompatibility)
		}
		if opts.SignedAssignment != nil && opts.SignedAssignment.Posture.RequireDefaultDeny && !opts.RequireLSM {
			_ = e.Close()
			return nil, fmt.Errorf("%w: signed required default-deny needs --require-lsm", assignment.ErrCompatibility)
		}
		if err := e.checkAssignment(e.evaluator, *opts.ExpectedAssignment); err != nil {
			_ = e.Close()
			return nil, err
		}
	}

	metricsServer.SetReadinessCheck(e.Ready)

	// Preload the kernel default-deny domains from the policy's static
	// rules. No events flow yet; decisionMu is uncontended but held for
	// symmetry with the reload path.
	var activationErr error
	if opts.AtomicGenerations {
		gp, ok := plat.(platform.GenerationPlatform)
		if !ok {
			activationErr = errors.New("platform lacks atomic generation dispatch")
		} else {
			activationErr = e.enableGenerations(gp)
		}
	} else {
		e.decisionMu.Lock()
		activationErr = e.applyDefaultDeny(evaluator)
		e.decisionMu.Unlock()
	}
	if activationErr != nil {
		e.Close()
		return nil, fmt.Errorf("activate kernel default-deny: %w", activationErr)
	}

	return e, nil
}

// Start begins processing events
func (e *Enforcer) Start() error {
	// Start metrics server
	if err := e.metricsServer.Start(); err != nil {
		return fmt.Errorf("start metrics server: %w", err)
	}

	// Start platform event capture, delivering into our channel.
	e.eventChan = make(chan *api.Event, 1024)
	if err := e.platform.Start(e.ctx, e.eventChan); err != nil {
		return fmt.Errorf("start platform: %w", err)
	}

	// Start event processing
	e.wg.Add(1)
	go e.eventLoop()
	if e.generations != nil {
		e.activationMu.Lock()
		err := e.finishGeneration()
		e.activationMu.Unlock()
		if err != nil {
			return fmt.Errorf("initial generation drain: %w", err)
		}
	}

	if _, ok := e.policyMap.(policyMapCounter); ok {
		e.wg.Add(1)
		go e.mapEntriesLoop(mapEntriesInterval)
	}

	if e.intelligence != nil {
		e.wg.Add(1)
		go e.attackGraphMetricsLoop(attackGraphMetricsInterval)
	}
	e.startStateMaintenance()

	e.logger.LogInfo("Enforcer started, processing events...")
	return nil
}

// eventLoop consumes events delivered by the platform monitor and evaluates
// them with the WASM policy.
func (e *Enforcer) eventLoop() {
	defer e.wg.Done()
	e.processing.Store(true)
	defer e.processing.Store(false)

	for {
		select {
		case <-e.ctx.Done():
			return
		case event, ok := <-e.eventChan:
			if !ok {
				return
			}
			if event.DispatchBarrier != nil {
				close(event.DispatchBarrier)
				continue
			}
			e.handleEvent(event)
		}
	}
}

// handleEvent processes a single event with caching and metrics
func (e *Enforcer) handleEvent(event *api.Event) {
	defer event.GenerationContext.Complete()
	e.eventMu.RLock()
	defer e.eventMu.RUnlock()
	if e.closed {
		return
	}
	decisionCache := e.cache
	var captured *evaluationGeneration
	if e.generations != nil {
		captured = e.eventGeneration(event)
		if captured == nil {
			return
		}
		// Direct/internal dispatch may acquire its lease here rather than in
		// the platform. Completion is idempotent for pre-captured events.
		defer event.GenerationContext.Complete()
		decisionCache = captured.cache
	}
	metrics.RecordEventProcessed(event.GetType().String())
	if e.checkEscape(event) {
		return
	}
	if e.handleKernelVerdict(event) {
		return
	}

	// Record process exec in lineage tracker
	if event.GetType() == api.EventTypeProcess {
		filename := event.Filename
		if event.Process != nil {
			filename = event.Process.Filename
		}
		e.lineageTracker.RecordExec(event.PID, event.PPID, event.UID, event.GID, event.Comm, filename)
	}

	// Network filter: check blocklist and rate limit before policy eval
	if e.netFilter != nil && event.GetType() == api.EventTypeNetwork {
		remoteAddr := ""
		if event.Network != nil {
			remoteAddr = event.Network.RemoteAddr
		}
		if remoteAddr != "" && e.netFilter.IsBlocked(remoteAddr) {
			result := &api.ActionResult{
				Action:    api.ActionDeny,
				Reason:    fmt.Sprintf("network blocked: %s in CIDR blocklist", remoteAddr),
				Timestamp: time.Now(),
				// Learning mode records a would-deny but never kills.
				Audit: e.learningMode,
			}
			_ = e.actionHandler.Enforce(e.ctx, event, result)
			e.logger.LogEvent(event, result)
			metrics.RecordEvent(result.Action.String())
			if e.pipeline != nil {
				e.pipeline.Emit(event, result)
			}
			return
		}
		if e.netFilter.CheckRateLimit(event.PID) {
			result := &api.ActionResult{
				Action:    api.ActionDeny,
				Reason:    fmt.Sprintf("rate limit exceeded for pid %d", event.PID),
				Timestamp: time.Now(),
				// Learning mode records a would-deny but never kills.
				Audit: e.learningMode,
			}
			_ = e.actionHandler.Enforce(e.ctx, event, result)
			e.logger.LogEvent(event, result)
			metrics.RecordEvent(result.Action.String())
			if e.pipeline != nil {
				e.pipeline.Emit(event, result)
			}
			return
		}
	}

	// Sandbox violation check: if a sandboxed process attempts a restricted action
	if e.sandbox != nil {
		action := eventTypeToSandboxAction(event)
		if action != "" {
			if reason := e.sandbox.CheckViolation(event.PID, action); reason != "" {
				result := &api.ActionResult{
					Action:    api.ActionDeny,
					Reason:    reason,
					Timestamp: time.Now(),
					// Learning mode records a would-deny but never kills.
					Audit: e.learningMode,
				}
				_ = e.actionHandler.Enforce(e.ctx, event, result)
				e.logger.LogEvent(event, result)
				metrics.RecordEvent(result.Action.String())
				if e.pipeline != nil {
					e.pipeline.Emit(event, result)
				}
				return
			}
		}
	}

	// Learning mode: allow everything but still emit to pipeline for recording
	if e.learningMode {
		result := &api.ActionResult{
			Action:    api.ActionAllow,
			Reason:    "learning mode",
			Timestamp: time.Now(),
		}
		// Count the event in stats; an allow never kills or blocks anything.
		_ = e.actionHandler.Enforce(e.ctx, event, result)
		e.logger.LogEvent(event, result)
		metrics.RecordEvent(result.Action.String())
		if e.pipeline != nil {
			e.pipeline.Emit(event, result)
		}
		return
	}

	// Capture evaluator and generation together before consulting their cache.
	// A terminal supervised child must not keep serving earlier cached allows.
	e.evaluatorMu.RLock()
	evaluator := e.evaluator
	gen := e.policyGen.Load()
	pid := e.policyID
	e.evaluatorMu.RUnlock()
	if captured != nil {
		evaluator, gen, pid = captured.evaluator, captured.id, captured.policyID
	}
	cacheUsable := true
	if host, ok := evaluator.(*hostEvaluator); ok {
		cacheUsable = host.Alive()
	}
	var cachedResult *api.ActionResult
	var cacheHit bool
	if cacheUsable {
		cachedResult, cacheHit = decisionCache.Get(event)
	}
	if result := cachedResult; cacheHit {
		metrics.RecordCacheHit()
		_ = e.actionHandler.Enforce(e.ctx, event, result)
		e.logger.LogEvent(event, result)
		metrics.RecordEvent(result.Action.String())
		metrics.RecordLatency(float64(result.Latency.Microseconds()))
		e.recordTelemetryDecision(result, nil)
		if e.pipeline != nil {
			e.pipeline.Emit(event, result)
		}
		return
	}

	metrics.RecordCacheMiss()

	if evaluator.ReadsContainerAge(event.GetType()) {
		e.annotateContainerStart(event)
	}

	evalStart := time.Now()
	result, err := evaluator.Evaluate(e.ctx, event)
	metrics.RecordWASMExec(pid, time.Since(evalStart).Seconds(), err, errors.Is(err, wasm.ErrEvaluationTimeout))
	if err != nil {
		e.logger.LogError(err, "policy evaluation failed")
		metrics.RecordProcessingError()
		// Fail closed - deny on error
		result = &api.ActionResult{
			Action:    api.ActionDeny,
			Reason:    fmt.Sprintf("Evaluation error: %v", err),
			Timestamp: time.Now(),
			Cached:    false,
			Latency:   0,
		}
	} else {
		// Only persist real policy decisions. An error-derived deny is
		// transient and must not outlive this event, otherwise a single
		// failed evaluation would keep denying until the cache TTL expires
		// (or indefinitely in the kernel policy map).
		e.persistDecision(event, result, gen, evaluator)
	}

	// Enforce the decision
	_ = e.actionHandler.Enforce(e.ctx, event, result)
	e.recordTelemetryDecision(result, err)

	// Log the event
	e.logger.LogEvent(event, result)
	if result.Action == api.ActionDeny && !result.Audit {
		e.logger.LogDenial(event, result)
	}

	// Record metrics
	metrics.RecordEvent(result.Action.String())
	metrics.RecordLatency(float64(result.Latency.Microseconds()))
	if result.Audit {
		metrics.RecordAuditDenied()
	}

	// Emit to streaming pipeline
	if e.pipeline != nil {
		e.pipeline.Emit(event, result)
	}

	// Update cache size metric
	cacheStats := decisionCache.Stats()
	metrics.UpdateCacheSize(cacheStats.Size)
}

// kernelKeyFielder is implemented by policy maps to report which event fields
// (compiler field names, e.g. "path", "remote_addr") their kernel key for an
// event type covers. A syncer that does not implement it never receives
// decisions, since nothing can be proven about its keys.
type kernelKeyFielder interface {
	KernelKeyFields(t api.EventType) []string
}

// decisionDeterminedByKernelKey reports whether a decision of a policy that
// reads fieldsRead (for events of type t) depends only on fields the kernel
// key of pm covers.
func decisionDeterminedByKernelKey(pm PolicyMapSyncer, t api.EventType, fieldsRead uint32) bool {
	kf, ok := pm.(kernelKeyFielder)
	if !ok || fieldsRead == wasm.FieldsUnknown {
		return false
	}
	if fieldsRead&wasm.TemporalFields != 0 {
		// No kernel key holds the clock or container age: the kernel
		// would keep applying the decision after its window changed.
		return false
	}
	keyFields := kf.KernelKeyFields(t)
	if len(keyFields) == 0 {
		return false
	}
	return fieldsRead&^compiler.FieldMask(keyFields...) == 0
}

// policyID is the policy_id metrics label for a policy file: its base name.
func policyID(path string) string {
	if path == "" {
		return "unknown"
	}
	return filepath.Base(path)
}

// policyMapCounter is implemented by policy maps that can report their size
// (Linux PolicyMapManager.Stats).
type policyMapCounter interface {
	Stats() (int, error)
}

// mapEntriesInterval is how often warmor_ebpf_map_entries is refreshed;
// counting iterates the whole map, so it is not done per event.
const mapEntriesInterval = 15 * time.Second

// updateMapEntries refreshes warmor_ebpf_map_entries{map_name="policy_map"}.
func (e *Enforcer) updateMapEntries() {
	pc, ok := e.policyMap.(policyMapCounter)
	if !ok {
		return
	}
	if n, err := pc.Stats(); err == nil {
		metrics.SetMapEntries("policy_map", n)
	}
}

func (e *Enforcer) mapEntriesLoop(interval time.Duration) {
	defer e.wg.Done()
	e.updateMapEntries()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-t.C:
			e.updateMapEntries()
		}
	}
}

// attackGraphMetricsLoop periodically exports the attack-graph summary and
// blast-radius gauges while the enforcer runs.
func (e *Enforcer) attackGraphMetricsLoop(interval time.Duration) {
	defer e.wg.Done()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-t.C:
			if e.intelligence != nil {
				e.intelligence.publishMetrics()
			}
		}
	}
}

// persistDecision stores a policy decision in the decision cache and, when
// sound, the kernel policy map. Nothing is stored if the policy that made the
// decision (generation gen) has been replaced by a reload in the meantime,
// since the reload has already reset both.
func (e *Enforcer) persistDecision(event *api.Event, result *api.ActionResult, gen uint64, evaluator policymeta.Source) {
	e.decisionMu.RLock()
	defer e.decisionMu.RUnlock()
	if e.policyGen.Load() != gen {
		return
	}
	if host, ok := evaluator.(*hostEvaluator); ok && !host.Alive() {
		return // the final request/CPU budget must not yield a renewable cache
	}
	decisionCache := e.cache
	if e.generations != nil {
		e.generations.mu.Lock()
		state := e.generations.states[gen]
		e.generations.mu.Unlock()
		if state == nil {
			return
		}
		decisionCache = state.cache
	}
	decisionCache.Put(event, result)

	// Compile decision into BPF policy map for kernel fast-path
	if e.policyMap != nil && !event.LSMEvent && (e.supervisor == nil || evaluator.LinuxKernelCacheEligible(event.GetType())) {
		// Failures are counted and rate-limit logged inside; the event
		// itself is already enforced in userspace.
		_ = e.syncToPolicyMap(event, result, gen, evaluator.FieldsRead(event.GetType()))
	}
}

// containerStarter dates the container a cgroup belongs to
// (container.CgroupResolver).
type containerStarter interface {
	ContainerStart(cgroupID uint64) (time.Time, bool)
}

// annotateContainerStart sets event.ContainerStart from the event's cgroup,
// so the policy host can send the container age. It is only called for
// policies that read the age; an undeterminable start stays zero, which a
// temporal rule treats as outside its window (fail closed).
func (e *Enforcer) annotateContainerStart(event *api.Event) {
	if e.containerStarts == nil || event.CgroupID == 0 || !event.ContainerStart.IsZero() {
		return
	}
	if start, ok := e.containerStarts.ContainerStart(event.CgroupID); ok {
		event.ContainerStart = start
	}
}

// setCacheDependencies installs what the policy's decisions depend on beyond
// the event fields into the decision cache: whether they read the PID, and
// whether they read time (temporal policies), which keeps them out of the
// cache altogether.
func setCacheDependencies(c *cache.DecisionCache, evaluator policymeta.Source) {
	c.SetPIDRelevant(pidRelevance(evaluator))
	c.SetTimeDependent(func(t api.EventType) bool {
		// Preserve legacy semantics, while Host's effective methods refuse
		// untrusted declarations (including finite raw fields).
		if _, supervised := evaluator.(*hostEvaluator); supervised {
			return !evaluator.DecisionCacheEligible(t)
		}
		return evaluator.TimeDependent(t)
	})
}

// pidRelevance derives the decision cache's PID rule from the policy's
// fields-read declaration: the PID is only left out of cache keys for event
// types whose policy has declared it never reads the PID.
func pidRelevance(evaluator policymeta.Source) func(api.EventType) bool {
	return func(t api.EventType) bool {
		return evaluator.FieldsRead(t)&compiler.FieldBitPID != 0
	}
}

// endpointPolicyMapSyncer is implemented by policy maps whose kernel programs
// key network rules on the binary address+port rather than a string (the
// Linux LSM connect hook hashes the raw sockaddr). Port is in host order.
type endpointPolicyMapSyncer interface {
	SetEndpointRule(cgroupID uint64, eventType uint8, addr string, port uint16, action uint8, audit bool) error
}

// eventPolicyMapSyncer is implemented by policy maps whose kernel keys need
// more of the event than a pattern string (on Windows, network rules are
// keyed on the connecting image as well as the endpoint, so a decision made
// for one executable never applies to another). It takes precedence over
// SetRule/SetEndpointRule.
type eventPolicyMapSyncer interface {
	SyncEvent(event *api.Event, action uint8, audit bool) error
}

// syncToPolicyMap compiles a decision into the kernel policy map. The syncer
// owns the kernel-side key: it refuses rules its BPF programs cannot match
// exactly (on Linux, file rules, since lsm/file_open only sees the dentry
// basename and a basename rule would hit every same-named file), so a cached
// decision never applies to events userspace did not evaluate.
//
// gen is the policy generation that produced result; the write is dropped if
// a reload has replaced that policy since.
//
// fieldsRead is the policy's declared fields-read mask for the event type
// (wasm.PolicyEvaluator.FieldsRead). The kernel applies a synced decision to
// every event with the same kernel key, so a decision is only synced when
// it is fully determined by that key: every field the policy reads must be
// part of it (see kernelKeyFielder). A decision that depends on, say, uid
// or comm would otherwise be enforced for other users or binaries. Policies
// that declare nothing are never synced.
//
// Callers hold decisionMu (shared); see persistDecision.
func (e *Enforcer) syncToPolicyMap(event *api.Event, result *api.ActionResult, gen uint64, fieldsRead uint32) error {
	err := e.syncDecision(event, result, gen, fieldsRead)
	e.recordSync(event, err)
	return err
}

var (
	// errStaleDecision: the policy that made the decision was replaced.
	errStaleDecision = errors.New("decision made by a replaced policy")
	// errNotKeyDetermined: the decision depends on fields the kernel key
	// does not cover (or the policy did not declare what it reads).
	errNotKeyDetermined = errors.New("decision not determined by the kernel key")
)

// recordSync counts the outcome of one kernel sync and logs failures, at
// most once per syncFailureLogInterval.
func (e *Enforcer) recordSync(event *api.Event, err error) {
	switch {
	case err == nil:
		metrics.RecordPolicyMapSync(metrics.SyncSynced)
	case errors.Is(err, errStaleDecision):
		metrics.RecordPolicyMapSync(metrics.SyncSkippedStale)
	case errors.Is(err, errNotKeyDetermined):
		metrics.RecordPolicyMapSync(metrics.SyncSkippedUnsound)
	case errors.Is(err, kernelmap.ErrNotKernelMatchable):
		metrics.RecordPolicyMapSync(metrics.SyncSkippedUnmatchable)
	default:
		metrics.RecordPolicyMapSync(metrics.SyncFailed)
		if ok, suppressed := e.syncFailLog.allow(time.Now()); ok && e.logger != nil {
			msg := fmt.Sprintf("sync %s decision to kernel policy map (userspace still enforces it)", event.GetType())
			if suppressed > 0 {
				msg += fmt.Sprintf("; %d similar failures suppressed", suppressed)
			}
			e.logger.LogError(err, msg)
		}
	}
}

func (e *Enforcer) syncDecision(event *api.Event, result *api.ActionResult, gen uint64, fieldsRead uint32) error {
	if e.policyGen.Load() != gen {
		return errStaleDecision
	}
	if !decisionDeterminedByKernelKey(e.policyMap, event.GetType(), fieldsRead) {
		return errNotKeyDetermined
	}

	action := uint8(0)
	if result.Action == api.ActionDeny {
		action = 1
	}
	// Sync runs before ActionHandler.Enforce applies the audit downgrade, so
	// fold global audit mode in here: the kernel must never be stricter than
	// userspace, and an audit-flagged deny is only logged by the BPF side.
	audit := result.Audit || e.auditMode
	if e.generations != nil {
		return e.generations.kernel.SyncEvent(gen, event, action, audit)
	}

	if es, ok := e.policyMap.(eventPolicyMapSyncer); ok {
		return es.SyncEvent(event, action, audit)
	}

	var eventType uint8
	var pattern string

	switch event.GetType() {
	case api.EventTypeProcess:
		eventType = 0
		pattern = event.Filename
		if event.Process != nil {
			pattern = event.Process.Filename
		}
	case api.EventTypeFile:
		eventType = 1
		pattern = event.Filename
		if event.File != nil {
			pattern = event.File.Path
		}
	case api.EventTypeNetwork:
		eventType = 2
		if event.Network != nil {
			pattern = event.Network.RemoteAddr
		}
	}

	if pattern == "" {
		return fmt.Errorf("empty pattern: %w", kernelmap.ErrNotKernelMatchable)
	}

	if eventType == 2 {
		if ep, ok := e.policyMap.(endpointPolicyMapSyncer); ok {
			return ep.SetEndpointRule(event.CgroupID, eventType, pattern, event.Network.RemotePort, action, audit)
		}
	}

	return e.policyMap.SetRule(event.CgroupID, eventType, pattern, action, audit)
}

// syncFailureLogInterval rate-limits kernel sync failure logs: a full or
// broken map fails every sync, and the event loop must not drown in logs.
const syncFailureLogInterval = 10 * time.Second

// logLimiter allows one log per interval and counts what it suppressed.
type logLimiter struct {
	mu         sync.Mutex
	interval   time.Duration
	last       time.Time
	suppressed int
}

func (l *logLimiter) allow(now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	interval := l.interval
	if interval == 0 {
		interval = syncFailureLogInterval
	}
	if !l.last.IsZero() && now.Sub(l.last) < interval {
		l.suppressed++
		return false, 0
	}
	n := l.suppressed
	l.last, l.suppressed = now, 0
	return true, n
}

// GetStats returns current statistics
func (e *Enforcer) GetStats() api.EnforcementStats {
	actionStats := e.actionHandler.GetStats()
	cacheStats := e.currentDecisionCache().Stats()

	return api.EnforcementStats{
		Allowed:              actionStats.Allowed,
		Denied:               actionStats.Denied,
		Logged:               actionStats.Logged,
		AuditDenied:          actionStats.AuditDenied,
		EnforcementAttempted: actionStats.EnforcementAttempted,
		EnforcementSucceeded: actionStats.EnforcementSucceeded,
		EnforcementFailed:    actionStats.EnforcementFailed,
		EnforcementRefused:   actionStats.EnforcementRefused,
		CacheHits:            cacheStats.TotalHits,
		CacheMisses:          actionStats.Allowed + actionStats.Denied + actionStats.Logged - cacheStats.TotalHits,
	}
}

// PrintStats prints current statistics
func (e *Enforcer) PrintStats() {
	stats := e.GetStats()
	cacheStats := e.currentDecisionCache().Stats()

	// Log structured stats
	e.logger.LogStats(&stats)

	// Print human-readable stats
	total := stats.Allowed + stats.Denied + stats.Logged
	if total == 0 {
		fmt.Println("\n=== Warmor Statistics ===")
		fmt.Println("No events processed yet")
		fmt.Println("========================")
		return
	}

	allowedPct := float64(stats.Allowed) / float64(total) * 100
	deniedPct := float64(stats.Denied) / float64(total) * 100
	loggedPct := float64(stats.Logged) / float64(total) * 100

	cacheHitRate := float64(0)
	if stats.CacheHits+stats.CacheMisses > 0 {
		cacheHitRate = float64(stats.CacheHits) / float64(stats.CacheHits+stats.CacheMisses) * 100
	}

	fmt.Println("\n=== Warmor Statistics ===")
	fmt.Printf("Total Events: %d\n", total)
	fmt.Printf("Allowed: %d (%.1f%%)\n", stats.Allowed, allowedPct)
	fmt.Printf("Denied: %d (%.1f%%)\n", stats.Denied, deniedPct)
	fmt.Printf("Logged: %d (%.1f%%)\n", stats.Logged, loggedPct)
	if stats.AuditDenied > 0 {
		fmt.Printf("Audit Denied: %d (would-be denials logged)\n", stats.AuditDenied)
	}
	fmt.Printf("Cache Hits: %d\n", stats.CacheHits)
	fmt.Printf("Cache Misses: %d\n", stats.CacheMisses)
	fmt.Printf("Cache Hit Rate: %.2f%%\n", cacheHitRate)
	fmt.Printf("Cache Size: %d/%d\n", cacheStats.Size, cacheStats.MaxSize)
	fmt.Println("========================")
}

// ReloadPolicy reloads the policy without stopping the enforcer. With a
// verification key, a policy whose signature is missing or invalid is
// refused and the current policy stays active.
func (e *Enforcer) ReloadPolicy() error {
	return e.ActivatePolicy(e.policyPath, nil)
}

// ActivatePolicy serializes candidate activation with close/reload. In the
// experimental generation path the kernel+userspace live commit PRECEDES the
// error-returning durableCommit hook. An error after live commit wraps
// ErrActivationPending, retains both evaluators, and must not be acknowledged
// or compensated by changing a disk pointer alone. Retry the same immutable
// path; the ORIGINAL hook is retained and must be idempotent. Supply exactly
// one durable publication authority (agentstore in signed mode), not a chain
// of independent pointer/store transactions. Nil means no durable publication
// is requested, as for a standalone reload. No reader/worker-needed lock is held
// during the hook, but activationMu remains held: it must not reenter activation.
//
// The default legacy path instead drains events, prepares its single map, calls
// durableCommit and swaps userspace. It is NOT generation-atomic: default-deny
// misses may allow during rebuild and rollback errors mean degraded enforcement.
// See docs/design/generation-activation.md before implementing a backend adapter.
func (e *Enforcer) ActivatePolicy(path string, durableCommit func() error) error {
	if e.signedAssignment {
		return errors.New("signed assignment mode refuses generic reload/activation")
	}
	return e.activatePolicy(path, nil, durableCommit, nil)
}

func (e *Enforcer) activatePolicy(path string, expected *assignment.Policy, durableCommit func() error, snapshot *telemetry.Snapshot) error {
	e.activationMu.Lock()
	defer e.activationMu.Unlock()
	e.eventMu.RLock()
	closed := e.closed
	e.eventMu.RUnlock()
	if closed {
		return errors.New("enforcer closed")
	}
	if err := e.ctx.Err(); err != nil {
		return err
	}
	if e.generations != nil {
		if expected != nil {
			return errors.New("signed assignments with atomic generations are unsupported")
		}
		if snapshot != nil {
			return errors.New("legacy telemetry attribution with atomic generations is unsupported")
		}
		return e.activateGeneration(path, durableCommit)
	}
	e.logger.LogInfo(fmt.Sprintf("Reloading policy from: %s", path))

	pid := policyID(e.policyPath)
	newBackend, err := e.candidateBackend(path, nil)
	metrics.RecordPolicyLoad(pid, err)
	if err != nil {
		return err
	}

	newEvaluator := newBackend.evaluator
	activated := false
	defer func() {
		if !activated {
			newBackend.close()
		}
	}()
	if expected != nil {
		if err := e.checkAssignment(newEvaluator, *expected); err != nil {
			return err
		}
	}

	e.eventMu.Lock()
	defer e.eventMu.Unlock()
	e.decisionMu.Lock()
	err = e.prepareKernel(newEvaluator)
	if err == nil && durableCommit != nil {
		err = durableCommit()
	}
	if err != nil {
		// Dynamic cached kernel entries cannot be restored transactionally.
		restoreErr := e.prepareKernel(e.evaluator)
		e.decisionMu.Unlock()
		if restoreErr != nil {
			return fmt.Errorf("activation failed: %w; kernel rollback failed (enforcement degraded): %v", err, restoreErr)
		}
		return fmt.Errorf("activation failed (previous userspace policy retained): %w", err)
	}

	// Atomic swap with mutex protection
	e.evaluatorMu.Lock()
	oldBackend := e.ownedBackend()
	e.evaluator = newEvaluator
	e.pool = newBackend.pool
	e.wasmRuntime = newBackend.runtime
	e.backend = newBackend
	e.policyID = pid
	e.policyGen.Add(1)
	if e.telemetry != nil {
		if snapshot == nil {
			e.telemetry.Seal()
		} else {
			e.telemetry.Replace(*snapshot)
		}
	}
	e.evaluatorMu.Unlock()
	setCacheDependencies(e.cache, newEvaluator)
	e.decisionMu.Unlock()
	activated = true
	e.updateMapEntries()

	// Clean up old resources
	oldBackend.close()

	metrics.SetPolicyInfo(e.policyPath, version.Version)
	e.logger.LogInfo("✓ Policy reloaded successfully")
	return nil
}

// loadPolicyPath compiles a candidate into a fresh runtime and instance pool.
func (e *Enforcer) loadPolicyPath(path string) (*wasm.Runtime, *wasm.Pool, error) {
	// With a verify key, read the file once, verify it and load exactly
	// those bytes, before creating anything.
	var verifiedPolicy []byte
	if e.verifyKey != nil {
		data, err := ReadVerifiedPolicy(path, e.verifyKey)
		if err != nil {
			return nil, nil, fmt.Errorf("verify new policy: %w", err)
		}
		verifiedPolicy = data
	}

	// Create new runtime with compilation cache
	newRuntime, err := wasm.NewRuntime(e.ctx, wasm.RuntimeConfig{
		CacheDir: wasm.DefaultCacheDir(),
		PoolSize: runtime.NumCPU(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create new runtime: %w", err)
	}

	// Load new policy (supports both .wasm and .yaml/.yml)
	if verifiedPolicy != nil {
		if err := newRuntime.LoadPolicyBytes(e.ctx, verifiedPolicy); err != nil {
			newRuntime.Close(e.ctx)
			return nil, nil, fmt.Errorf("load new policy: %w", err)
		}
	} else if wasm.IsYAMLPolicy(path) {
		if err := newRuntime.LoadPolicyFromYAML(e.ctx, path); err != nil {
			newRuntime.Close(e.ctx)
			return nil, nil, fmt.Errorf("load new YAML policy: %w", err)
		}
	} else {
		if err := newRuntime.LoadPolicy(e.ctx, path); err != nil {
			newRuntime.Close(e.ctx)
			return nil, nil, fmt.Errorf("load new policy: %w", err)
		}
	}

	// Create new pool
	poolSize := runtime.NumCPU()
	newPool, err := wasm.NewPool(e.ctx, newRuntime, poolSize)
	if err != nil {
		newRuntime.Close(e.ctx)
		return nil, nil, fmt.Errorf("create new policy pool: %w", err)
	}
	return newRuntime, newPool, nil
}

// NetFilter returns the enforcer's network filter (nil if not configured).
func (e *Enforcer) NetFilter() *NetFilter { return e.netFilter }

// Sandbox returns the enforcer's sandbox manager.
func (e *Enforcer) Sandbox() *SandboxManager { return e.sandbox }

func eventTypeToSandboxAction(event *api.Event) string {
	switch event.GetType() {
	case api.EventTypeNetwork:
		return "network"
	case api.EventTypeFile:
		return "write"
	default:
		return ""
	}
}

// Stop stops the enforcer
func (e *Enforcer) Stop() {
	e.logger.LogInfo("Stopping enforcer...")
	e.stopProcessing()
	e.logger.LogInfo("✓ Enforcer stopped")
}

// Cancel before acquiring activationMu: an activation may hold it while waiting
// for a reader fence, host I/O, or an old work lease. Stop only readers/workers;
// the backend and kernel maps/hooks remain owned until Close drains eventMu.
// Once also serializes concurrent Stop/Close queue draining and platform access.
func (e *Enforcer) stopProcessing() {
	e.stopOnce.Do(func() {
		if e.cancel != nil {
			e.cancel()
		}
		if e.platform != nil {
			_ = e.platform.Stop()
		}
		e.wg.Wait()
		e.releaseQueuedGenerationEvents()
	})
}

// Close cleans up resources
func (e *Enforcer) Close() error {
	e.stopProcessing()
	e.activationMu.Lock()
	defer e.activationMu.Unlock()
	e.eventMu.Lock()
	defer e.eventMu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	if e.telemetry != nil {
		e.telemetry.Seal()
	}
	e.logger.LogShutdown()

	// Flush and close the streaming pipeline
	if e.pipeline != nil {
		_ = e.pipeline.Close()
	}

	// Stop metrics server
	if e.metricsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = e.metricsServer.Stop(ctx)
	}

	// Clean up enforcer resources
	e.evaluatorMu.Lock()
	backend := e.ownedBackend()
	e.evaluatorMu.Unlock()

	backend.close()
	if e.generations != nil {
		for _, state := range e.generations.states {
			closeEvaluationGeneration(state)
		}
	}
	if e.platform != nil {
		e.platform.Close()
		e.platform = nil
	}

	e.logger.LogInfo("✓ Resources cleaned up")
	return nil
}
