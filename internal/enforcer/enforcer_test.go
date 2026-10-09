package enforcer

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/cache"
	"github.com/yasindce1998/warmor/internal/lineage"
	"github.com/yasindce1998/warmor/internal/logging"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/platform"
	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

// testPolicyPath is the prebuilt WASM fixture shared with internal/wasm.
// Policy: deny uid 0 running bash, log anything mentioning python, allow
// everything else.
var testPolicyPath = filepath.Join("..", "wasm", "testdata", "allow_policy.wasm")

// ---- fakes ----

// fakePlatform is an in-memory platform.Platform that never touches the kernel.
type fakePlatform struct {
	mu       sync.Mutex
	startErr error
	started  int
	stopped  int
	closed   int
	ch       chan<- *api.Event
}

var _ platform.Platform = (*fakePlatform)(nil)

func (f *fakePlatform) Name() string                        { return "fake" }
func (f *fakePlatform) Load(context.Context) error          { return nil }
func (f *fakePlatform) Capabilities() platform.Capabilities { return platform.Capabilities{} }
func (f *fakePlatform) PolicyMap() any                      { return nil }

func (f *fakePlatform) Start(_ context.Context, ch chan<- *api.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started++
	f.ch = ch
	return f.startErr
}

func (f *fakePlatform) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped++
	return nil
}

func (f *fakePlatform) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return nil
}

type policyRule struct {
	cgroupID  uint64
	eventType uint8
	pattern   string
	action    uint8
	audit     bool
}

// fakePolicyMap records rules compiled into the (would-be) BPF policy map.
type fakePolicyMap struct {
	mu    sync.Mutex
	rules []policyRule
}

func (f *fakePolicyMap) SetRule(cgroupID uint64, eventType uint8, pattern string, action uint8, audit bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, policyRule{cgroupID, eventType, pattern, action, audit})
	return nil
}

func (f *fakePolicyMap) snapshot() []policyRule {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]policyRule(nil), f.rules...)
}

// sinkRecorder collects CEF lines written by the streaming pipeline.
type sinkRecorder struct {
	mu    sync.Mutex
	lines []string
}

func (s *sinkRecorder) write(line string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, line)
	return nil
}

func (s *sinkRecorder) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}

// ---- helpers ----

type testEnforcerOpts struct {
	audit     bool
	learning  bool
	poolSize  int
	netFilter *NetFilterConfig
	policyMap PolicyMapSyncer
	sink      *sinkRecorder
}

// newTestEnforcer builds an Enforcer by hand (bypassing New, which requires a
// real eBPF/ETW/ESF platform) with a real WASM evaluator over the test fixture.
func newTestEnforcer(t *testing.T, o testEnforcerOpts) (*Enforcer, *fakePlatform) {
	t.Helper()
	ctx := context.Background()

	rt, err := wasm.NewRuntime(ctx)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if err := rt.LoadPolicy(ctx, testPolicyPath); err != nil {
		rt.Close(ctx)
		t.Fatalf("LoadPolicy: %v", err)
	}
	size := o.poolSize
	if size == 0 {
		size = 2
	}
	pool, err := wasm.NewPool(ctx, rt, size)
	if err != nil {
		rt.Close(ctx)
		t.Fatalf("NewPool: %v", err)
	}

	tracker := lineage.NewTracker(lineage.TrackerConfig{})

	var pipeline *streaming.Pipeline
	if o.sink != nil {
		pipeline = streaming.NewPipeline(streaming.PipelineConfig{
			Sinks:     []streaming.Sink{streaming.NewCEFSink("test", o.sink.write)},
			Enrichers: []streaming.Enricher{lineage.NewEnricher(tracker)},
		})
	}

	var nf *NetFilter
	if o.netFilter != nil {
		nf, err = NewNetFilter(*o.netFilter)
		if err != nil {
			t.Fatalf("NewNetFilter: %v", err)
		}
	}

	plat := &fakePlatform{}
	ectx, cancel := context.WithCancel(ctx)
	e := &Enforcer{
		platform:       plat,
		wasmRuntime:    rt,
		evaluator:      wasm.NewPolicyEvaluator(pool, "test-host"),
		pool:           pool,
		cache:          cache.NewDecisionCache(100, time.Minute),
		actionHandler:  NewActionHandler(o.audit),
		logger:         logging.NewLoggerWithWriter("error", io.Discard),
		metricsServer:  metrics.NewServer(-1),
		policyMap:      o.policyMap,
		pipeline:       pipeline,
		lineageTracker: tracker,
		netFilter:      nf,
		sandbox:        NewSandboxManager(DefaultProfiles()...),
		policyPath:     testPolicyPath,
		auditMode:      o.audit,
		learningMode:   o.learning,
		ctx:            ectx,
		cancel:         cancel,
	}
	t.Cleanup(func() {
		cancel()
		if pipeline != nil {
			_ = pipeline.Close()
		}
		// Close the pool and runtime directly; Close is idempotent, so this
		// is safe even when the test already called Enforcer.Close.
		e.evaluatorMu.Lock()
		p, r := e.pool, e.wasmRuntime
		e.evaluatorMu.Unlock()
		if p != nil {
			p.Close(context.Background())
		}
		if r != nil {
			r.Close(context.Background())
		}
	})
	return e, plat
}

// isolateCacheDir points os.UserCacheDir at a temp dir so code paths using
// wasm.DefaultCacheDir() never write into the real user cache.
func isolateCacheDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("LocalAppData", dir)
	return dir
}

// ---- handleEvent: policy decisions ----

func TestHandleEvent_PolicyAllow(t *testing.T) {
	pm := &fakePolicyMap{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyMap: pm})

	event := &api.Event{PID: 0, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls", CgroupID: 7}
	e.handleEvent(event)

	stats := e.GetStats()
	if stats.Allowed != 1 || stats.Denied != 0 || stats.Logged != 0 {
		t.Fatalf("stats = %+v, want exactly 1 allowed", stats)
	}
	if e.cache.Stats().Size != 1 {
		t.Errorf("expected decision to be cached")
	}

	rules := pm.snapshot()
	if len(rules) != 1 {
		t.Fatalf("expected 1 policy map rule, got %d", len(rules))
	}
	want := policyRule{cgroupID: 7, eventType: 0, pattern: "/usr/bin/ls", action: 0, audit: false}
	if rules[0] != want {
		t.Errorf("rule = %+v, want %+v", rules[0], want)
	}

	// Process exec must be recorded in lineage.
	if _, ok := e.lineageTracker.GetProcess(0); !ok {
		t.Error("expected process exec to be recorded in lineage tracker")
	}
}

func TestHandleEvent_PolicyDeny(t *testing.T) {
	pm := &fakePolicyMap{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyMap: pm})

	// PID 0 means handleDeny skips the kill, so nothing real is signalled.
	event := &api.Event{PID: 0, UID: 0, Comm: "bash", Filename: "/bin/bash"}
	e.handleEvent(event)

	stats := e.GetStats()
	if stats.Denied != 1 || stats.Allowed != 0 {
		t.Fatalf("stats = %+v, want 1 denied", stats)
	}
	rules := pm.snapshot()
	if len(rules) != 1 || rules[0].action != 1 || rules[0].pattern != "/bin/bash" {
		t.Errorf("expected deny rule for /bin/bash, got %+v", rules)
	}
}

func TestHandleEvent_PolicyLog(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})

	e.handleEvent(&api.Event{PID: 0, UID: 1000, Comm: "python3", Filename: "/usr/bin/python3"})

	stats := e.GetStats()
	if stats.Logged != 1 || stats.Denied != 0 || stats.AuditDenied != 0 {
		t.Fatalf("stats = %+v, want 1 logged", stats)
	}
}

func TestHandleEvent_AuditModeDowngradesPolicyDeny(t *testing.T) {
	pm := &fakePolicyMap{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{audit: true, policyMap: pm})

	// Non-zero PID is safe: audit mode never reaches terminateProcess.
	e.handleEvent(&api.Event{PID: 4242, UID: 0, Comm: "bash", Filename: "/bin/bash"})

	stats := e.GetStats()
	if stats.Denied != 0 || stats.AuditDenied != 1 || stats.Logged != 1 {
		t.Fatalf("stats = %+v, want audit-denied only", stats)
	}
	// Policy-map sync happens before Enforce, so the rule is a hard deny with
	// audit=false even though user-space downgraded it.
	rules := pm.snapshot()
	if len(rules) != 1 || rules[0].action != 1 {
		t.Fatalf("expected one deny rule, got %+v", rules)
	}
}

func TestHandleEvent_CacheHit(t *testing.T) {
	pm := &fakePolicyMap{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyMap: pm})

	event := &api.Event{PID: 0, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls"}
	e.handleEvent(event)
	e.handleEvent(event)
	e.handleEvent(event)

	stats := e.GetStats()
	if stats.Allowed != 3 {
		t.Fatalf("Allowed = %d, want 3", stats.Allowed)
	}
	if stats.CacheHits != 2 {
		t.Errorf("CacheHits = %d, want 2", stats.CacheHits)
	}
	if stats.CacheMisses != 1 {
		t.Errorf("CacheMisses = %d, want 1", stats.CacheMisses)
	}
	// Cached decisions must not be re-synced into the policy map.
	if n := len(pm.snapshot()); n != 1 {
		t.Errorf("policy map sync count = %d, want 1", n)
	}
}

func TestHandleEvent_CachedDenyStillEnforced(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})

	event := &api.Event{PID: 0, UID: 0, Comm: "bash", Filename: "/bin/bash"}
	e.handleEvent(event)
	e.handleEvent(event)

	if got := e.GetStats().Denied; got != 2 {
		t.Errorf("Denied = %d, want 2 (cache hit must still enforce deny)", got)
	}
}

func TestHandleEvent_EvaluationErrorFailsClosed(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{poolSize: 1})

	// Exhaust the pool so Evaluate blocks on Get, then cancel the context so
	// Get returns an error deterministically.
	inst, err := e.pool.Get(context.Background())
	if err != nil {
		t.Fatalf("pool.Get: %v", err)
	}
	defer e.pool.Put(inst)
	e.cancel()

	// An event the policy would otherwise allow.
	event := &api.Event{PID: 0, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls"}
	e.handleEvent(event)

	stats := e.GetStats()
	if stats.Denied != 1 || stats.Allowed != 0 {
		t.Fatalf("stats = %+v, want fail-closed deny", stats)
	}

	cached, hit := e.cache.Get(event)
	if !hit {
		t.Fatal("expected fail-closed decision to be cached (current behaviour)")
	}
	if cached.Action != api.ActionDeny || !strings.Contains(cached.Reason, "Evaluation error") {
		t.Errorf("cached result = %+v, want deny with evaluation error reason", cached)
	}
}

func TestHandleEvent_EvaluationErrorAuditMode(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{audit: true, poolSize: 1})

	inst, err := e.pool.Get(context.Background())
	if err != nil {
		t.Fatalf("pool.Get: %v", err)
	}
	defer e.pool.Put(inst)
	e.cancel()

	e.handleEvent(&api.Event{PID: 4242, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls"})

	stats := e.GetStats()
	if stats.AuditDenied != 1 || stats.Denied != 0 {
		t.Fatalf("stats = %+v, want audit-denied in audit mode", stats)
	}
}

func TestHandleEvent_LSMEventSkipsPolicyMapSync(t *testing.T) {
	pm := &fakePolicyMap{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyMap: pm})

	e.handleEvent(&api.Event{PID: 0, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls", LSMEvent: true})

	if n := len(pm.snapshot()); n != 0 {
		t.Errorf("LSM-originated event should not be synced to policy map, got %d rules", n)
	}
	if e.GetStats().Allowed != 1 {
		t.Error("LSM event should still be evaluated and enforced")
	}
}

func TestHandleEvent_ProcessFilenameFromProcessEvent(t *testing.T) {
	pm := &fakePolicyMap{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{policyMap: pm})

	e.handleEvent(&api.Event{
		PID:      0,
		UID:      1000,
		Comm:     "ls",
		Filename: "legacy",
		Process:  &api.ProcessEvent{Filename: "/usr/bin/ls"},
	})

	info, ok := e.lineageTracker.GetProcess(0)
	if !ok || info.Filename != "/usr/bin/ls" {
		t.Errorf("lineage filename = %q, want /usr/bin/ls", info.Filename)
	}
}

// ---- handleEvent: learning mode ----

func TestHandleEvent_LearningModeAllowsEverything(t *testing.T) {
	rec := &sinkRecorder{}
	pm := &fakePolicyMap{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{learning: true, sink: rec, policyMap: pm})

	// Would be denied by policy.
	e.handleEvent(&api.Event{PID: 4242, UID: 0, Comm: "bash", Filename: "/bin/bash"})

	stats := e.GetStats()
	if stats.Denied != 0 || stats.AuditDenied != 0 {
		t.Fatalf("learning mode must never deny, stats = %+v", stats)
	}
	if e.cache.Stats().Size != 0 {
		t.Error("learning mode should not populate the decision cache")
	}
	if n := len(pm.snapshot()); n != 0 {
		t.Error("learning mode should not compile rules into the policy map")
	}

	_ = e.pipeline.Close()
	lines := rec.snapshot()
	if len(lines) != 1 || !strings.Contains(lines[0], "exec_allow") {
		t.Errorf("expected one exec_allow pipeline event, got %v", lines)
	}
}

// ---- handleEvent: network filter ----

func TestHandleEvent_NetFilterBlocklistDenies(t *testing.T) {
	rec := &sinkRecorder{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{
		audit:     true, // avoid any kill on non-zero PID
		netFilter: &NetFilterConfig{BlockCIDRs: []string{"10.0.0.0/8"}},
		sink:      rec,
	})

	event := &api.Event{
		PID:     4242,
		UID:     1000,
		Comm:    "curl",
		Network: &api.NetworkEvent{BaseEvent: api.BaseEvent{Type: api.EventTypeNetwork}, RemoteAddr: "10.1.2.3", RemotePort: 443},
	}
	e.handleEvent(event)

	stats := e.GetStats()
	if stats.AuditDenied != 1 {
		t.Fatalf("stats = %+v, want blocklisted connection denied", stats)
	}
	if e.cache.Stats().Size != 0 {
		t.Error("blocklist short-circuit must happen before policy evaluation/caching")
	}

	_ = e.pipeline.Close()
	lines := rec.snapshot()
	if len(lines) != 1 || !strings.Contains(lines[0], "network_deny") || !strings.Contains(lines[0], "CIDR blocklist") {
		t.Errorf("unexpected pipeline output: %v", lines)
	}
}

func TestHandleEvent_NetFilterAllowedAddressGoesToPolicy(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{
		netFilter: &NetFilterConfig{BlockCIDRs: []string{"10.0.0.0/8"}},
	})

	e.handleEvent(&api.Event{
		PID:     0,
		UID:     1000,
		Comm:    "curl",
		Network: &api.NetworkEvent{BaseEvent: api.BaseEvent{Type: api.EventTypeNetwork}, RemoteAddr: "8.8.8.8", RemotePort: 53},
	})

	if got := e.GetStats().Allowed; got != 1 {
		t.Errorf("Allowed = %d, want 1", got)
	}
	if e.cache.Stats().Size != 1 {
		t.Error("non-blocked connection should be evaluated by policy and cached")
	}
}

func TestHandleEvent_NetFilterNilNetworkPayload(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{
		netFilter: &NetFilterConfig{BlockCIDRs: []string{"0.0.0.0/0"}},
	})

	// Network type with no payload: no remote addr to check, falls through.
	e.handleEvent(&api.Event{PID: 0, UID: 1000, Comm: "x", Type: api.EventTypeNetwork})

	if got := e.GetStats().Allowed; got != 1 {
		t.Errorf("Allowed = %d, want 1 (empty remote addr is not blocklisted)", got)
	}
}

func TestHandleEvent_NetFilterRateLimit(t *testing.T) {
	rec := &sinkRecorder{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{
		audit:     true,
		netFilter: &NetFilterConfig{RateLimit: 2, Window: time.Hour},
		sink:      rec,
	})

	event := func() *api.Event {
		return &api.Event{
			PID:     4242,
			UID:     1000,
			Comm:    "curl",
			Network: &api.NetworkEvent{BaseEvent: api.BaseEvent{Type: api.EventTypeNetwork}, RemoteAddr: "8.8.8.8", RemotePort: 53},
		}
	}
	for range 3 {
		e.handleEvent(event())
	}

	stats := e.GetStats()
	if stats.Allowed != 2 {
		t.Errorf("Allowed = %d, want 2", stats.Allowed)
	}
	if stats.AuditDenied != 1 {
		t.Errorf("AuditDenied = %d, want 1 (3rd connection rate-limited)", stats.AuditDenied)
	}

	_ = e.pipeline.Close()
	found := false
	for _, l := range rec.snapshot() {
		if strings.Contains(l, "rate limit exceeded for pid 4242") {
			found = true
		}
	}
	if !found {
		t.Error("expected rate-limit deny to be emitted to pipeline")
	}
}

func TestHandleEvent_NetFilterIgnoresNonNetworkEvents(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{
		netFilter: &NetFilterConfig{BlockCIDRs: []string{"0.0.0.0/0"}, RateLimit: 1},
	})

	for range 3 {
		e.handleEvent(&api.Event{PID: 0, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls"})
	}
	if got := e.GetStats().Allowed; got != 3 {
		t.Errorf("Allowed = %d, want 3 (net filter applies only to network events)", got)
	}
}

// ---- handleEvent: sandbox ----

func TestHandleEvent_SandboxNetworkViolation(t *testing.T) {
	rec := &sinkRecorder{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{audit: true, sink: rec})

	if err := e.Sandbox().ApplySandbox(4242, "network-deny"); err != nil {
		t.Fatal(err)
	}

	e.handleEvent(&api.Event{
		PID:     4242,
		UID:     1000,
		Comm:    "curl",
		Network: &api.NetworkEvent{BaseEvent: api.BaseEvent{Type: api.EventTypeNetwork}, RemoteAddr: "8.8.8.8"},
	})

	if got := e.GetStats().AuditDenied; got != 1 {
		t.Fatalf("AuditDenied = %d, want 1", got)
	}
	if e.cache.Stats().Size != 0 {
		t.Error("sandbox violation must short-circuit before policy evaluation")
	}
	_ = e.pipeline.Close()
	lines := rec.snapshot()
	if len(lines) != 1 || !strings.Contains(lines[0], "network access denied") {
		t.Errorf("unexpected pipeline output: %v", lines)
	}
}

func TestHandleEvent_SandboxReadOnlyFileViolation(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{audit: true})

	if err := e.Sandbox().ApplySandbox(4242, "readonly"); err != nil {
		t.Fatal(err)
	}
	e.handleEvent(&api.Event{
		PID:  4242,
		UID:  1000,
		Comm: "vim",
		File: &api.FileEvent{BaseEvent: api.BaseEvent{Type: api.EventTypeFile}, Operation: "write", Path: "/etc/passwd"},
	})

	if got := e.GetStats().AuditDenied; got != 1 {
		t.Errorf("AuditDenied = %d, want 1", got)
	}
}

func TestHandleEvent_SandboxedProcessExecNotRestricted(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})

	if err := e.Sandbox().ApplySandbox(0, "strict"); err != nil {
		t.Fatal(err)
	}
	// Process events map to no sandbox action, so they go to the policy.
	e.handleEvent(&api.Event{PID: 0, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls"})

	if got := e.GetStats().Allowed; got != 1 {
		t.Errorf("Allowed = %d, want 1", got)
	}
}

func TestHandleEvent_SandboxNotAppliedAllowsNetwork(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})

	e.handleEvent(&api.Event{
		PID:     0,
		UID:     1000,
		Comm:    "curl",
		Network: &api.NetworkEvent{BaseEvent: api.BaseEvent{Type: api.EventTypeNetwork}, RemoteAddr: "8.8.8.8"},
	})
	if got := e.GetStats().Allowed; got != 1 {
		t.Errorf("Allowed = %d, want 1", got)
	}
}

func TestHandleEvent_NilSandbox(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	e.sandbox = nil

	e.handleEvent(&api.Event{
		PID:  0,
		UID:  1000,
		Comm: "touch",
		File: &api.FileEvent{BaseEvent: api.BaseEvent{Type: api.EventTypeFile}, Path: "/tmp/x"},
	})
	if got := e.GetStats().Allowed; got != 1 {
		t.Errorf("Allowed = %d, want 1", got)
	}
}

// ---- handleEvent: pipeline emission for policy and cache paths ----

func TestHandleEvent_PipelineEmitsPolicyAndCachedDecisions(t *testing.T) {
	rec := &sinkRecorder{}
	e, _ := newTestEnforcer(t, testEnforcerOpts{audit: true, sink: rec})

	deny := &api.Event{PID: 4242, UID: 0, Comm: "bash", Filename: "/bin/bash"}
	e.handleEvent(deny) // miss
	e.handleEvent(deny) // hit
	e.handleEvent(&api.Event{PID: 4243, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls"})

	_ = e.pipeline.Close()
	lines := rec.snapshot()
	if len(lines) != 3 {
		t.Fatalf("expected 3 pipeline events, got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "exec_deny") || !strings.Contains(lines[1], "exec_deny") {
		t.Errorf("expected first two events to be denies: %v", lines[:2])
	}
	if !strings.Contains(lines[2], "exec_allow") {
		t.Errorf("expected third event to be allow: %s", lines[2])
	}
}

// ---- syncToPolicyMap ----

func TestSyncToPolicyMap(t *testing.T) {
	allow := &api.ActionResult{Action: api.ActionAllow}
	deny := &api.ActionResult{Action: api.ActionDeny}
	auditDeny := &api.ActionResult{Action: api.ActionDeny, Audit: true}
	logRes := &api.ActionResult{Action: api.ActionLog}

	tests := []struct {
		name   string
		event  *api.Event
		result *api.ActionResult
		want   *policyRule
	}{
		{
			name:   "legacy process uses Filename",
			event:  &api.Event{CgroupID: 1, Filename: "/bin/sh"},
			result: deny,
			want:   &policyRule{cgroupID: 1, eventType: 0, pattern: "/bin/sh", action: 1},
		},
		{
			name:   "process event overrides Filename",
			event:  &api.Event{CgroupID: 2, Filename: "x", Process: &api.ProcessEvent{Filename: "/usr/bin/id"}},
			result: allow,
			want:   &policyRule{cgroupID: 2, eventType: 0, pattern: "/usr/bin/id", action: 0},
		},
		{
			name:   "file event uses File.Path",
			event:  &api.Event{CgroupID: 3, Filename: "x", File: &api.FileEvent{BaseEvent: api.BaseEvent{Type: api.EventTypeFile}, Path: "/etc/shadow"}},
			result: auditDeny,
			want:   &policyRule{cgroupID: 3, eventType: 1, pattern: "/etc/shadow", action: 1, audit: true},
		},
		{
			name:   "file type without payload uses Filename",
			event:  &api.Event{CgroupID: 4, Type: api.EventTypeFile, Filename: "/tmp/f"},
			result: logRes,
			want:   &policyRule{cgroupID: 4, eventType: 1, pattern: "/tmp/f", action: 0},
		},
		{
			name:   "network event uses RemoteAddr",
			event:  &api.Event{CgroupID: 5, Network: &api.NetworkEvent{BaseEvent: api.BaseEvent{Type: api.EventTypeNetwork}, RemoteAddr: "1.2.3.4"}},
			result: deny,
			want:   &policyRule{cgroupID: 5, eventType: 2, pattern: "1.2.3.4", action: 1},
		},
		{
			name:   "network type without payload is skipped",
			event:  &api.Event{Type: api.EventTypeNetwork},
			result: deny,
			want:   nil,
		},
		{
			name:   "empty pattern is skipped",
			event:  &api.Event{},
			result: deny,
			want:   nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pm := &fakePolicyMap{}
			e := &Enforcer{policyMap: pm}
			e.syncToPolicyMap(tc.event, tc.result)

			rules := pm.snapshot()
			if tc.want == nil {
				if len(rules) != 0 {
					t.Errorf("expected no rule, got %+v", rules)
				}
				return
			}
			if len(rules) != 1 {
				t.Fatalf("expected 1 rule, got %d", len(rules))
			}
			if rules[0] != *tc.want {
				t.Errorf("rule = %+v, want %+v", rules[0], *tc.want)
			}
		})
	}
}

// ---- eventTypeToSandboxAction ----

func TestEventTypeToSandboxAction(t *testing.T) {
	tests := []struct {
		name  string
		event *api.Event
		want  string
	}{
		{"process", &api.Event{}, ""},
		{"network", &api.Event{Type: api.EventTypeNetwork}, "network"},
		{"file", &api.Event{Type: api.EventTypeFile}, "write"},
		{"unknown", &api.Event{Type: api.EventType(99)}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := eventTypeToSandboxAction(tc.event); got != tc.want {
				t.Errorf("eventTypeToSandboxAction = %q, want %q", got, tc.want)
			}
		})
	}
}

// ---- accessors, stats ----

func TestAccessors(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{netFilter: &NetFilterConfig{}})
	if e.NetFilter() == nil {
		t.Error("NetFilter() returned nil when configured")
	}
	if e.Sandbox() == nil {
		t.Error("Sandbox() returned nil")
	}

	e2, _ := newTestEnforcer(t, testEnforcerOpts{})
	if e2.NetFilter() != nil {
		t.Error("NetFilter() should be nil when not configured")
	}
}

// captureStdout runs fn while redirecting os.Stdout and returns what was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	w.Close()
	return <-done
}

func TestPrintStats_NoEvents(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	out := captureStdout(t, e.PrintStats)
	if !strings.Contains(out, "No events processed yet") {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestPrintStats_WithEvents(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{audit: true})

	allow := &api.Event{PID: 0, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls"}
	e.handleEvent(allow)
	e.handleEvent(allow)
	e.handleEvent(&api.Event{PID: 4242, UID: 0, Comm: "bash", Filename: "/bin/bash"})
	e.handleEvent(&api.Event{PID: 0, UID: 1000, Comm: "python", Filename: "/usr/bin/python"})

	out := captureStdout(t, e.PrintStats)
	for _, want := range []string{
		"Total Events: 4",
		"Allowed: 2 (50.0%)",
		"Logged: 2 (50.0%)",
		"Audit Denied: 1",
		"Cache Hits: 1",
		"Cache Misses: 3",
		"Cache Hit Rate: 25.00%",
		"Cache Size: 3/100",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("PrintStats output missing %q:\n%s", want, out)
		}
	}
}

// ---- lifecycle ----

func TestStart_MetricsServerError(t *testing.T) {
	e, plat := newTestEnforcer(t, testEnforcerOpts{})
	// metrics.NewServer(-1) listens on ":-1", which fails without touching
	// the network.
	err := e.Start()
	if err == nil || !strings.Contains(err.Error(), "start metrics server") {
		t.Fatalf("Start() error = %v, want metrics server error", err)
	}
	if plat.started != 0 {
		t.Error("platform must not be started when metrics server fails")
	}
}

func TestEventLoop_ProcessesEventsAndStops(t *testing.T) {
	e, plat := newTestEnforcer(t, testEnforcerOpts{})

	// Wire up the loop the way Start does, minus the metrics listener.
	e.eventChan = make(chan *api.Event, 8)
	if err := e.platform.Start(e.ctx, e.eventChan); err != nil {
		t.Fatal(err)
	}
	e.wg.Add(1)
	go e.eventLoop()

	for range 3 {
		e.eventChan <- &api.Event{PID: 0, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls"}
	}

	deadline := time.Now().Add(5 * time.Second)
	for e.actionHandler.GetStats().Allowed < 3 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for event loop to process events")
		}
		time.Sleep(5 * time.Millisecond)
	}

	e.Stop()
	if plat.stopped != 1 {
		t.Errorf("platform Stop called %d times, want 1", plat.stopped)
	}
	if e.ctx.Err() == nil {
		t.Error("Stop should cancel the enforcer context")
	}
}

func TestEventLoop_ExitsOnClosedChannel(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})

	e.eventChan = make(chan *api.Event)
	e.wg.Add(1)
	done := make(chan struct{})
	go func() {
		e.eventLoop()
		close(done)
	}()
	close(e.eventChan)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("eventLoop did not exit when channel closed")
	}
}

func TestStop_NilPlatform(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	e.platform = nil
	e.Stop() // must not panic
}

func TestClose_ReleasesResources(t *testing.T) {
	rec := &sinkRecorder{}
	e, plat := newTestEnforcer(t, testEnforcerOpts{sink: rec})
	e.handleEvent(&api.Event{PID: 0, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls"})

	// Regression: Close used to panic by closing the WASM pool twice
	// (evaluator.Close followed by pool.Close).
	if err := e.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if plat.closed != 1 {
		t.Errorf("platform Close called %d times, want 1", plat.closed)
	}
	if e.platform != nil {
		t.Error("platform should be nil after Close")
	}
	if len(rec.snapshot()) != 1 {
		t.Error("pipeline should be flushed on Close")
	}
}

func TestClose_WithoutEvaluator(t *testing.T) {
	rec := &sinkRecorder{}
	e, plat := newTestEnforcer(t, testEnforcerOpts{sink: rec})
	e.handleEvent(&api.Event{PID: 0, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls"})

	// With only the pool/runtime set, each resource is closed exactly once.
	e.evaluator = nil
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	e.pool, e.wasmRuntime = nil, nil

	if plat.closed != 1 {
		t.Errorf("platform Close called %d times, want 1", plat.closed)
	}
	if e.platform != nil {
		t.Error("platform should be nil after Close")
	}
	if got := len(rec.snapshot()); got != 1 {
		t.Errorf("pipeline flushed %d events on Close, want 1", got)
	}
}

func TestClose_Minimal(t *testing.T) {
	e := &Enforcer{logger: logging.NewLoggerWithWriter("error", io.Discard), ctx: context.Background()}
	if err := e.Close(); err != nil {
		t.Fatalf("Close on minimal enforcer: %v", err)
	}
}

// ---- ReloadPolicy ----

func TestReloadPolicy_SwapsEvaluatorAndClearsCache(t *testing.T) {
	isolateCacheDir(t)
	e, _ := newTestEnforcer(t, testEnforcerOpts{})

	e.handleEvent(&api.Event{PID: 0, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls"})
	if e.cache.Stats().Size != 1 {
		t.Fatal("precondition: expected cached decision")
	}
	oldEval, oldPool := e.evaluator, e.pool

	// Avoid the known double-close of the old pool (see TestReloadPolicy_DoubleClose)
	// by letting ReloadPolicy close the old pool only via e.pool.
	e.evaluator = nil

	if err := e.ReloadPolicy(); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}
	if e.evaluator == nil || e.evaluator == oldEval || e.pool == oldPool {
		t.Error("expected evaluator and pool to be swapped")
	}
	if e.cache.Stats().Size != 0 {
		t.Error("cache must be cleared on reload")
	}

	// New evaluator must be functional and still enforce policy.
	e.handleEvent(&api.Event{PID: 0, UID: 0, Comm: "bash", Filename: "/bin/bash"})
	if got := e.GetStats().Denied; got != 1 {
		t.Errorf("Denied = %d after reload, want 1", got)
	}
}

func TestReloadPolicy_DoubleClose(t *testing.T) {
	isolateCacheDir(t)
	e, _ := newTestEnforcer(t, testEnforcerOpts{})

	// Regression: ReloadPolicy used to panic by closing the old pool twice
	// (oldEvaluator.Close followed by oldPool.Close).
	if err := e.ReloadPolicy(); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}
}

func TestReloadPolicy_YAMLWithPrecompiledWasm(t *testing.T) {
	isolateCacheDir(t)
	e, _ := newTestEnforcer(t, testEnforcerOpts{})

	dir := t.TempDir()
	data, err := os.ReadFile(testPolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.wasm"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	yamlPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(yamlPath, []byte("# precompiled sibling is used\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.policyPath = yamlPath
	e.evaluator = nil

	if err := e.ReloadPolicy(); err != nil {
		t.Fatalf("ReloadPolicy(yaml): %v", err)
	}
}

func TestReloadPolicy_Errors(t *testing.T) {
	dir := t.TempDir()

	// A valid module whose import can't be satisfied: compiles, but fails to
	// instantiate, exercising the pool-creation error path.
	unresolvable := []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
		0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section: () -> ()
		0x02, 0x0d, 0x01, // import section, 1 import
		0x04, 'n', 'o', 'p', 'e', // module "nope"
		0x04, 'n', 'o', 'p', 'e', // name "nope"
		0x00, 0x00, // func, type 0
	}
	badImport := filepath.Join(dir, "bad_import.wasm")
	if err := os.WriteFile(badImport, unresolvable, 0o600); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(dir, "garbage.wasm")
	if err := os.WriteFile(garbage, []byte("not wasm"), 0o600); err != nil {
		t.Fatal(err)
	}
	badYAML := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badYAML, []byte(":\t- [unbalanced"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr string
	}{
		{"missing wasm", filepath.Join(dir, "missing.wasm"), "load new policy"},
		{"invalid wasm", garbage, "load new policy"},
		{"missing yaml", filepath.Join(dir, "missing.yaml"), "load new YAML policy"},
		{"invalid yaml", badYAML, "load new YAML policy"},
		{"uninstantiable module", badImport, "create new policy pool"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isolateCacheDir(t)
			e, _ := newTestEnforcer(t, testEnforcerOpts{})
			e.handleEvent(&api.Event{PID: 0, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls"})
			oldEval := e.evaluator
			e.policyPath = tc.path

			err := e.ReloadPolicy()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ReloadPolicy() error = %v, want containing %q", err, tc.wantErr)
			}
			// Failed reload must keep the old policy active and the cache intact.
			if e.evaluator != oldEval {
				t.Error("evaluator must not change on failed reload")
			}
			if e.cache.Stats().Size != 1 {
				t.Error("cache must not be cleared on failed reload")
			}
			e.handleEvent(&api.Event{PID: 0, UID: 0, Comm: "bash", Filename: "/bin/bash"})
			if e.GetStats().Denied != 1 {
				t.Error("old policy should still enforce after failed reload")
			}
		})
	}
}

func writeFile(path string) error {
	return os.WriteFile(path, []byte("x"), 0o600)
}
