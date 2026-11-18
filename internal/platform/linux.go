//go:build linux

package platform

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/yasindce1998/warmor/internal/ebpf"
	"github.com/yasindce1998/warmor/internal/generationvm"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/pkg/api"
)

// LinuxConfig holds configuration for the Linux platform.
//
// Fields must stay aligned with platform.Config (see new_linux.go, which
// converts one to the other with LinuxConfig(cfg)).
type LinuxConfig struct {
	CgroupFilter []string
	LSMEnforce   bool
	RequireLSM   bool
	SkipLSM      bool
	AuditMode    bool

	IntegrityMode    string
	IntegrityDigests []string
	UnixWatch        []string

	LSMRingBufferSize       uint32
	OnEventLoss             string
	CgroupRoot              string
	CgroupReconcileInterval time.Duration
}

type tracepointMonitor interface {
	ReadProcessEvent() (*ebpf.Event, error)
	ReadFileEvent() (*ebpf.Event, error)
	ReadNetworkEvent() (*ebpf.Event, error)
	ReplaceCgroupFilter([]uint64) error
	StopReaders() error
	Close() error
}

// tracepointDropSource is implemented by *ebpf.Loader. It is a separate
// interface so test doubles of tracepointMonitor need not implement drop
// reporting; monitorTracepointDrops obtains it with a type assertion.
type tracepointDropSource interface {
	TracepointDrops() (map[string]uint64, error)
}

type LinuxPlatform struct {
	ebpfLoader    tracepointMonitor
	lsmLoader     *ebpf.LSMLoader
	eventChan     chan<- *api.Event
	stopChan      chan struct{}
	stopOnce      sync.Once
	stopErr       error
	wg            sync.WaitGroup
	config        LinuxConfig
	lsmEnabled    bool
	lsmBlocking   bool                  // true only after successful enforce-toggle initialization
	capture       func(*api.Event) bool // installed before Start; never changed afterward
	drainMu       sync.Mutex
	drainPending  chan struct{}
	drainObserved bool
	readerFailed  chan struct{}
	readerErr     error
	lsmEvents     lsmEventStream // production loader or VM-free reader fixture
	scope         cgroupScope
	// correlator pairs a tracepoint observation with its LSM twin so one
	// syscall is delivered once. Nil unless both monitors are active (LSM
	// loaded): direct-monitor unit tests and non-Linux builds never dedup.
	correlator *eventCorrelator
	// kernelSync is observability-only posture state mirroring recent
	// userspace→kernel policy-map sync health. Ready() never reads it: a
	// degraded kernel fast path must not make the daemon unready.
	kernelSync atomic.Bool // true = degraded; zero value is healthy
}

// SetKernelSyncHealthy mirrors the enforcer's kernel fast-path posture for
// readiness reporting. It is deliberately informational: LinuxPlatform.Ready()
// ignores it so degraded sync coverage never flips readiness by default.
func (p *LinuxPlatform) SetKernelSyncHealthy(healthy bool) {
	p.kernelSync.Store(!healthy)
}

// KernelSyncHealthy reports the mirrored kernel fast-path posture. It starts
// healthy (zero value) so an idle daemon reports healthy coverage.
func (p *LinuxPlatform) KernelSyncHealthy() bool {
	return !p.kernelSync.Load()
}

type lsmEventStream interface {
	ReadLSMEvent() (*ebpf.Event, error)
	FlushLSMEvents() error
	StopReaders() error
}

// Tracepoint↔LSM correlation. A single exec/connect/file operation is observed
// twice: a tracepoint (sys_enter_*, rich in argv/parent) and an LSM hook
// (bprm_check_security/file_open/security_socket_connect, carrying the kernel
// verdict and policy generation). The two ring buffers are read by different
// goroutines, so their delivery order is not guaranteed. We buffer the
// tracepoint observation briefly and let the LSM decision claim it.
//
// Pairing is deliberately conservative. A twin must share (cgroup, pid,
// event type) and carry a kernel timestamp within corrMaxSkewNS; a wider gap
// is treated as PID reuse and both events are kept. Unsure → deliver both.
const (
	// corrMaxSkewNS bounds how far apart the two bpf_ktime_get_ns stamps of
	// one operation may be. sys_enter_execve and bprm_check_security run at
	// different points in an exec; 100 ms is far wider than that gap but far
	// shorter than any realistic PID reuse window.
	corrMaxSkewNS uint64 = uint64(100 * time.Millisecond)
	// corrTTL is how long an unclaimed tracepoint waits for its LSM twin
	// before it is delivered as-is.
	corrTTL = time.Second
	// corrMaxEntries caps buffered tracepoints; beyond it the least-recently
	// used twin is evicted and delivered rather than dropped.
	corrMaxEntries = 4096
	// corrSweepInterval is the cadence for flushing TTL-expired twins.
	corrSweepInterval = 250 * time.Millisecond
)

// correlationKey identifies the process and syscall class a twin belongs to.
// The kernel timestamp is a skew dimension checked on lookup, not part of the
// key: the two observations of one exec never carry the exact same stamp.
type correlationKey struct {
	cgroupID  uint64
	pid       uint32
	eventType api.EventType
}

type corrEntry struct {
	key       correlationKey
	kernelTS  uint64
	event     *api.Event
	expiresAt time.Time
	elem      *list.Element
}

// eventCorrelator is a bounded, TTL+LRU window of unpaired tracepoint events.
// It is safe for concurrent use by the tracepoint readers, the LSM reader and
// the TTL sweeper.
type eventCorrelator struct {
	mu         sync.Mutex
	entries    map[correlationKey]*corrEntry
	lru        list.List // front = most recently added, back = oldest
	maxEntries int
	maxSkew    uint64
	ttl        time.Duration
	now        func() time.Time
}

func newEventCorrelator() *eventCorrelator {
	return &eventCorrelator{
		entries:    make(map[correlationKey]*corrEntry),
		maxEntries: corrMaxEntries,
		maxSkew:    corrMaxSkewNS,
		ttl:        corrTTL,
		now:        time.Now,
	}
}

func correlationKeyOf(event *api.Event) correlationKey {
	return correlationKey{cgroupID: event.CgroupID, pid: event.PID, eventType: event.GetType()}
}

func tsSkew(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return b - a
}

// removeEntryLocked unlinks e from both the map and the LRU list. Caller holds mu.
func (c *eventCorrelator) removeEntryLocked(e *corrEntry) {
	c.lru.Remove(e.elem)
	delete(c.entries, e.key)
}

// register enrolls a tracepoint observation as a potential twin. It returns
// any previously buffered events that must still be delivered: a displaced
// twin for the same key and/or LRU victims when the window is full.
func (c *eventCorrelator) register(event *api.Event) []*api.Event {
	if event == nil || event.KernelTimestampNS == 0 {
		return nil // never correlate events without a trusted kernel stamp
	}
	key := correlationKeyOf(event)
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()

	var out []*api.Event
	if old, ok := c.entries[key]; ok {
		out = append(out, old.event) // a twin from a different operation: keep it
		c.removeEntryLocked(old)
	}
	e := &corrEntry{
		key: key, kernelTS: event.KernelTimestampNS,
		event: event, expiresAt: now.Add(c.ttl),
	}
	e.elem = c.lru.PushFront(e)
	c.entries[key] = e
	for c.lru.Len() > c.maxEntries {
		back := c.lru.Back()
		victim := back.Value.(*corrEntry)
		out = append(out, victim.event)
		c.removeEntryLocked(victim)
	}
	return out
}

// correlate tries to claim the tracepoint twin of an LSM decision. The
// returned twin (when non-nil) has been removed from the window; the caller
// merges its process context into the LSM event and suppresses the twin. A
// present-but-expired twin is returned in expired for unconditional delivery
// so TTL expiry never loses a security event.
func (c *eventCorrelator) correlate(lsm *api.Event) (twin *api.Event, expired []*api.Event) {
	if lsm == nil || lsm.KernelTimestampNS == 0 || !correlatableHook(lsm.Hook) {
		return nil, nil
	}
	key := correlationKeyOf(lsm)
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[key]
	if !ok {
		return nil, nil
	}
	if !now.Before(e.expiresAt) {
		expired = append(expired, e.event)
		c.removeEntryLocked(e)
		return nil, expired
	}
	if tsSkew(e.kernelTS, lsm.KernelTimestampNS) > c.maxSkew {
		// PID reuse suspicion: keep both, leave the twin for TTL delivery.
		return nil, nil
	}
	twin = e.event
	c.removeEntryLocked(e)
	return twin, nil
}

// flushExpired returns every twin whose TTL elapsed, removing them from the
// window. LRU order is arrival order and TTL is uniform, so the back expires
// first and we can stop at the first unexpired entry.
func (c *eventCorrelator) flushExpired() []*api.Event {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*api.Event
	for {
		back := c.lru.Back()
		if back == nil {
			break
		}
		e := back.Value.(*corrEntry)
		if now.Before(e.expiresAt) {
			break
		}
		out = append(out, e.event)
		c.removeEntryLocked(e)
	}
	return out
}

// flushAll drains the window (e.g. on shutdown) so buffered observations are
// never lost.
func (c *eventCorrelator) flushAll() []*api.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*api.Event, 0, c.lru.Len())
	for e := c.lru.Front(); e != nil; e = e.Next() {
		out = append(out, e.Value.(*corrEntry).event)
	}
	c.entries = make(map[correlationKey]*corrEntry)
	c.lru.Init()
	return out
}

// correlatableHook restricts dedup to LSM hooks whose twin carries context
// worth inheriting and whose delivery can tolerate a short buffer window.
// exec/connect twins supply argv/parent/PPID for the richer tracepoint payload.
// file_open is deliberately excluded: every open is high-frequency, it has no
// process context to merge, and buffering it for the correlation TTL adds up
// to 1s of latency that breaks latency-sensitive paths (e.g. the supervised
// host's held-load confirmation, which completes inside a 500ms window).
// Hooks such as ptrace/mount/bind/listen/connect_unix have no tracepoint
// counterpart and must never be paired with an unrelated observation.
func correlatableHook(hook string) bool {
	switch hook {
	case "exec", "connect":
		return true
	default:
		return false
	}
}

// correlatableTracepoint is the mirror of correlatableHook for the tracepoint
// side: only process (exec) and network (connect) observations are buffered.
// File opens are delivered immediately so their high volume never waits on the
// correlation TTL (which would add up to 1s of latency to every file event).
func correlatableTracepoint(event *api.Event) bool {
	if event == nil {
		return false
	}
	switch event.GetType() {
	case api.EventTypeProcess, api.EventTypeNetwork:
		return true
	default:
		return false
	}
}

// inheritProcessContext grafts the tracepoint's richer process context onto
// the authoritative LSM-origin event. The LSM kernel decision fields
// (KernelDenied, PolicyGeneration, Hook, ...) are left untouched.
func inheritProcessContext(dst, src *api.Event) {
	if src == nil {
		return
	}
	if src.PPID != 0 {
		dst.PPID = src.PPID
	}
	if src.ParentComm != "" {
		dst.ParentComm = src.ParentComm
	}
	dst.TruncatedFields = append(dst.TruncatedFields, src.TruncatedFields...)
	if src.Process == nil {
		return
	}
	if dst.Process == nil {
		cp := *src.Process
		cp.Args = slices.Clone(src.Process.Args)
		dst.Process = &cp
		return
	}
	if len(dst.Process.Args) == 0 && src.Process.Args != nil {
		dst.Process.Args = slices.Clone(src.Process.Args)
	}
	if dst.Process.Filename == "" {
		dst.Process.Filename = src.Process.Filename
	}
}

func duplicateEventType(event *api.Event) string {
	switch event.GetType() {
	case api.EventTypeProcess:
		return "exec"
	case api.EventTypeFile:
		return "file"
	case api.EventTypeNetwork:
		return "network"
	default:
		return "unknown"
	}
}

func NewLinuxPlatform(config LinuxConfig) (Platform, error) {
	if config.SkipLSM && config.RequireLSM {
		return nil, fmt.Errorf("cannot skip LSM when LSM is required")
	}
	if config.CgroupRoot == "" {
		config.CgroupRoot = "/sys/fs/cgroup"
	}
	if !filepath.IsAbs(config.CgroupRoot) {
		return nil, fmt.Errorf("cgroup root must be an absolute host mount path")
	}
	if config.CgroupReconcileInterval < 0 {
		return nil, fmt.Errorf("cgroup reconcile interval must be positive")
	}
	if config.CgroupReconcileInterval == 0 {
		config.CgroupReconcileInterval = time.Second
	}
	if config.AuditMode {
		config.LSMEnforce = false
		if config.IntegrityMode == "enforce" {
			config.IntegrityMode = "audit"
		}
	}
	return &LinuxPlatform{
		stopChan:     make(chan struct{}),
		config:       config,
		readerFailed: make(chan struct{}),
	}, nil
}

func (p *LinuxPlatform) Name() string {
	return "linux"
}

func (p *LinuxPlatform) Load(ctx context.Context) (loadErr error) {
	defer func() {
		if loadErr != nil {
			_ = p.Close()
			p.ebpfLoader = nil
			p.lsmLoader = nil
			p.lsmEnabled = false
			p.lsmBlocking = false
		}
	}()
	loader, err := ebpf.Load()
	if err != nil {
		return fmt.Errorf("load eBPF: %w", err)
	}
	p.ebpfLoader = loader

	// BPF's bpf_get_current_cgroup_id() (kernfs node id) only matches the
	// statx-inode scope IDs used for cgroup filtering and kernel default-deny
	// marking on cgroup v2. Refuse v1/unknown views before arming either.
	if err := p.requireCgroupV2ForEnforcement(); err != nil {
		return err
	}

	var cgroupIDs []uint64
	if len(p.config.CgroupFilter) > 0 {
		p.scope.enabled = true
		if len(p.config.CgroupFilter) == 1 && p.config.CgroupFilter[0] == "auto" {
			cgroupIDs, err = ebpf.DiscoverPodCgroups(p.config.CgroupRoot)
			if err != nil {
				return fmt.Errorf("discover pod cgroups: %w", err)
			}
		} else {
			cgroupIDs, err = ebpf.ResolveCgroupIDs(p.config.CgroupFilter)
			if err != nil {
				return fmt.Errorf("resolve cgroup filter: %w", err)
			}
		}
		if err := loader.ReplaceCgroupFilter(cgroupIDs); err != nil {
			return fmt.Errorf("set cgroup filter: %w", err)
		}
		p.scope.accept(cgroupIDs, nil)
	}

	// Attempt to load LSM-BPF programs. By default this is a graceful
	// fallback: if the kernel can't load them we keep running in
	// tracepoint-only (observe) mode. With RequireLSM set, the operator has
	// demanded kernel enforcement, so any failure to establish it is fatal
	// (fail-closed startup) rather than a silent downgrade.
	if p.config.SkipLSM {
		fmt.Println("LSM-BPF loading skipped (--no-lsm)")
		p.logSecurityPosture()
		return nil
	}
	onLoss, err := ebpf.ParseOnEventLoss(p.config.OnEventLoss)
	if err != nil {
		return err
	}
	lsmLoader, err := ebpf.LoadLSMWithOptions(ebpf.LSMOptions{
		RingBufferSize: p.config.LSMRingBufferSize,
		OnEventLoss:    onLoss,
	})
	if err != nil {
		if p.config.RequireLSM {
			return fmt.Errorf("LSM-BPF required (--require-lsm) but failed to load: %w", err)
		}
		fmt.Printf("WARNING: LSM-BPF load failed: %v (continuing with tracepoints only)\n", err)
	}
	if lsmLoader == nil {
		// Kernel does not support BPF LSM (LoadLSM returns nil,nil).
		if p.config.RequireLSM {
			return fmt.Errorf("LSM-BPF required (--require-lsm) but the kernel does not support BPF LSM " +
				"(need CONFIG_BPF_LSM=y and \"bpf\" in /sys/kernel/security/lsm); refusing to start")
		}
		if p.config.LSMEnforce {
			fmt.Println("WARNING: --lsm-enforce was requested but BPF LSM is unavailable on this kernel; " +
				"kernel-level blocking is INACTIVE (running in observe mode). Pass --require-lsm to fail closed instead.")
		}
	}
	if lsmLoader != nil {
		p.lsmLoader = lsmLoader
		p.lsmEvents = lsmLoader
		p.lsmEnabled = true

		if err := p.initializeLSMPosture(cgroupIDs, lsmLoader.ReplaceCgroupFilter, lsmLoader.SetEnforceMode); err != nil {
			return err
		}
	}

	if p.lsmLoader != nil && len(p.config.UnixWatch) > 0 {
		if err := p.lsmLoader.SetUnixWatch(p.config.UnixWatch); err != nil {
			fmt.Printf("WARNING: runtime socket watch unavailable: %v\n", err)
		}
	}

	if err := p.loadIntegrity(); err != nil {
		return err
	}

	p.logSecurityPosture()
	return nil
}

// requireCgroupV2ForEnforcement asserts the cgroup view before any feature
// that correlates BPF cgroup IDs with userspace scope IDs is armed. Kernel
// default-deny marking (--lsm-enforce) and cgroup filtering both depend on
// bpf_get_current_cgroup_id() matching the statx-inode IDs from cgroup.go,
// which only holds on cgroup v2. It is a no-op when neither is requested, so
// observe-only runs on v1 are unaffected.
func (p *LinuxPlatform) requireCgroupV2ForEnforcement() error {
	if !p.config.LSMEnforce && len(p.config.CgroupFilter) == 0 {
		return nil
	}
	return ebpf.RequireCgroupV2(p.config.CgroupRoot)
}

// initializeLSMPosture publishes blocking status only after both scope and the
// kernel toggle have been written successfully. Injection tests this boundary
// without loading BPF or installing hooks.
func (p *LinuxPlatform) initializeLSMPosture(ids []uint64, replaceScope func([]uint64) error, setEnforce func(bool) error) error {
	p.lsmBlocking = false
	// Scope MUST be established before enabling blocking. Optional LSM does
	// not make filter failures optional: never expand to the host.
	if len(p.config.CgroupFilter) > 0 {
		if err := replaceScope(ids); err != nil {
			return fmt.Errorf("set LSM cgroup filter: %w", err)
		}
	}
	if err := setEnforce(p.config.LSMEnforce); err != nil {
		return fmt.Errorf("set LSM enforce mode: %w", err)
	}
	p.lsmBlocking = p.config.LSMEnforce
	return nil
}

// LSMBlocking reports initialized blocking posture, not merely loaded hooks.
// The posture is fixed after Load and is never modified by policy activation.
func (p *LinuxPlatform) LSMBlocking() bool { return p.lsmEnabled && p.lsmBlocking }

// loadIntegrity enables the content-hash exec check when configured. It needs
// the LSM programs, so asking for it without them is an error rather than a
// silent downgrade.
func (p *LinuxPlatform) loadIntegrity() error {
	mode, err := ebpf.ParseIntegrityMode(p.config.IntegrityMode)
	if err != nil {
		return err
	}
	if mode == ebpf.IntegrityOff {
		return nil
	}
	if p.lsmLoader == nil {
		return fmt.Errorf("--integrity-mode=%s requires BPF LSM, which is not loaded on this host", mode)
	}
	digests := make([]ebpf.Digest, 0, len(p.config.IntegrityDigests))
	for _, s := range p.config.IntegrityDigests {
		d, err := ebpf.ParseDigest(s)
		if err != nil {
			return fmt.Errorf("integrity allowlist: %w", err)
		}
		digests = append(digests, d)
	}
	if err := p.lsmLoader.EnableIntegrity(digests, mode); err != nil {
		return fmt.Errorf("enable integrity checking: %w", err)
	}
	fmt.Printf("Exec integrity: %s (%d allowlisted SHA-256 digests)\n", mode, len(digests))
	return nil
}

// logSecurityPosture prints a one-line summary of the active enforcement
// posture so operators can see at a glance whether the kernel fast-path is
// blocking, merely auditing, or absent.
func (p *LinuxPlatform) logSecurityPosture() {
	switch {
	case p.LSMBlocking():
		fmt.Println("Security posture: LSM-BPF kernel enforcement ACTIVE (deny rules blocked in-kernel)")
	case p.lsmEnabled:
		fmt.Println("Security posture: LSM-BPF loaded in AUDIT-ONLY mode (deny rules logged, not blocked); pass --lsm-enforce to block")
	default:
		fmt.Println("Security posture: OBSERVE-ONLY via tracepoints (no kernel-level enforcement)")
	}
}

func (p *LinuxPlatform) Start(ctx context.Context, eventChan chan<- *api.Event) error {
	if p.ebpfLoader == nil {
		return fmt.Errorf("platform not loaded")
	}
	// stopChan is closed for good once Stop runs; monitors started now would
	// exit immediately, so refuse rather than silently capture nothing.
	select {
	case <-p.stopChan:
		return fmt.Errorf("platform already stopped")
	default:
	}
	p.eventChan = eventChan

	goroutines := 4
	if p.lsmEnabled {
		goroutines = 7 // + LSM reader, drop poll, correlation TTL sweeper
		p.correlator = newEventCorrelator()
	}
	if p.autoCgroups() {
		goroutines++
	}
	p.wg.Add(goroutines)
	go p.monitorProcessEvents(ctx)
	go p.monitorFileEvents(ctx)
	go p.monitorNetworkEvents(ctx)
	go p.monitorTracepointDrops(ctx)

	if p.lsmEnabled {
		go p.monitorLSMEvents(ctx)
		go p.monitorEventDrops(ctx)
		go p.monitorCorrelation(ctx)
	}
	if p.autoCgroups() {
		go p.monitorCgroups(ctx)
	}

	return nil
}

func (p *LinuxPlatform) monitorProcessEvents(ctx context.Context) {
	p.monitorProcessEventsFrom(ctx, p.ebpfLoader.ReadProcessEvent)
}

func (p *LinuxPlatform) monitorProcessEventsFrom(ctx context.Context, read func() (*ebpf.Event, error)) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		default:
		}

		ev, err := read()
		if err != nil {
			p.readerError(err)
			return
		}
		if !p.scope.contains(ev.CgroupID) {
			continue
		}

		event := &api.Event{
			Type:              api.EventTypeProcess,
			PID:               ev.PID,
			UID:               ev.UID,
			GID:               ev.GID,
			Comm:              ev.Comm,
			Filename:          ev.Filename,
			Timestamp:         ev.Timestamp,
			KernelTimestampNS: ev.KernelTimestampNS,
			CgroupID:          ev.CgroupID,
			PPID:              ev.PPID,
			ParentComm:        ev.ParentComm,
			TruncatedFields:   append([]string(nil), ev.TruncatedFields...),
			Process: &api.ProcessEvent{
				BaseEvent: api.BaseEvent{
					Type:      api.EventTypeProcess,
					PID:       ev.PID,
					UID:       ev.UID,
					GID:       ev.GID,
					Comm:      ev.Comm,
					Timestamp: ev.Timestamp,
					CgroupID:  ev.CgroupID,
				},
				Filename: ev.Filename,
				Args:     ev.Args,
			},
		}

		if !p.deliverTracepoint(ctx, event) {
			return
		}
	}
}

func (p *LinuxPlatform) monitorFileEvents(ctx context.Context) {
	p.monitorFileEventsFrom(ctx, p.ebpfLoader.ReadFileEvent)
}

func (p *LinuxPlatform) monitorFileEventsFrom(ctx context.Context, read func() (*ebpf.Event, error)) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		default:
		}

		ev, err := read()
		if err != nil {
			p.readerError(err)
			return
		}
		if !p.scope.contains(ev.CgroupID) {
			continue
		}

		event := &api.Event{
			Type:              api.EventTypeFile,
			PID:               ev.PID,
			UID:               ev.UID,
			GID:               ev.GID,
			Comm:              ev.Comm,
			Filename:          ev.Filename,
			Timestamp:         ev.Timestamp,
			KernelTimestampNS: ev.KernelTimestampNS,
			CgroupID:          ev.CgroupID,
			File: &api.FileEvent{
				BaseEvent: api.BaseEvent{
					Type:      api.EventTypeFile,
					PID:       ev.PID,
					UID:       ev.UID,
					GID:       ev.GID,
					Comm:      ev.Comm,
					Timestamp: ev.Timestamp,
					CgroupID:  ev.CgroupID,
				},
				Operation: "open",
				Path:      ev.Filename,
				Flags:     ev.Flags,
				Mode:      ev.Mode,
			},
		}

		if !p.deliverTracepoint(ctx, event) {
			return
		}
	}
}

func (p *LinuxPlatform) monitorNetworkEvents(ctx context.Context) {
	p.monitorNetworkEventsFrom(ctx, p.ebpfLoader.ReadNetworkEvent)
}

func (p *LinuxPlatform) monitorNetworkEventsFrom(ctx context.Context, read func() (*ebpf.Event, error)) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		default:
		}

		ev, err := read()
		if err != nil {
			p.readerError(err)
			return
		}
		if !p.scope.contains(ev.CgroupID) {
			continue
		}

		protocol := "tcp"
		if ev.Family == 10 {
			protocol = "tcp6"
		}

		event := &api.Event{
			Type:              api.EventTypeNetwork,
			PID:               ev.PID,
			UID:               ev.UID,
			GID:               ev.GID,
			Comm:              ev.Comm,
			Timestamp:         ev.Timestamp,
			KernelTimestampNS: ev.KernelTimestampNS,
			CgroupID:          ev.CgroupID,
			Network: &api.NetworkEvent{
				BaseEvent: api.BaseEvent{
					Type:      api.EventTypeNetwork,
					PID:       ev.PID,
					UID:       ev.UID,
					GID:       ev.GID,
					Comm:      ev.Comm,
					Timestamp: ev.Timestamp,
					CgroupID:  ev.CgroupID,
				},
				Operation:  "connect",
				Protocol:   protocol,
				RemoteAddr: ev.RemoteAddr,
				RemotePort: ev.RemotePort,
			},
		}

		if !p.deliverTracepoint(ctx, event) {
			return
		}
	}
}

func (p *LinuxPlatform) monitorLSMEvents(ctx context.Context) {
	p.monitorLSMEventsFrom(ctx, p.lsmEvents.ReadLSMEvent)
}

func (p *LinuxPlatform) monitorLSMEventsFrom(ctx context.Context, read func() (*ebpf.Event, error)) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		default:
		}

		ev, err := read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrFlushed) {
				p.drainMu.Lock()
				fence := p.drainPending
				if p.drainObserved {
					fence = nil
				}
				if fence != nil {
					p.drainObserved = true
				}
				p.drainMu.Unlock()
				if fence != nil && !p.deliver(ctx, &api.Event{DispatchBarrier: fence}) {
					return
				}
				continue
			}
			p.drainMu.Lock()
			p.readerErr = err
			// Withdraw local readiness before waking generation drain waiters.
			p.readerError(err)
			if p.readerFailed != nil {
				close(p.readerFailed)
			}
			p.drainMu.Unlock()
			return
		}
		if !p.scope.contains(ev.CgroupID) {
			continue
		}
		metrics.RecordLSMDecision(ebpf.LSMHookName(ev.LSMHook), ebpf.LSMDecisionAction(ev.LSMDecision))

		event := &api.Event{
			Type:              api.EventType(ev.Kind),
			PID:               ev.PID,
			UID:               ev.UID,
			GID:               ev.GID,
			Comm:              ev.Comm,
			Filename:          ev.Filename,
			Timestamp:         ev.Timestamp,
			KernelTimestampNS: ev.KernelTimestampNS,
			CgroupID:          ev.CgroupID,
			LSMEvent:          true,
			PolicyGeneration:  ev.PolicyGeneration,

			KernelDenied:       ev.KernelDenied,
			IntegrityViolation: ev.IntegrityViolation,
			Hook:               ev.Hook,
			MountSource:        ev.MountSource,
			TargetCgroupID:     ev.TargetCgroupID,
		}

		switch ev.Kind {
		case ebpf.EventKindProcess:
			event.Process = &api.ProcessEvent{
				BaseEvent: api.BaseEvent{
					Type:      api.EventTypeProcess,
					PID:       ev.PID,
					UID:       ev.UID,
					GID:       ev.GID,
					Comm:      ev.Comm,
					Timestamp: ev.Timestamp,
					CgroupID:  ev.CgroupID,
				},
				Filename: ev.Filename,
			}
		case ebpf.EventKindFile:
			event.File = &api.FileEvent{
				BaseEvent: api.BaseEvent{
					Type:      api.EventTypeFile,
					PID:       ev.PID,
					UID:       ev.UID,
					GID:       ev.GID,
					Comm:      ev.Comm,
					Timestamp: ev.Timestamp,
					CgroupID:  ev.CgroupID,
				},
				Operation: "open",
				Path:      ev.Filename,
			}
		case ebpf.EventKindNetwork:
			protocol := "tcp"
			if ev.Family == 10 {
				protocol = "tcp6"
			}
			event.Network = &api.NetworkEvent{
				BaseEvent: api.BaseEvent{
					Type:      api.EventTypeNetwork,
					PID:       ev.PID,
					UID:       ev.UID,
					GID:       ev.GID,
					Comm:      ev.Comm,
					Timestamp: ev.Timestamp,
					CgroupID:  ev.CgroupID,
				},
				Operation:  "connect",
				Protocol:   protocol,
				RemoteAddr: ev.RemoteAddr,
				RemotePort: ev.RemotePort,
			}
		}

		if !p.deliverLSM(ctx, event) {
			return
		}
	}
}

func (p *LinuxPlatform) SetEventCapture(capture func(*api.Event) bool) { p.capture = capture }

// deliverTracepoint enrolls a tracepoint observation in the correlation window
// instead of delivering it immediately when LSM is active. Anything evicted
// from the bounded window is delivered first so no observation is lost; for a
// confident twin the LSM path delivers the single merged event instead.
func (p *LinuxPlatform) deliverTracepoint(ctx context.Context, event *api.Event) bool {
	if p.correlator == nil || !correlatableTracepoint(event) {
		return p.deliver(ctx, event)
	}
	for _, evicted := range p.correlator.register(event) {
		if !p.deliver(ctx, evicted) {
			return false
		}
	}
	return true
}

// deliverLSM claims the tracepoint twin of an LSM decision (if any). On a
// confident pair the twin's argv/parent context is inherited into the LSM
// event, the twin is suppressed, the pair is counted, and the single enriched
// event is delivered. Unpaired decisions pass through unchanged.
func (p *LinuxPlatform) deliverLSM(ctx context.Context, event *api.Event) bool {
	if p.correlator != nil {
		twin, expired := p.correlator.correlate(event)
		if twin != nil {
			inheritProcessContext(event, twin)
			event.Deduplicated = true
			metrics.RecordDuplicateEvent(duplicateEventType(event))
		}
		// TTL-expired twins are delivered unpaired; best effort only. Never
		// let a failed sidecar delivery suppress the authoritative decision.
		for _, ev := range expired {
			p.deliver(ctx, ev)
		}
	}
	return p.deliver(ctx, event)
}

// monitorCorrelation periodically delivers twins whose LSM counterpart never
// arrived within the TTL window, so a tracepoint-only observation is still
// surfaced rather than waiting indefinitely for a twin.
func (p *LinuxPlatform) monitorCorrelation(ctx context.Context) {
	defer p.wg.Done()
	ticker := time.NewTicker(corrSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		case <-ticker.C:
		}
		for _, ev := range p.correlator.flushExpired() {
			if !p.deliver(ctx, ev) {
				return
			}
		}
	}
}

func (p *LinuxPlatform) deliver(ctx context.Context, event *api.Event) bool {
	if event.DispatchBarrier == nil && p.capture != nil && !p.capture(event) {
		return true // unknown generation is refused, never relabeled as current
	}
	if event.DispatchBarrier == nil {
		generationvm.Capture(event)
	}
	// Delivery is intentionally blocking (backpressure), not drop-on-full:
	// these events feed kernel verdicts and carry generation dispatch fences,
	// so shedding one would change enforcement semantics and could strand a
	// generation drain. Probe with a non-blocking send first only to make
	// that backpressure visible; when the channel is full, count the blocked
	// delivery and fall through to the original blocking select below. No
	// event is dropped and ordering/cancellation behavior is unchanged.
	select {
	case p.eventChan <- event:
		return true
	default:
		metrics.RecordEventChannelBackpressure()
	}
	select {
	case p.eventChan <- event:
		return true
	case <-ctx.Done():
	case <-p.stopChan:
	}
	event.GenerationContext.Complete()
	return false
}

type linuxPolicyGenerations struct {
	*ebpf.GenerationManager
	p *LinuxPlatform
}

func (p *LinuxPlatform) PolicyGenerations() PolicyGenerations {
	if p.lsmLoader == nil {
		return nil
	}
	return &linuxPolicyGenerations{p.lsmLoader.PolicyGenerations(), p}
}

// Drain never reads the ring itself. The existing single reader must observe
// ErrFlushed and enqueue a fence behind every old sample, even NO_WAKEUP ones.
// A timed-out request remains outstanding; retries wait for that SAME fence.
func (g *linuxPolicyGenerations) Drain(ctx context.Context) error {
	p := g.p
	p.drainMu.Lock()
	if err := p.drainStatus(ctx); err != nil {
		p.drainMu.Unlock()
		return err
	}
	if p.readerErr != nil {
		err := p.readerErr
		p.drainMu.Unlock()
		return err
	}
	if p.drainPending == nil {
		p.drainPending = make(chan struct{})
		p.drainObserved = false
		if err := p.lsmEvents.FlushLSMEvents(); err != nil {
			p.drainPending = nil
			p.drainMu.Unlock()
			return err
		}
	}
	fence := p.drainPending
	p.drainMu.Unlock()
	select {
	case <-fence:
		p.drainMu.Lock()
		if err := p.drainStatus(ctx); err != nil {
			p.drainMu.Unlock()
			return err
		}
		if p.drainPending == fence {
			p.drainPending = nil
		}
		p.drainMu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-p.stopChan:
		return errors.New("LSM reader stopped before drain")
	case <-p.readerFailed:
		p.drainMu.Lock()
		err := p.readerErr
		p.drainMu.Unlock()
		return err
	}
}

func (p *LinuxPlatform) drainStatus(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-p.stopChan:
		return errors.New("LSM reader stopped before drain")
	default:
		return nil
	}
}

// monitorTracepointDrops publishes the kernel's per-hook tracepoint drop
// counters as warmor_tracepoint_events_dropped_total. A dropped tracepoint
// event is an observation nobody received, so it must never be silent.
// Non-Loader monitors (test doubles) simply have nothing to publish.
func (p *LinuxPlatform) monitorTracepointDrops(ctx context.Context) {
	defer p.wg.Done()
	source, ok := p.ebpfLoader.(tracepointDropSource)
	if !ok {
		return
	}
	seen := make(map[string]uint64)
	tick := time.NewTicker(dropPollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		case <-tick.C:
		}
		drops, err := source.TracepointDrops()
		if err != nil {
			continue
		}
		var fresh uint64
		for hook, total := range drops {
			if total < seen[hook] {
				seen[hook] = 0 // counters reset when objects are reloaded
			}
			if d := total - seen[hook]; d > 0 {
				metrics.RecordTracepointEventsDropped(hook, d)
				fresh += d
			}
			seen[hook] = total
		}
		if fresh > 0 {
			fmt.Printf("WARNING: %d tracepoint events dropped in the last %s (ring buffer full); "+
				"those observations were lost. See warmor_tracepoint_events_dropped_total.\n",
				fresh, dropPollInterval)
		}
	}
}

// dropPollInterval is how often the kernel drop counters are published.
const dropPollInterval = 5 * time.Second

// monitorEventDrops publishes the kernel's per-hook event drop counters (the
// ring buffer was full) as warmor_lsm_events_dropped_total and logs when new
// drops appear: a dropped miss is an operation nobody evaluated.
func (p *LinuxPlatform) monitorEventDrops(ctx context.Context) {
	defer p.wg.Done()
	seen := make(map[string]uint64)
	tick := time.NewTicker(dropPollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		case <-tick.C:
		}
		drops, err := p.lsmLoader.EventDrops()
		if err != nil {
			continue
		}
		var fresh uint64
		for hook, total := range drops {
			if d := total - seen[hook]; d > 0 {
				metrics.RecordLSMEventsDropped(hook, d)
				fresh += d
			}
			seen[hook] = total
		}
		if fresh > 0 {
			fmt.Printf("WARNING: %d LSM events dropped in the last %s (ring buffer full); "+
				"those operations were %s without evaluation. See warmor_lsm_events_dropped_total.\n",
				fresh, dropPollInterval, p.lossVerb())
		}
	}
}

func (p *LinuxPlatform) lossVerb() string {
	if p.config.OnEventLoss == "deny" && p.config.LSMEnforce {
		return "refused (exec/connect) or allowed (other hooks)"
	}
	return "allowed"
}

// Stop signals the monitors to exit and waits for them. It is idempotent.
func (p *LinuxPlatform) Stop() error {
	p.stopOnce.Do(func() {
		close(p.stopChan)
		// Readers can be idle forever (including ReadLSMEvent's deadline
		// retry loop). Interrupt them before waiting, but keep enforcement
		// hooks/maps alive until Close finishes the resource lifecycle.
		var errs []error
		if p.ebpfLoader != nil {
			errs = append(errs, p.ebpfLoader.StopReaders())
		}
		if p.lsmEvents != nil {
			errs = append(errs, p.lsmEvents.StopReaders())
		} else if p.lsmLoader != nil {
			errs = append(errs, p.lsmLoader.StopReaders())
		}
		p.stopErr = errors.Join(errs...)
	})
	p.wg.Wait()
	// All readers have stopped: deliver any twins still waiting for an LSM
	// counterpart so shutdown never strands a security observation.
	if p.correlator != nil {
		for _, ev := range p.correlator.flushAll() {
			p.deliver(context.Background(), ev)
		}
	}
	return p.stopErr
}

func (p *LinuxPlatform) Close() error {
	var errs []error
	if err := p.Stop(); err != nil {
		errs = append(errs, err)
	}
	if p.lsmLoader != nil {
		if err := p.lsmLoader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if p.ebpfLoader != nil {
		if err := p.ebpfLoader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}
	return nil
}

func (p *LinuxPlatform) Capabilities() Capabilities {
	return Capabilities{
		ProcessMonitoring: true,
		FileMonitoring:    true,
		NetworkMonitoring: true,
		Enforcement:       true,
		LSMEnforcement:    p.lsmEnabled,
	}
}

// PolicyMap returns the LSM policy map manager, or nil if LSM is not active.
func (p *LinuxPlatform) PolicyMap() any {
	if p.lsmLoader == nil {
		return nil
	}
	return p.lsmLoader.PolicyMap()
}
