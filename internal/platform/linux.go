//go:build linux

package platform

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/ebpf"
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

	IntegrityMode    string
	IntegrityDigests []string
	UnixWatch        []string

	LSMRingBufferSize uint32
	OnEventLoss       string
}

type LinuxPlatform struct {
	ebpfLoader *ebpf.Loader
	lsmLoader  *ebpf.LSMLoader
	eventChan  chan<- *api.Event
	stopChan   chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
	config     LinuxConfig
	lsmEnabled bool
}

func NewLinuxPlatform(config LinuxConfig) (Platform, error) {
	return &LinuxPlatform{
		stopChan: make(chan struct{}),
		config:   config,
	}, nil
}

func (p *LinuxPlatform) Name() string {
	return "linux"
}

func (p *LinuxPlatform) Load(ctx context.Context) error {
	loader, err := ebpf.Load()
	if err != nil {
		return fmt.Errorf("load eBPF: %w", err)
	}
	p.ebpfLoader = loader

	var cgroupIDs []uint64
	if len(p.config.CgroupFilter) > 0 {
		if len(p.config.CgroupFilter) == 1 && p.config.CgroupFilter[0] == "auto" {
			cgroupIDs, err = ebpf.DiscoverPodCgroups("/sys/fs/cgroup")
			if err != nil {
				loader.Close()
				return fmt.Errorf("discover pod cgroups: %w", err)
			}
		} else {
			cgroupIDs, err = ebpf.ResolveCgroupIDs(p.config.CgroupFilter)
			if err != nil {
				loader.Close()
				return fmt.Errorf("resolve cgroup filter: %w", err)
			}
		}
		if err := loader.SetCgroupFilter(cgroupIDs); err != nil {
			loader.Close()
			return fmt.Errorf("set cgroup filter: %w", err)
		}
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
		loader.Close()
		return err
	}
	lsmLoader, err := ebpf.LoadLSMWithOptions(ebpf.LSMOptions{
		RingBufferSize: p.config.LSMRingBufferSize,
		OnEventLoss:    onLoss,
	})
	if err != nil {
		if p.config.RequireLSM {
			loader.Close()
			return fmt.Errorf("LSM-BPF required (--require-lsm) but failed to load: %w", err)
		}
		fmt.Printf("WARNING: LSM-BPF load failed: %v (continuing with tracepoints only)\n", err)
	}
	if lsmLoader == nil {
		// Kernel does not support BPF LSM (LoadLSM returns nil,nil).
		if p.config.RequireLSM {
			loader.Close()
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
		p.lsmEnabled = true

		if err := lsmLoader.SetEnforceMode(p.config.LSMEnforce); err != nil {
			if p.config.RequireLSM {
				loader.Close()
				return fmt.Errorf("LSM-BPF required (--require-lsm) but failed to set enforce mode: %w", err)
			}
			fmt.Printf("WARNING: failed to set LSM enforce mode: %v\n", err)
		}

		if len(cgroupIDs) > 0 {
			if err := lsmLoader.SetCgroupFilter(cgroupIDs); err != nil {
				fmt.Printf("WARNING: failed to set LSM cgroup filter: %v\n", err)
			}
		}
	}

	if p.lsmLoader != nil && len(p.config.UnixWatch) > 0 {
		if err := p.lsmLoader.SetUnixWatch(p.config.UnixWatch); err != nil {
			fmt.Printf("WARNING: runtime socket watch unavailable: %v\n", err)
		}
	}

	if err := p.loadIntegrity(); err != nil {
		p.Close()
		return err
	}

	p.logSecurityPosture()
	return nil
}

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
	case p.lsmEnabled && p.config.LSMEnforce:
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

	goroutines := 3
	if p.lsmEnabled {
		goroutines = 5
	}
	p.wg.Add(goroutines)
	go p.monitorProcessEvents(ctx)
	go p.monitorFileEvents(ctx)
	go p.monitorNetworkEvents(ctx)

	if p.lsmEnabled {
		go p.monitorLSMEvents(ctx)
		go p.monitorEventDrops(ctx)
	}

	return nil
}

func (p *LinuxPlatform) monitorProcessEvents(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		default:
		}

		ev, err := p.ebpfLoader.ReadProcessEvent()
		if err != nil {
			continue
		}

		event := &api.Event{
			Type:      api.EventTypeProcess,
			PID:       ev.PID,
			UID:       ev.UID,
			GID:       ev.GID,
			Comm:      ev.Comm,
			Filename:  ev.Filename,
			Timestamp: ev.Timestamp,
			CgroupID:  ev.CgroupID,
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
			},
		}

		select {
		case p.eventChan <- event:
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		}
	}
}

func (p *LinuxPlatform) monitorFileEvents(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		default:
		}

		ev, err := p.ebpfLoader.ReadFileEvent()
		if err != nil {
			continue
		}

		event := &api.Event{
			Type:      api.EventTypeFile,
			PID:       ev.PID,
			UID:       ev.UID,
			GID:       ev.GID,
			Comm:      ev.Comm,
			Filename:  ev.Filename,
			Timestamp: ev.Timestamp,
			CgroupID:  ev.CgroupID,
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

		select {
		case p.eventChan <- event:
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		}
	}
}

func (p *LinuxPlatform) monitorNetworkEvents(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		default:
		}

		ev, err := p.ebpfLoader.ReadNetworkEvent()
		if err != nil {
			continue
		}

		protocol := "tcp"
		if ev.Family == 10 {
			protocol = "tcp6"
		}

		event := &api.Event{
			Type:      api.EventTypeNetwork,
			PID:       ev.PID,
			UID:       ev.UID,
			GID:       ev.GID,
			Comm:      ev.Comm,
			Timestamp: ev.Timestamp,
			CgroupID:  ev.CgroupID,
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

		select {
		case p.eventChan <- event:
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		}
	}
}

func (p *LinuxPlatform) monitorLSMEvents(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		default:
		}

		ev, err := p.lsmLoader.ReadLSMEvent()
		if err != nil {
			continue
		}
		metrics.RecordLSMDecision(ebpf.LSMHookName(ev.LSMHook), ebpf.LSMDecisionAction(ev.LSMDecision))

		event := &api.Event{
			Type:      api.EventType(ev.Kind),
			PID:       ev.PID,
			UID:       ev.UID,
			GID:       ev.GID,
			Comm:      ev.Comm,
			Filename:  ev.Filename,
			Timestamp: ev.Timestamp,
			CgroupID:  ev.CgroupID,
			LSMEvent:  true,

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

		select {
		case p.eventChan <- event:
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
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
	p.stopOnce.Do(func() { close(p.stopChan) })
	p.wg.Wait()
	return nil
}

func (p *LinuxPlatform) Close() error {
	var errs []error
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
