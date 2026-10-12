//go:build windows

package platform

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/yasindce1998/warmor/internal/platform/efw"
	"github.com/yasindce1998/warmor/internal/platform/etw"
	"github.com/yasindce1998/warmor/internal/platform/winutil"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Backends a Windows event type can be served by.
const (
	BackendEBPF = "ebpf" // eBPF-for-Windows hook: blocks in the kernel
	BackendETW  = "etw"  // ETW provider: detect, then terminate
	BackendNone = "none"
)

// WindowsConfig selects how kernel enforcement is set up.
type WindowsConfig struct {
	// SkipEBPF uses ETW for every event type (--no-lsm).
	SkipEBPF bool
	// RequireEBPF fails Load unless at least one eBPF hook attaches
	// (--require-lsm).
	RequireEBPF bool
	// ProgramDir overrides where the native eBPF images are looked up.
	ProgramDir string
}

// WindowsPlatform picks a backend per event type: eBPF-for-Windows where a
// hook exists and loads (network; process with ntosebpfext), ETW for
// everything else (always for files). ETW providers are only enabled for the
// event types eBPF does not own, so no event is reported twice.
type WindowsPlatform struct {
	cfg WindowsConfig

	procs *winutil.ProcTable
	paths *winutil.DevicePathMap

	ebpf *efw.Loader
	etw  *etw.Consumer

	mu       sync.RWMutex
	backends map[api.EventType]string

	stopOnce sync.Once
	stopErr  error
}

// NewWindowsPlatform creates the Windows platform.
func NewWindowsPlatform(cfg WindowsConfig) (Platform, error) {
	return &WindowsPlatform{
		cfg:      cfg,
		procs:    winutil.NewProcTable(),
		backends: make(map[api.EventType]string),
	}, nil
}

func (p *WindowsPlatform) Name() string { return "windows" }

func (p *WindowsPlatform) Load(ctx context.Context) error {
	p.paths = winutil.NewDevicePathMap(winutil.LoadDriveDevices())

	if p.cfg.SkipEBPF {
		log.Println("Windows: eBPF disabled by configuration; using ETW only")
	} else if err := efw.Available(); err != nil {
		log.Printf("Windows: eBPF-for-Windows unavailable, using ETW: %v", err)
	} else if loader, err := efw.Load(efw.Options{Dir: p.cfg.ProgramDir, Procs: p.procs, Paths: p.paths}); err != nil {
		log.Printf("Windows: eBPF programs not loaded, using ETW: %v", err)
	} else {
		p.ebpf = loader
	}

	if p.cfg.RequireEBPF && p.ebpf == nil {
		return errors.New("eBPF kernel enforcement required (--require-lsm) but no eBPF-for-Windows hook could be attached")
	}

	p.backends[api.EventTypeProcess] = BackendETW
	p.backends[api.EventTypeNetwork] = BackendETW
	p.backends[api.EventTypeFile] = BackendETW
	if p.ebpf != nil && p.ebpf.Process() {
		p.backends[api.EventTypeProcess] = BackendEBPF
	}
	if p.ebpf != nil && p.ebpf.Network() {
		p.backends[api.EventTypeNetwork] = BackendEBPF
	}

	// Processes started before us: the process table resolves their PIDs
	// for file/network events, and the network hooks need their images.
	if procs, err := winutil.SnapshotProcesses(p.paths); err != nil {
		log.Printf("Windows: process snapshot failed: %v", err)
	} else {
		for _, info := range procs {
			p.procs.Put(info)
			p.trackProcess(info)
		}
	}

	var providers []etw.Provider
	if p.backends[api.EventTypeProcess] == BackendETW {
		providers = append(providers, etw.ProviderProcess)
	}
	if p.backends[api.EventTypeNetwork] == BackendETW {
		providers = append(providers, etw.ProviderNetwork)
	}
	providers = append(providers, etw.ProviderFile)

	consumer, err := etw.NewConsumer(etw.Options{
		Providers:      providers,
		Procs:          p.procs,
		Paths:          p.paths,
		OnProcessStart: p.trackProcess,
		OnProcessExit:  p.forgetProcess,
	})
	if err != nil {
		p.closeEBPF()
		return fmt.Errorf("create ETW consumer: %w", err)
	}
	p.etw = consumer

	p.logBackends()
	return nil
}

// trackProcess feeds processes seen by ETW or the snapshot to the eBPF
// network hooks. Processes reported by the eBPF process hook are tracked by
// the loader itself.
func (p *WindowsPlatform) trackProcess(info winutil.ProcInfo) {
	if p.ebpf != nil {
		p.ebpf.PolicyMap().TrackProcess(info)
	}
}

func (p *WindowsPlatform) forgetProcess(pid uint32) {
	if p.ebpf != nil {
		p.ebpf.PolicyMap().ForgetProcess(pid)
	}
}

func (p *WindowsPlatform) Start(ctx context.Context, eventChan chan<- *api.Event) error {
	if p.etw == nil {
		return errors.New("platform not loaded")
	}
	if p.ebpf != nil {
		p.ebpf.Start(ctx, eventChan)
	}

	if err := p.etw.Start(eventChan); err != nil {
		if p.ebpf == nil {
			return fmt.Errorf("start ETW consumer: %w", err)
		}
		log.Printf("Windows: ETW unavailable, continuing with eBPF only: %v", err)
	}

	// A provider that failed to enable leaves its event type unmonitored.
	p.mu.Lock()
	for et, provider := range map[api.EventType]etw.Provider{
		api.EventTypeProcess: etw.ProviderProcess,
		api.EventTypeNetwork: etw.ProviderNetwork,
		api.EventTypeFile:    etw.ProviderFile,
	} {
		if p.backends[et] == BackendETW && !p.etw.Enabled(provider) {
			p.backends[et] = BackendNone
		}
	}
	p.mu.Unlock()

	p.logBackends()
	return nil
}

func (p *WindowsPlatform) logBackends() {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, et := range []api.EventType{api.EventTypeProcess, api.EventTypeNetwork, api.EventTypeFile} {
		switch b := p.backends[et]; b {
		case BackendEBPF:
			log.Printf("Windows: %-7s → eBPF-for-Windows (kernel blocking)", et)
		case BackendETW:
			log.Printf("Windows: %-7s → ETW (detect, then terminate)", et)
		default:
			log.Printf("Windows: %-7s → not monitored", et)
		}
	}
}

// Backends reports which backend serves each event type.
func (p *WindowsPlatform) Backends() map[api.EventType]string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[api.EventType]string, len(p.backends))
	for k, v := range p.backends {
		out[k] = v
	}
	return out
}

// Stop stops event delivery and detaches eBPF programs. Safe to call more
// than once (the enforcer calls Stop and then Close).
func (p *WindowsPlatform) Stop() error {
	p.stopOnce.Do(func() {
		if p.etw != nil {
			p.stopErr = p.etw.Stop()
		}
		p.closeEBPF()
	})
	return p.stopErr
}

func (p *WindowsPlatform) closeEBPF() {
	if p.ebpf != nil {
		_ = p.ebpf.Stop()
	}
}

func (p *WindowsPlatform) Close() error { return p.Stop() }

func (p *WindowsPlatform) Capabilities() Capabilities {
	b := p.Backends()
	return Capabilities{
		ProcessMonitoring: b[api.EventTypeProcess] != BackendNone,
		FileMonitoring:    b[api.EventTypeFile] != BackendNone,
		NetworkMonitoring: b[api.EventTypeNetwork] != BackendNone,
		// Every backend can at least terminate the offending process.
		Enforcement: true,
		// Kernel blocking for the event types served by eBPF.
		LSMEnforcement: p.ebpf != nil,
	}
}

// PolicyMap returns the eBPF policy map syncer when any hook is attached.
func (p *WindowsPlatform) PolicyMap() any {
	if p.ebpf == nil {
		return nil
	}
	return p.ebpf.PolicyMap()
}
