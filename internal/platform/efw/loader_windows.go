//go:build windows

package efw

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/windows"

	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/platform/winutil"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Native image file names (built by bpf-windows/build.ps1).
const (
	NetImage  = "warmor_net.sys"
	ProcImage = "warmor_proc.sys"
)

// eBPF-for-Windows attach types (enum bpf_attach_type in ebpf_structs.h).
// cilium/ebpf only names the older ones, so they are encoded here.
const (
	attachCgroupInet4Connect    = 3
	attachCgroupInet6Connect    = 4
	attachCgroupInet4RecvAccept = 5
	attachCgroupInet6RecvAccept = 6
	attachProcess               = 11 // implemented by ntosebpfext
)

// Options configures a Loader.
type Options struct {
	// Dir holds the native images. When empty, the "bpf" directory next to
	// the executable and then the executable's own directory are searched.
	Dir string
	// Procs and Paths are shared with the ETW consumer. Required.
	Procs *winutil.ProcTable
	Paths *winutil.DevicePathMap
}

// Available reports whether the eBPF-for-Windows runtime is installed: its
// user-mode API (ebpfapi.dll) loads and its driver is reachable.
func Available() error {
	if err := windows.NewLazySystemDLL("ebpfapi.dll").Load(); err != nil {
		return fmt.Errorf("ebpfapi.dll not found (install eBPF-for-Windows): %w", err)
	}
	path, _ := windows.UTF16PtrFromString(`\\.\ebpfctl`)
	h, err := windows.CreateFile(path, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return fmt.Errorf("eBPF-for-Windows driver not reachable: %w", err)
	}
	_ = windows.CloseHandle(h)
	return nil
}

// Loader owns the loaded programs, their links and ring buffer readers.
type Loader struct {
	opts Options

	net  *ebpf.Collection
	proc *ebpf.Collection

	links   []link.Link
	readers []*ringbuf.Reader

	netOK  bool
	procOK bool

	policy *PolicyMap

	wg       sync.WaitGroup
	stopOnce sync.Once

	received atomic.Uint64
	dropped  atomic.Uint64
	bad      atomic.Uint64
}

// Load loads and attaches whatever the host supports. Network enforcement
// needs only eBPF-for-Windows; process enforcement also needs ntosebpfext.
// Each part that fails is logged and left to the ETW fallback; Load errors
// only if nothing could be attached.
func Load(opts Options) (*Loader, error) {
	if opts.Procs == nil || opts.Paths == nil {
		return nil, errors.New("efw: Procs and Paths are required")
	}
	dir, err := findImageDir(opts.Dir)
	if err != nil {
		return nil, err
	}
	l := &Loader{opts: opts}

	if err := l.loadNet(filepath.Join(dir, NetImage)); err != nil {
		log.Printf("eBPF: network enforcement unavailable: %v", err)
	}
	if err := l.loadProc(filepath.Join(dir, ProcImage)); err != nil {
		log.Printf("eBPF: process enforcement unavailable (is ntosebpfext installed?): %v", err)
	}
	if !l.netOK && !l.procOK {
		l.close()
		return nil, errors.New("efw: no program could be attached")
	}

	l.policy = &PolicyMap{paths: opts.Paths, procs: opts.Procs}
	if l.netOK {
		l.policy.netPolicy = l.net.Maps["net_policy"]
		l.policy.procInfo = l.net.Maps["proc_info"]
	}
	if l.procOK {
		l.policy.procDeny = l.proc.Maps["proc_deny"]
	}
	return l, nil
}

func findImageDir(dir string) (string, error) {
	candidates := []string{dir}
	if dir == "" {
		candidates = nil
		if exe, err := os.Executable(); err == nil {
			candidates = append(candidates, filepath.Join(filepath.Dir(exe), "bpf"), filepath.Dir(exe))
		}
	}
	for _, d := range candidates {
		if _, err := os.Stat(filepath.Join(d, NetImage)); err == nil {
			return d, nil
		}
		if _, err := os.Stat(filepath.Join(d, ProcImage)); err == nil {
			return d, nil
		}
	}
	return "", fmt.Errorf("efw: no native images (%s, %s) in %v; build them with bpf-windows/build.ps1",
		NetImage, ProcImage, candidates)
}

func (l *Loader) loadNet(path string) error {
	coll, err := ebpf.LoadCollection(path)
	if err != nil {
		return fmt.Errorf("load %s: %w", path, err)
	}
	for _, name := range []string{"net_policy", "proc_info", "net_events"} {
		if coll.Maps[name] == nil {
			coll.Close()
			return fmt.Errorf("%s: map %q missing", path, name)
		}
	}

	// Outbound enforcement is the point of this image: without both connect
	// hooks the image is not used at all. Accept hooks are best effort.
	required := []struct {
		prog   string
		attach uint32
	}{
		{"warmor_connect4", attachCgroupInet4Connect},
		{"warmor_connect6", attachCgroupInet6Connect},
	}
	optional := []struct {
		prog   string
		attach uint32
	}{
		{"warmor_recv_accept4", attachCgroupInet4RecvAccept},
		{"warmor_recv_accept6", attachCgroupInet6RecvAccept},
	}

	var links []link.Link
	for _, p := range required {
		lk, err := attach(coll, p.prog, p.attach)
		if err != nil {
			for _, lk := range links {
				_ = lk.Close()
			}
			coll.Close()
			return err
		}
		links = append(links, lk)
	}
	for _, p := range optional {
		lk, err := attach(coll, p.prog, p.attach)
		if err != nil {
			log.Printf("eBPF: %v (inbound connections fall back to userspace)", err)
			continue
		}
		links = append(links, lk)
	}

	rd, err := ringbuf.NewReader(coll.Maps["net_events"])
	if err != nil {
		for _, lk := range links {
			_ = lk.Close()
		}
		coll.Close()
		return fmt.Errorf("net_events reader: %w", err)
	}

	l.net = coll
	l.links = append(l.links, links...)
	l.readers = append(l.readers, rd)
	l.netOK = true
	log.Printf("eBPF: network hooks attached (%d programs)", len(links))
	return nil
}

func (l *Loader) loadProc(path string) error {
	coll, err := ebpf.LoadCollection(path)
	if err != nil {
		return fmt.Errorf("load %s: %w", path, err)
	}
	for _, name := range []string{"proc_deny", "proc_events"} {
		if coll.Maps[name] == nil {
			coll.Close()
			return fmt.Errorf("%s: map %q missing", path, name)
		}
	}
	lk, err := attach(coll, "warmor_process", attachProcess)
	if err != nil {
		coll.Close()
		return err
	}
	rd, err := ringbuf.NewReader(coll.Maps["proc_events"])
	if err != nil {
		_ = lk.Close()
		coll.Close()
		return fmt.Errorf("proc_events reader: %w", err)
	}

	l.proc = coll
	l.links = append(l.links, lk)
	l.readers = append(l.readers, rd)
	l.procOK = true
	log.Println("eBPF: process hook attached")
	return nil
}

func attach(coll *ebpf.Collection, name string, attachType uint32) (link.Link, error) {
	prog := coll.Programs[name]
	if prog == nil {
		return nil, fmt.Errorf("program %q missing", name)
	}
	at, err := ebpf.AttachTypeForPlatform("windows", attachType)
	if err != nil {
		return nil, fmt.Errorf("attach type %d: %w", attachType, err)
	}
	lk, err := link.AttachRawLink(link.RawLinkOptions{Program: prog, Attach: at})
	if err != nil {
		return nil, fmt.Errorf("attach %s: %w", name, err)
	}
	return lk, nil
}

// Network reports whether connect/accept hooks are enforcing.
func (l *Loader) Network() bool { return l.netOK }

// Process reports whether the process hook is enforcing.
func (l *Loader) Process() bool { return l.procOK }

// PolicyMap returns the kernel policy map syncer.
func (l *Loader) PolicyMap() *PolicyMap { return l.policy }

// Start delivers kernel events to eventChan until Stop.
func (l *Loader) Start(ctx context.Context, eventChan chan<- *api.Event) {
	for _, rd := range l.readers {
		l.wg.Add(1)
		go func(rd *ringbuf.Reader) {
			defer l.wg.Done()
			l.readLoop(ctx, rd, eventChan)
		}(rd)
	}
}

func (l *Loader) readLoop(ctx context.Context, rd *ringbuf.Reader, eventChan chan<- *api.Event) {
	var rec ringbuf.Record
	for {
		if err := rd.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return
			}
			l.bad.Add(1)
			continue
		}
		l.received.Add(1)

		decoded, err := parseRecord(rec.RawSample)
		if err != nil {
			l.bad.Add(1)
			continue
		}
		ev := l.handle(decoded)
		if ev == nil {
			continue
		}
		select {
		case eventChan <- ev:
		default:
			l.dropped.Add(1)
			metrics.RecordEventDropped()
		}
	}
}

// verdictAction maps a kernel verdict to the warmor_lsm_decisions_total
// action label used on every platform: "deny" for a policy deny (blocked,
// or only logged in audit mode), "pass" otherwise.
func verdictAction(v Verdict) string {
	if v == VerdictBlocked || v == VerdictAudit {
		return "deny"
	}
	return "pass"
}

func (l *Loader) handle(decoded any) *api.Event {
	switch r := decoded.(type) {
	case *ProcessRecord:
		if r.Exit {
			l.opts.Procs.Exit(r.PID)
			l.policy.ForgetProcess(r.PID)
			return nil
		}
		metrics.RecordLSMDecision("exec", verdictAction(r.Verdict))
		ts := time.Now()
		if r.CreationTime > 0 {
			ts = time.Unix(0, (r.CreationTime-116444736000000000)*100)
		}
		info := winutil.ProcInfo{
			PID:        r.PID,
			PPID:       r.PPID,
			NTImage:    r.NTImage,
			Image:      l.opts.Paths.TranslateImage(r.NTImage),
			Comm:       winutil.CommFromPath(r.NTImage),
			CmdLine:    r.CmdLine,
			CreateTime: ts,
		}
		l.opts.Procs.Put(info)
		if r.Verdict == VerdictBlocked {
			// The creation was denied: the process never runs.
			l.opts.Procs.Exit(r.PID)
		} else {
			l.policy.trackHash(r.PID, r.ImageHash)
		}
		ev := winutil.ProcessEvent(info, ts)
		ev.LSMEvent = r.Verdict == VerdictBlocked
		return ev

	case *NetworkRecord:
		metrics.RecordLSMDecision(r.Operation(), verdictAction(r.Verdict))
		ts := time.Now()
		proc, _ := l.opts.Procs.Get(r.PID)
		netEv := &api.NetworkEvent{
			BaseEvent:  api.BaseEvent{Type: api.EventTypeNetwork, PID: r.PID, Comm: proc.Comm, Timestamp: ts},
			Operation:  r.Operation(),
			Protocol:   r.ProtocolName(),
			RemoteAddr: r.Remote.Addr().String(),
			RemotePort: r.Remote.Port(),
			LocalAddr:  r.Local.Addr().String(),
			LocalPort:  r.Local.Port(),
		}
		return &api.Event{
			Type:      api.EventTypeNetwork,
			PID:       r.PID,
			Comm:      proc.Comm,
			Filename:  proc.Image,
			Timestamp: ts,
			Network:   netEv,
			LSMEvent:  r.Verdict == VerdictBlocked,
		}
	}
	return nil
}

// Stats returns event counters.
func (l *Loader) Stats() (received, dropped, malformed uint64) {
	return l.received.Load(), l.dropped.Load(), l.bad.Load()
}

// Stop detaches every program (enforcement stops with the daemon: nothing
// is pinned) and waits for the readers. Safe to call more than once.
func (l *Loader) Stop() error {
	l.stopOnce.Do(func() {
		for _, rd := range l.readers {
			_ = rd.Close()
		}
		l.wg.Wait()
		l.close()
		r, d, b := l.Stats()
		log.Printf("eBPF: stopped (received=%d dropped=%d malformed=%d)", r, d, b)
	})
	return nil
}

func (l *Loader) close() {
	for _, lk := range l.links {
		_ = lk.Close()
	}
	l.links = nil
	if l.net != nil {
		l.net.Close()
		l.net = nil
	}
	if l.proc != nil {
		l.proc.Close()
		l.proc = nil
	}
}
