//go:build windows

package etw

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/platform/winutil"
	"github.com/yasindce1998/warmor/pkg/api"
	"golang.org/x/sys/windows"
)

// Microsoft-Windows-Kernel-Process event IDs.
const (
	processEventStart = 1
	processEventStop  = 2
)

// DefaultSessionName is the real-time session the daemon owns.
const DefaultSessionName = "WarmorETW"

// Options configures a Consumer.
type Options struct {
	// SessionName defaults to DefaultSessionName.
	SessionName string
	// Providers to enable. Event types owned by eBPF-for-Windows are left
	// out so events are never reported twice.
	Providers []Provider
	// Procs and Paths are shared with the eBPF loader. Required.
	Procs *winutil.ProcTable
	Paths *winutil.DevicePathMap
	// OnProcessStart/OnProcessExit are called for every process event the
	// session sees, whether or not it is forwarded. Optional.
	OnProcessStart func(winutil.ProcInfo)
	OnProcessExit  func(pid uint32)
}

// Stats are consumer counters.
type Stats struct {
	Received uint64 // events delivered by ETW
	Emitted  uint64 // events sent to the enforcer
	Dropped  uint64 // events lost because the enforcer channel was full
}

// Consumer runs one real-time ETW session with the kernel providers
// enabled on it.
type Consumer struct {
	opts    Options
	selfPID uint32

	session uint64
	trace   uint64
	enabled map[Provider]bool

	eventChan chan<- *api.Event
	done      chan struct{}
	stopOnce  sync.Once
	stopErr   error

	fileObjs *fileObjectTable
	udp      *udpDeduper

	received atomic.Uint64
	emitted  atomic.Uint64
	dropped  atomic.Uint64
}

// ETW invokes a C callback that cannot carry Go state, and the number of
// callbacks syscall.NewCallback can create is limited, so one callback is
// created per process and dispatches to the running consumer.
var (
	active       atomic.Pointer[Consumer]
	callbackOnce sync.Once
	callbackPtr  uintptr
)

// NewConsumer creates a consumer. Nothing is started until Start.
func NewConsumer(opts Options) (*Consumer, error) {
	if opts.Procs == nil || opts.Paths == nil {
		return nil, errors.New("etw: Procs and Paths are required")
	}
	if opts.SessionName == "" {
		opts.SessionName = DefaultSessionName
	}
	return &Consumer{
		opts:     opts,
		selfPID:  windows.GetCurrentProcessId(),
		enabled:  make(map[Provider]bool),
		done:     make(chan struct{}),
		fileObjs: newFileObjectTable(),
		udp:      newUDPDeduper(),
	}, nil
}

// Start starts the session, enables the providers and begins delivering
// events. A provider that cannot be enabled is logged and skipped; Start
// fails only if none can be.
func (c *Consumer) Start(eventChan chan<- *api.Event) error {
	if len(c.opts.Providers) == 0 {
		close(c.done)
		return nil
	}
	if !active.CompareAndSwap(nil, c) {
		return errors.New("etw: another consumer is already running in this process")
	}
	c.eventChan = eventChan

	session, err := startSession(c.opts.SessionName)
	if err != nil {
		active.Store(nil)
		return err
	}
	c.session = session

	for _, p := range c.opts.Providers {
		if err := enableProvider(session, p.guid(), p.Keywords()); err != nil {
			log.Printf("ETW: %s provider unavailable: %v", p, err)
			continue
		}
		c.enabled[p] = true
	}
	if len(c.enabled) == 0 {
		_ = stopSessionByName(c.opts.SessionName)
		active.Store(nil)
		return errors.New("etw: no provider could be enabled")
	}

	callbackOnce.Do(func() { callbackPtr = syscall.NewCallback(eventRecordCallback) })
	trace, err := openRealtimeTrace(c.opts.SessionName, callbackPtr)
	if err != nil {
		_ = stopSessionByName(c.opts.SessionName)
		active.Store(nil)
		return err
	}
	c.trace = trace

	go func() {
		defer close(c.done)
		if err := processTrace(trace); err != nil {
			log.Printf("ETW: %v", err)
		}
	}()

	log.Printf("ETW: session %q started (providers: %v)", c.opts.SessionName, c.EnabledProviders())
	return nil
}

// Enabled reports whether a provider is delivering events.
func (c *Consumer) Enabled(p Provider) bool { return c.enabled[p] }

// EnabledProviders lists the providers delivering events.
func (c *Consumer) EnabledProviders() []Provider {
	var ps []Provider
	for _, p := range []Provider{ProviderProcess, ProviderFile, ProviderNetwork} {
		if c.enabled[p] {
			ps = append(ps, p)
		}
	}
	return ps
}

// Stop stops the session and waits for delivery to end. Safe to call more
// than once.
func (c *Consumer) Stop() error {
	c.stopOnce.Do(func() {
		if c.session == 0 {
			return
		}
		// Stopping the session flushes it and makes ProcessTrace return;
		// closing the consumer handle covers a session that is already gone.
		err := stopSessionByName(c.opts.SessionName)
		if c.trace != 0 {
			if cerr := closeTrace(c.trace); cerr != nil && err == nil {
				err = cerr
			}
		}
		select {
		case <-c.done:
		case <-time.After(5 * time.Second):
			if err == nil {
				err = errors.New("etw: timed out waiting for ProcessTrace to return")
			}
		}
		active.CompareAndSwap(c, nil)
		c.stopErr = err
	})
	return c.stopErr
}

// Stats returns consumer counters.
func (c *Consumer) Stats() Stats {
	return Stats{
		Received: c.received.Load(),
		Emitted:  c.emitted.Load(),
		Dropped:  c.dropped.Load(),
	}
}

func eventRecordCallback(rec *eventRecord) uintptr {
	c := active.Load()
	if c == nil || rec == nil {
		return 0
	}
	// A panic must not unwind into ETW's C frames.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ETW: panic decoding event: %v", r)
		}
	}()
	c.received.Add(1)

	var ev *api.Event
	switch rec.EventHeader.ProviderID {
	case processProviderGUID:
		ev = c.handleProcess(rec)
	case fileProviderGUID:
		ev = c.handleFile(rec)
	case networkProviderGUID:
		ev = c.handleNetwork(rec)
	}
	if ev == nil {
		return 0
	}

	// Never block ETW's delivery thread: a stalled consumer makes the
	// session drop events for everyone.
	select {
	case c.eventChan <- ev:
		c.emitted.Add(1)
	default:
		c.dropped.Add(1)
		metrics.RecordEventDropped()
	}
	return 0
}

func (c *Consumer) handleProcess(rec *eventRecord) *api.Event {
	ts := filetimeToTime(rec.EventHeader.TimeStamp)
	pid64, err := propUint(rec, "ProcessID")
	if err != nil {
		return nil
	}
	pid := uint32(pid64)

	switch rec.EventHeader.EventDescriptor.ID {
	case processEventStart:
		nt := firstString(rec, "ImageName")
		info := winutil.ProcInfo{
			PID:        pid,
			NTImage:    nt,
			Image:      c.opts.Paths.TranslateImage(nt),
			Comm:       winutil.CommFromPath(nt),
			CreateTime: ts,
		}
		if ppid, err := propUint(rec, "ParentProcessID"); err == nil {
			info.PPID = uint32(ppid)
		}
		if ct, err := propUint(rec, "CreateTime"); err == nil && ct != 0 {
			info.CreateTime = filetimeToTime(int64(ct))
		}
		// Kernel-Process carries no command line. The process has only
		// just started, so read it from the live process (best effort:
		// short-lived processes may already be gone).
		if cmd, err := winutil.QueryCommandLine(pid); err == nil {
			info.CmdLine = cmd
		}
		c.opts.Procs.Put(info)
		if c.opts.OnProcessStart != nil {
			c.opts.OnProcessStart(info)
		}
		if !c.enabled[ProviderProcess] {
			return nil
		}
		return winutil.ProcessEvent(info, ts)

	case processEventStop:
		c.opts.Procs.Exit(pid)
		if c.opts.OnProcessExit != nil {
			c.opts.OnProcessExit(pid)
		}
	}
	return nil
}

func (c *Consumer) handleFile(rec *eventRecord) *api.Event {
	pid := rec.EventHeader.ProcessID
	if pid == c.selfPID {
		return nil // our own policy/log/cache I/O would feed back
	}

	r := fileRecord{EventID: rec.EventHeader.EventDescriptor.ID}
	if obj, err := propUint(rec, "FileObject"); err == nil {
		r.FileObject = obj
	}

	switch r.EventID {
	case fileEventCreate, fileEventCreateNewFile:
		r.Path = firstString(rec, "FileName", "OpenPath")
		if opts, err := propUint(rec, "CreateOptions"); err == nil {
			r.CreateOptions = uint32(opts)
		}
		c.fileObjs.opened(r.FileObject, r.Path)
	case fileEventWrite:
		path, first, ok := c.fileObjs.firstWrite(r.FileObject)
		if !ok || !first {
			return nil
		}
		r.Path = path
	case fileEventDeletePath, fileEventRenamePath:
		r.Path = firstString(rec, "FilePath", "FileName")
	default:
		return nil
	}
	if r.Path == "" {
		return nil
	}

	op, ok := fileOperation(&r)
	if !ok {
		return nil
	}
	ts := filetimeToTime(rec.EventHeader.TimeStamp)
	path := c.opts.Paths.Translate(r.Path)
	proc := c.lookupProcess(pid)

	ev := &api.Event{
		Type:      api.EventTypeFile,
		PID:       pid,
		Comm:      proc.Comm,
		Filename:  path,
		Timestamp: ts,
		File: &api.FileEvent{
			BaseEvent: api.BaseEvent{Type: api.EventTypeFile, PID: pid, Comm: proc.Comm, Timestamp: ts},
			Operation: op,
			Path:      path,
			Flags:     r.CreateOptions,
		},
	}
	return ev
}

func (c *Consumer) handleNetwork(rec *eventRecord) *api.Event {
	id := rec.EventHeader.EventDescriptor.ID
	if _, _, ok := netOperation(id); !ok {
		return nil
	}

	r := netRecord{EventID: id, PID: rec.EventHeader.ProcessID}
	// The PID property is the owning process; the header PID can be System
	// for work the stack does on a process's behalf.
	if pid, err := propUint(rec, "PID"); err == nil {
		r.PID = uint32(pid)
	}
	if r.PID == c.selfPID {
		return nil
	}
	r.Daddr, _ = propBytes(rec, "daddr")
	r.Saddr, _ = propBytes(rec, "saddr")
	r.Dport, _ = propBytes(rec, "dport")
	r.Sport, _ = propBytes(rec, "sport")

	ts := filetimeToTime(rec.EventHeader.TimeStamp)
	netEv, ok := r.toNetworkEvent(ts)
	if !ok {
		return nil
	}
	if netEv.Operation == "sendto" && !c.udp.first(r.PID, netEv.RemoteAddr, netEv.RemotePort, ts) {
		return nil
	}

	proc := c.lookupProcess(r.PID)
	netEv.Comm = proc.Comm
	return &api.Event{
		Type:      api.EventTypeNetwork,
		PID:       r.PID,
		Comm:      proc.Comm,
		Filename:  proc.Image,
		Timestamp: ts,
		Network:   netEv,
	}
}

// lookupProcess resolves a PID through the process table, querying the live
// process on a miss (processes started before the snapshot raced us).
func (c *Consumer) lookupProcess(pid uint32) winutil.ProcInfo {
	if p, ok := c.opts.Procs.Get(pid); ok {
		return p
	}
	info := winutil.ProcInfo{PID: pid, CreateTime: time.Now()}
	if nt, err := winutil.QueryImageNT(pid); err == nil {
		info.NTImage = nt
		info.Image = c.opts.Paths.TranslateImage(nt)
		info.Comm = winutil.CommFromPath(nt)
		if ct, err := winutil.ProcessCreateTime(pid); err == nil {
			info.CreateTime = ct
		}
	} else if pid == 4 {
		info.Comm = "system"
	}
	// Cache failures too: protected processes (System, Registry, PPL
	// services) refuse the query, and they issue file I/O constantly. A
	// later start event for the PID replaces the entry.
	c.opts.Procs.Put(info)
	return info
}

// String implements fmt.Stringer for logs.
func (s Stats) String() string {
	return fmt.Sprintf("received=%d emitted=%d dropped=%d", s.Received, s.Emitted, s.Dropped)
}
