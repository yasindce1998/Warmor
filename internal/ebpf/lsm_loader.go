//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type warmor_event -type policy_key -type policy_value -type lsm_config lsm_exec ../../bpf/lsm_exec.bpf.c -- -I../../bpf -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type warmor_event lsm_file ../../bpf/lsm_file.bpf.c -- -I../../bpf -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go lsm_connect ../../bpf/lsm_connect.bpf.c -- -I../../bpf -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go lsm_bind ../../bpf/lsm_bind.bpf.c -- -I../../bpf -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go lsm_listen ../../bpf/lsm_listen.bpf.c -- -I../../bpf -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go lsm_ptrace ../../bpf/lsm_ptrace.bpf.c -- -I../../bpf -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go lsm_mount ../../bpf/lsm_mount.bpf.c -- -I../../bpf -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu

// LSMEvent matches struct warmor_event in warmor_lsm.h
type LSMEvent struct {
	PID          uint32
	UID          uint32
	GID          uint32
	Comm         [16]byte
	Filename     [256]byte
	_            [4]byte
	Timestamp    uint64
	CgroupID     uint64
	EventType    uint8
	Decision     uint8
	RemotePort   uint16
	RemoteAddrV4 uint32
	RemoteAddrV6 [16]byte
	Family       uint16
	_            [6]byte
	Aux          [64]byte
	AuxID        uint64
}

// ToEvent converts an LSMEvent to a unified Event.
func (e *LSMEvent) ToEvent() Event {
	ev := Event{
		PID:       e.PID,
		UID:       e.UID,
		GID:       e.GID,
		Comm:      nullTerminatedString(e.Comm[:]),
		Filename:  nullTerminatedString(e.Filename[:]),
		Timestamp: bootTimeToWallClock(e.Timestamp),
		CgroupID:  e.CgroupID,

		LSMHook:     e.EventType,
		LSMDecision: e.Decision,
		// decision 1 = the kernel refused the operation (see warmor_event).
		KernelDenied: e.Decision == 1,
	}

	switch e.EventType {
	case EventTypeExec:
		ev.Hook = "exec"
		ev.Kind = EventKindProcess
	case EventTypeFile:
		ev.Hook = "file"
		ev.Kind = EventKindFile
	case EventTypeNetwork, EventTypeBind:
		ev.Hook = "connect"
		if e.EventType == EventTypeBind {
			ev.Hook = "bind"
		}
		ev.Kind = EventKindNetwork
		if e.Family == 1 { // AF_UNIX: Filename is the socket path
			ev.Hook = "connect_unix"
			ev.Family = e.Family
			break
		}
		// connect/bind report the raw sockaddr sin_port, in network order.
		ev.RemotePort = ntohs(e.RemotePort)
		ev.Family = e.Family
		switch e.Family {
		case 2: // AF_INET
			ev.RemoteAddr = intToIPv4(e.RemoteAddrV4)
		case 10: // AF_INET6
			ev.RemoteAddr = net.IP(e.RemoteAddrV6[:]).String()
		}
	case EventTypeListen:
		ev.Hook = "listen"
		ev.Kind = EventKindNetwork
		// listen reports skc_num, which is already in host order.
		ev.RemotePort = e.RemotePort
		ev.Family = e.Family
	case EventTypePtrace:
		// Filename is the target's comm.
		ev.Hook = "ptrace"
		ev.Kind = EventKindProcess
		ev.TargetCgroupID = e.AuxID
	case EventTypeMount:
		// Filename is the filesystem type, Aux the mount source.
		ev.Hook = "mount"
		ev.Kind = EventKindFile
		ev.MountSource = nullTerminatedString(e.Aux[:])
	case EventTypeIntegrity:
		ev.Hook = "exec"
		ev.Kind = EventKindProcess
		ev.IntegrityViolation = true
	}

	return ev
}

// LSMHookName names an LSM event type for metrics labels.
func LSMHookName(eventType uint8) string {
	switch eventType {
	case EventTypeExec:
		return "exec"
	case EventTypeFile:
		return "file"
	case EventTypeNetwork:
		return "connect"
	case EventTypeBind:
		return "bind"
	case EventTypeListen:
		return "listen"
	case EventTypePtrace:
		return "ptrace"
	case EventTypeMount:
		return "mount"
	default:
		return "unknown"
	}
}

// LSMDecisionAction maps the kernel's decision byte to the
// warmor_lsm_decisions_total action label.
func LSMDecisionAction(decision uint8) string {
	if decision == ActionDeny {
		return "deny"
	}
	return "pass"
}

// LSMLoader manages the lifecycle of LSM-BPF programs.
type LSMLoader struct {
	execObjs    *lsm_execObjects
	fileObjs    *lsm_fileObjects
	connectObjs *lsm_connectObjects
	bindObjs    *lsm_bindObjects
	listenObjs  *lsm_listenObjects
	ptraceObjs  *lsm_ptraceObjects
	mountObjs   *lsm_mountObjects

	execLink    link.Link
	fileLink    link.Link
	connectLink link.Link
	bindLink    link.Link
	listenLink  link.Link
	ptraceLink  link.Link
	mountLink   link.Link

	lsmReader  *ringbuf.Reader
	policyMap  *PolicyMapManager
	enforceMap *ciliumebpf.Map
	filterMap  *ciliumebpf.Map

	// integrity is nil until EnableIntegrity loads lsm_integrity.
	integrity *integrityProgram

	// opts are the options the programs were loaded with; programs loaded
	// later (lsm_integrity) must match them to share the maps.
	opts LSMOptions
}

// IsLSMSupported checks whether the running kernel supports BPF LSM.
// It first checks /sys/kernel/security/lsm (securityfs), then falls back to
// parsing the kernel command line for the lsm= parameter (covers WSL2 where
// securityfs may not be auto-mounted).
func IsLSMSupported() bool {
	if data, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		for _, l := range strings.Split(strings.TrimSpace(string(data)), ",") {
			if strings.TrimSpace(l) == "bpf" {
				return true
			}
		}
		return false
	}
	// Fallback: parse /proc/cmdline for lsm= boot parameter
	if data, err := os.ReadFile("/proc/cmdline"); err == nil {
		for _, field := range strings.Fields(string(data)) {
			if strings.HasPrefix(field, "lsm=") {
				for _, l := range strings.Split(field[4:], ",") {
					if l == "bpf" {
						return true
					}
				}
			}
		}
	}
	return false
}

// kernelBTFAvailable reports whether the running kernel exposes its own BTF,
// which cilium/ebpf needs to relocate the CO-RE field accesses in our minimal
// vmlinux structs to the correct offsets for this kernel.
func kernelBTFAvailable() bool {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	return err == nil
}

// OnEventLoss selects what the LSM hooks do with an operation whose event
// could not be queued because the ring buffer was full. The policy map had no
// entry for it, so userspace will never evaluate it.
type OnEventLoss uint32

const (
	// OnLossLog allows the operation and counts the drop (default).
	OnLossLog OnEventLoss = 0
	// OnLossDeny refuses unknown execs and connects in enforce mode.
	OnLossDeny OnEventLoss = 1
)

// ParseOnEventLoss parses the --on-event-loss flag.
func ParseOnEventLoss(s string) (OnEventLoss, error) {
	switch s {
	case "", "log":
		return OnLossLog, nil
	case "deny":
		return OnLossDeny, nil
	}
	return OnLossLog, fmt.Errorf("invalid --on-event-loss %q (valid: log, deny)", s)
}

// LSMOptions configures LoadLSMWithOptions.
type LSMOptions struct {
	// RingBufferSize is the event ring size in bytes; 0 keeps the default
	// (LSM_RINGBUF_SIZE). It must be a power of two and a page multiple.
	RingBufferSize uint32
	OnEventLoss    OnEventLoss
}

// LoadLSM loads and attaches all LSM-BPF programs with default options.
// Returns nil without error if LSM-BPF is not supported.
func LoadLSM() (*LSMLoader, error) {
	return LoadLSMWithOptions(LSMOptions{})
}

// validRingSize reports whether n is a valid BPF ring buffer size: a power of
// two and a multiple of the page size.
func validRingSize(n uint32) bool {
	page := uint32(os.Getpagesize())
	return n >= page && n&(n-1) == 0 && n%page == 0
}

// LoadLSMWithOptions loads and attaches all LSM-BPF programs.
// Returns nil without error if LSM-BPF is not supported.
func LoadLSMWithOptions(opts LSMOptions) (*LSMLoader, error) {
	if opts.RingBufferSize != 0 && !validRingSize(opts.RingBufferSize) {
		return nil, fmt.Errorf("LSM ring buffer size %d must be a power of two and a multiple of the page size (%d)",
			opts.RingBufferSize, os.Getpagesize())
	}
	if !IsLSMSupported() {
		log.Println("LSM-BPF not available, using tracepoint-only mode")
		return nil, nil
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock for lsm: %w", err)
	}

	// CO-RE relocations require kernel BTF. Without it, loading the programs
	// fails deep inside the verifier with an opaque message; check up front so
	// the operator gets an actionable error (and --require-lsm fails cleanly).
	if !kernelBTFAvailable() {
		return nil, fmt.Errorf("kernel BTF not found at /sys/kernel/btf/vmlinux: " +
			"CO-RE requires a kernel built with CONFIG_DEBUG_INFO_BTF=y")
	}

	l := &LSMLoader{opts: opts}

	// All programs are CO-RE relocated against the same kernel BTF.
	// cilium/ebpf no longer caches vmlinux globally, so share one cache
	// across the loads instead of decoding vmlinux once per program.
	btfCache := btf.NewCache()

	// The exec objects own the shared maps; every other program reuses them.
	execSpec, err := loadLsm_exec()
	if err != nil {
		return nil, fmt.Errorf("load lsm_exec spec: %w", err)
	}
	if opts.RingBufferSize != 0 {
		execSpec.Maps["lsm_events"].MaxEntries = opts.RingBufferSize
	}
	l.execObjs = &lsm_execObjects{}
	if err := execSpec.LoadAndAssign(l.execObjs, &ciliumebpf.CollectionOptions{Cache: btfCache}); err != nil {
		return nil, fmt.Errorf("load lsm_exec objects: %w", err)
	}
	if err := l.execObjs.LsmCfg.Put(uint32(0), lsm_execLsmConfig{OnLoss: uint32(opts.OnEventLoss)}); err != nil {
		l.Close()
		return nil, fmt.Errorf("set lsm config: %w", err)
	}

	execLnk, err := link.AttachLSM(link.LSMOptions{
		Program: l.execObjs.LsmExecCheck,
	})
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach lsm/bprm_check_security: %w", err)
	}
	l.execLink = execLnk

	shared := &ciliumebpf.CollectionOptions{
		Cache:           btfCache,
		MapReplacements: l.sharedMaps(),
	}

	l.fileObjs = &lsm_fileObjects{}
	l.connectObjs = &lsm_connectObjects{}
	l.bindObjs = &lsm_bindObjects{}
	l.listenObjs = &lsm_listenObjects{}
	l.ptraceObjs = &lsm_ptraceObjects{}
	l.mountObjs = &lsm_mountObjects{}
	programs := []struct {
		name, hook string
		load       func(*ciliumebpf.CollectionOptions) error
		prog       func() *ciliumebpf.Program
		link       *link.Link
	}{
		{"lsm_file", "lsm/file_open",
			func(o *ciliumebpf.CollectionOptions) error { return loadResized(loadLsm_file, l.fileObjs, opts, o) },
			func() *ciliumebpf.Program { return l.fileObjs.LsmFileCheck }, &l.fileLink},
		{"lsm_connect", "lsm/socket_connect",
			func(o *ciliumebpf.CollectionOptions) error {
				return loadResized(loadLsm_connect, l.connectObjs, opts, o)
			},
			func() *ciliumebpf.Program { return l.connectObjs.LsmConnectCheck }, &l.connectLink},
		{"lsm_bind", "lsm/socket_bind",
			func(o *ciliumebpf.CollectionOptions) error { return loadResized(loadLsm_bind, l.bindObjs, opts, o) },
			func() *ciliumebpf.Program { return l.bindObjs.LsmBindCheck }, &l.bindLink},
		{"lsm_listen", "lsm/socket_listen",
			func(o *ciliumebpf.CollectionOptions) error { return loadResized(loadLsm_listen, l.listenObjs, opts, o) },
			func() *ciliumebpf.Program { return l.listenObjs.LsmListenCheck }, &l.listenLink},
		{"lsm_ptrace", "lsm/ptrace_access_check",
			func(o *ciliumebpf.CollectionOptions) error { return loadResized(loadLsm_ptrace, l.ptraceObjs, opts, o) },
			func() *ciliumebpf.Program { return l.ptraceObjs.LsmPtraceCheck }, &l.ptraceLink},
		{"lsm_mount", "lsm/sb_mount",
			func(o *ciliumebpf.CollectionOptions) error { return loadResized(loadLsm_mount, l.mountObjs, opts, o) },
			func() *ciliumebpf.Program { return l.mountObjs.LsmMountCheck }, &l.mountLink},
	}
	for _, p := range programs {
		if err := p.load(shared); err != nil {
			l.Close()
			return nil, fmt.Errorf("load %s objects: %w", p.name, err)
		}
		lnk, err := link.AttachLSM(link.LSMOptions{Program: p.prog()})
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("attach %s: %w", p.hook, err)
		}
		*p.link = lnk
	}

	// Open ring buffer reader on shared lsm_events
	rd, err := ringbuf.NewReader(l.execObjs.LsmEvents)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("open lsm ring buffer: %w", err)
	}
	l.lsmReader = rd

	// Initialize policy map manager
	l.policyMap = NewPolicyMapManager(l.execObjs.PolicyMap)
	l.enforceMap = l.execObjs.LsmEnforce
	l.filterMap = l.execObjs.LsmCgroupFilter

	log.Printf("LSM-BPF programs loaded: bprm_check_security, file_open, socket_connect, socket_bind, "+
		"socket_listen, ptrace_access_check, sb_mount (ring buffer %d KiB)", l.execObjs.LsmEvents.MaxEntries()/1024)
	return l, nil
}

// loadResized loads a program's objects from its spec with the ring buffer
// resized like the exec objects'. Each program declares lsm_events with the
// default size, and a replacement map must match the declared spec.
func loadResized(spec func() (*ciliumebpf.CollectionSpec, error), objs any, opts LSMOptions, o *ciliumebpf.CollectionOptions) error {
	cs, err := spec()
	if err != nil {
		return err
	}
	if m, ok := cs.Maps["lsm_events"]; ok && opts.RingBufferSize != 0 {
		m.MaxEntries = opts.RingBufferSize
	}
	return cs.LoadAndAssign(objs, o)
}

// sharedMaps returns the maps the exec objects own, which every other LSM
// program must reuse rather than create privately: a private lsm_drops or
// lsm_cfg would silently lose drop counts or ignore --on-event-loss.
func (l *LSMLoader) sharedMaps() map[string]*ciliumebpf.Map {
	return map[string]*ciliumebpf.Map{
		"policy_map":        l.execObjs.PolicyMap,
		"lsm_events":        l.execObjs.LsmEvents,
		"lsm_cgroup_filter": l.execObjs.LsmCgroupFilter,
		"lsm_enforce":       l.execObjs.LsmEnforce,
		"lsm_drops":         l.execObjs.LsmDrops,
		"lsm_cfg":           l.execObjs.LsmCfg,
		"unix_watch":        l.execObjs.UnixWatch,
	}
}

// EventDrops returns, per LSM hook name, how many events could not be queued
// because the ring buffer was full, summed across CPUs.
func (l *LSMLoader) EventDrops() (map[string]uint64, error) {
	out := make(map[string]uint64)
	for t := uint32(0); t < lsmEventTypes; t++ {
		var perCPU []uint64
		if err := l.execObjs.LsmDrops.Lookup(t, &perCPU); err != nil {
			return nil, fmt.Errorf("read lsm_drops[%d]: %w", t, err)
		}
		var n uint64
		for _, v := range perCPU {
			n += v
		}
		if n > 0 {
			out[LSMHookName(uint8(t))] += n
		}
	}
	return out, nil
}

// lsmEventTypes matches LSM_EVENT_TYPES in warmor_lsm.h.
const lsmEventTypes = 8

// lsmPollInterval bounds how long a queued event can wait for the reader.
// The kernel only wakes the reader once LSM_WAKEUP_BYTES are queued (or for a
// denial), so a lone event is picked up by this deadline instead.
const lsmPollInterval = 5 * time.Millisecond

// ReadLSMEvent reads the next event from the LSM ring buffer.
func (l *LSMLoader) ReadLSMEvent() (*Event, error) {
	var record ringbuf.Record
	for {
		l.lsmReader.SetDeadline(time.Now().Add(lsmPollInterval))
		err := l.lsmReader.ReadInto(&record)
		if err == nil {
			break
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, err
		}
		return nil, fmt.Errorf("read lsm event: %w", err)
	}

	reader := bytes.NewReader(record.RawSample)
	var raw LSMEvent
	if err := binary.Read(reader, binary.NativeEndian, &raw); err != nil {
		return nil, fmt.Errorf("parse lsm event: %w", err)
	}

	ev := raw.ToEvent()
	return &ev, nil
}

// SetUnixWatch replaces the set of unix socket paths whose connects
// lsm_connect reports. Paths must fit sun_path (at most 106 bytes plus NUL
// so the kernel can tell they weren't truncated).
func (l *LSMLoader) SetUnixWatch(paths []string) error {
	m := l.execObjs.UnixWatch
	var key uint32
	var stale []uint32
	iter := m.Iterate()
	for iter.Next(&key, new(uint8)) {
		stale = append(stale, key)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate unix_watch: %w", err)
	}
	for _, k := range stale {
		if err := m.Delete(k); err != nil && !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
			return fmt.Errorf("clear unix_watch: %w", err)
		}
	}
	one := uint8(1)
	for _, p := range paths {
		if p == "" || len(p) > 106 || strings.IndexByte(p, 0) >= 0 {
			return fmt.Errorf("unix watch path %q: must be 1-106 bytes without NUL", p)
		}
		if err := m.Put(HashPattern(p), one); err != nil {
			return fmt.Errorf("watch unix socket %s: %w", p, err)
		}
	}
	return nil
}

// PolicyMap returns the policy map manager for this LSM instance.
func (l *LSMLoader) PolicyMap() *PolicyMapManager {
	return l.policyMap
}

// SetEnforceMode enables or disables kernel-level blocking.
func (l *LSMLoader) SetEnforceMode(enabled bool) error {
	return SetEnforce(l.enforceMap, enabled)
}

// SetCgroupFilter updates the cgroup filter for LSM programs.
func (l *LSMLoader) SetCgroupFilter(ids []uint64) error {
	return SetLSMCgroupFilter(l.filterMap, ids)
}

// Close releases all LSM resources.
func (l *LSMLoader) Close() error {
	var errs []error

	if l.lsmReader != nil {
		if err := l.lsmReader.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// Detach integrity before the exec objects whose maps it shares.
	if l.integrity != nil {
		if err := l.integrity.close(); err != nil {
			errs = append(errs, err)
		}
		l.integrity = nil
	}

	for _, lnk := range []link.Link{l.execLink, l.fileLink, l.connectLink, l.bindLink, l.listenLink, l.ptraceLink, l.mountLink} {
		if lnk != nil {
			if err := lnk.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}

	// NOTE: these are concrete pointer types stored into an interface. A nil
	// *lsm_xxxObjects (a load step that never ran, or one that failed) becomes
	// a non-nil interface holding a nil pointer, so a plain `obj != nil` check
	// passes and Close() runs on a nil receiver — which segfaults in the
	// bpf2go-generated Close(). This happens on every partial load (e.g. a
	// program that fails to verify on some kernel), so guard the pointer value.
	for _, obj := range []interface{ Close() error }{l.execObjs, l.fileObjs, l.connectObjs, l.bindObjs, l.listenObjs, l.ptraceObjs, l.mountObjs} {
		if obj == nil || reflect.ValueOf(obj).IsNil() {
			continue
		}
		if err := obj.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("lsm close errors: %v", errs)
	}
	return nil
}
