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

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type warmor_event -type policy_key -type policy_value lsm_exec ../../bpf/lsm_exec.bpf.c -- -I../../bpf -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu
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
	}

	switch e.EventType {
	case EventTypeExec:
		ev.Kind = EventKindProcess
	case EventTypeFile:
		ev.Kind = EventKindFile
	case EventTypeNetwork, EventTypeBind:
		ev.Kind = EventKindNetwork
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
		ev.Kind = EventKindNetwork
		// listen reports skc_num, which is already in host order.
		ev.RemotePort = e.RemotePort
		ev.Family = e.Family
	case EventTypePtrace:
		ev.Kind = EventKindProcess
	case EventTypeMount:
		ev.Kind = EventKindFile
	}

	return ev
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

// LoadLSM loads and attaches all LSM-BPF programs.
// Returns nil without error if LSM-BPF is not supported.
func LoadLSM() (*LSMLoader, error) {
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

	l := &LSMLoader{}

	// All seven programs are CO-RE relocated against the same kernel BTF.
	// cilium/ebpf no longer caches vmlinux globally, so share one cache
	// across the loads instead of decoding vmlinux seven times.
	btfCache := btf.NewCache()

	// Load exec LSM
	l.execObjs = &lsm_execObjects{}
	if err := loadLsm_execObjects(l.execObjs, &ciliumebpf.CollectionOptions{Cache: btfCache}); err != nil {
		return nil, fmt.Errorf("load lsm_exec objects: %w", err)
	}

	execLnk, err := link.AttachLSM(link.LSMOptions{
		Program: l.execObjs.LsmExecCheck,
	})
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach lsm/bprm_check_security: %w", err)
	}
	l.execLink = execLnk

	// Load file LSM — reuse policy_map from exec via MapReplacements
	l.fileObjs = &lsm_fileObjects{}
	fileOpts := &ciliumebpf.CollectionOptions{
		Maps:  ciliumebpf.MapOptions{},
		Cache: btfCache,
	}
	fileOpts.MapReplacements = map[string]*ciliumebpf.Map{
		"policy_map":        l.execObjs.PolicyMap,
		"lsm_events":       l.execObjs.LsmEvents,
		"lsm_cgroup_filter": l.execObjs.LsmCgroupFilter,
		"lsm_enforce":      l.execObjs.LsmEnforce,
	}
	if err := loadLsm_fileObjects(l.fileObjs, fileOpts); err != nil {
		l.Close()
		return nil, fmt.Errorf("load lsm_file objects: %w", err)
	}

	fileLnk, err := link.AttachLSM(link.LSMOptions{
		Program: l.fileObjs.LsmFileCheck,
	})
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach lsm/file_open: %w", err)
	}
	l.fileLink = fileLnk

	// Load connect LSM — reuse maps from exec
	l.connectObjs = &lsm_connectObjects{}
	connectOpts := &ciliumebpf.CollectionOptions{
		Maps:  ciliumebpf.MapOptions{},
		Cache: btfCache,
	}
	connectOpts.MapReplacements = map[string]*ciliumebpf.Map{
		"policy_map":        l.execObjs.PolicyMap,
		"lsm_events":       l.execObjs.LsmEvents,
		"lsm_cgroup_filter": l.execObjs.LsmCgroupFilter,
		"lsm_enforce":      l.execObjs.LsmEnforce,
	}
	if err := loadLsm_connectObjects(l.connectObjs, connectOpts); err != nil {
		l.Close()
		return nil, fmt.Errorf("load lsm_connect objects: %w", err)
	}

	connectLnk, err := link.AttachLSM(link.LSMOptions{
		Program: l.connectObjs.LsmConnectCheck,
	})
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach lsm/socket_connect: %w", err)
	}
	l.connectLink = connectLnk

	// Load bind LSM — reuse maps from exec
	l.bindObjs = &lsm_bindObjects{}
	bindOpts := &ciliumebpf.CollectionOptions{
		Maps:  ciliumebpf.MapOptions{},
		Cache: btfCache,
	}
	bindOpts.MapReplacements = map[string]*ciliumebpf.Map{
		"policy_map":        l.execObjs.PolicyMap,
		"lsm_events":       l.execObjs.LsmEvents,
		"lsm_cgroup_filter": l.execObjs.LsmCgroupFilter,
		"lsm_enforce":      l.execObjs.LsmEnforce,
	}
	if err := loadLsm_bindObjects(l.bindObjs, bindOpts); err != nil {
		l.Close()
		return nil, fmt.Errorf("load lsm_bind objects: %w", err)
	}

	bindLnk, err := link.AttachLSM(link.LSMOptions{
		Program: l.bindObjs.LsmBindCheck,
	})
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach lsm/socket_bind: %w", err)
	}
	l.bindLink = bindLnk

	// Load listen LSM — reuse maps from exec
	l.listenObjs = &lsm_listenObjects{}
	listenOpts := &ciliumebpf.CollectionOptions{
		Maps:  ciliumebpf.MapOptions{},
		Cache: btfCache,
	}
	listenOpts.MapReplacements = map[string]*ciliumebpf.Map{
		"policy_map":        l.execObjs.PolicyMap,
		"lsm_events":       l.execObjs.LsmEvents,
		"lsm_cgroup_filter": l.execObjs.LsmCgroupFilter,
		"lsm_enforce":      l.execObjs.LsmEnforce,
	}
	if err := loadLsm_listenObjects(l.listenObjs, listenOpts); err != nil {
		l.Close()
		return nil, fmt.Errorf("load lsm_listen objects: %w", err)
	}

	listenLnk, err := link.AttachLSM(link.LSMOptions{
		Program: l.listenObjs.LsmListenCheck,
	})
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach lsm/socket_listen: %w", err)
	}
	l.listenLink = listenLnk

	// Load ptrace LSM — reuse maps from exec
	l.ptraceObjs = &lsm_ptraceObjects{}
	ptraceOpts := &ciliumebpf.CollectionOptions{
		Maps:  ciliumebpf.MapOptions{},
		Cache: btfCache,
	}
	ptraceOpts.MapReplacements = map[string]*ciliumebpf.Map{
		"policy_map":        l.execObjs.PolicyMap,
		"lsm_events":       l.execObjs.LsmEvents,
		"lsm_cgroup_filter": l.execObjs.LsmCgroupFilter,
		"lsm_enforce":      l.execObjs.LsmEnforce,
	}
	if err := loadLsm_ptraceObjects(l.ptraceObjs, ptraceOpts); err != nil {
		l.Close()
		return nil, fmt.Errorf("load lsm_ptrace objects: %w", err)
	}

	ptraceLnk, err := link.AttachLSM(link.LSMOptions{
		Program: l.ptraceObjs.LsmPtraceCheck,
	})
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach lsm/ptrace_access_check: %w", err)
	}
	l.ptraceLink = ptraceLnk

	// Load mount LSM — reuse maps from exec
	l.mountObjs = &lsm_mountObjects{}
	mountOpts := &ciliumebpf.CollectionOptions{
		Maps:  ciliumebpf.MapOptions{},
		Cache: btfCache,
	}
	mountOpts.MapReplacements = map[string]*ciliumebpf.Map{
		"policy_map":        l.execObjs.PolicyMap,
		"lsm_events":       l.execObjs.LsmEvents,
		"lsm_cgroup_filter": l.execObjs.LsmCgroupFilter,
		"lsm_enforce":      l.execObjs.LsmEnforce,
	}
	if err := loadLsm_mountObjects(l.mountObjs, mountOpts); err != nil {
		l.Close()
		return nil, fmt.Errorf("load lsm_mount objects: %w", err)
	}

	mountLnk, err := link.AttachLSM(link.LSMOptions{
		Program: l.mountObjs.LsmMountCheck,
	})
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach lsm/sb_mount: %w", err)
	}
	l.mountLink = mountLnk

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

	log.Println("LSM-BPF programs loaded: bprm_check_security, file_open, socket_connect, socket_bind, socket_listen, ptrace_access_check, sb_mount")
	return l, nil
}

// ReadLSMEvent reads the next event from the LSM ring buffer.
func (l *LSMLoader) ReadLSMEvent() (*Event, error) {
	record, err := l.lsmReader.Read()
	if err != nil {
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
