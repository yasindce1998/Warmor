//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"reflect"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type execve_event execve_monitor ../../bpf/execve_monitor.bpf.c -- -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type file_event openat_monitor ../../bpf/openat_monitor.bpf.c -- -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type network_event connect_monitor ../../bpf/connect_monitor.bpf.c -- -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu

type Loader struct {
	execveObjs  *execve_monitorObjects
	openatObjs  *openat_monitorObjects
	connectObjs *connect_monitorObjects

	execveLink  link.Link
	openatLink  link.Link
	connectLink link.Link

	processReader *ringbuf.Reader
	fileReader    *ringbuf.Reader
	networkReader *ringbuf.Reader
}

// InterruptEventReads wakes the single readers during platform shutdown.
func (l *Loader) InterruptEventReads() error {
	var errs []error
	for _, rd := range []*ringbuf.Reader{l.processReader, l.fileReader, l.networkReader} {
		if rd != nil {
			errs = append(errs, rd.Flush())
		}
	}
	return errors.Join(errs...)
}

func Load() (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	l := &Loader{}

	// Load execve monitor
	l.execveObjs = &execve_monitorObjects{}
	if err := loadExecve_monitorObjects(l.execveObjs, nil); err != nil {
		return nil, fmt.Errorf("load execve objects: %w", err)
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", l.execveObjs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach execve tracepoint: %w", err)
	}
	l.execveLink = tp

	rd, err := ringbuf.NewReader(l.execveObjs.Events)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("open execve ring buffer: %w", err)
	}
	l.processReader = rd

	// Load openat monitor
	l.openatObjs = &openat_monitorObjects{}
	if err := loadOpenat_monitorObjects(l.openatObjs, nil); err != nil {
		l.Close()
		return nil, fmt.Errorf("load openat objects: %w", err)
	}

	tp, err = link.Tracepoint("syscalls", "sys_enter_openat", l.openatObjs.TracepointSyscallsSysEnterOpenat, nil)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach openat tracepoint: %w", err)
	}
	l.openatLink = tp

	rd, err = ringbuf.NewReader(l.openatObjs.FileEvents)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("open file ring buffer: %w", err)
	}
	l.fileReader = rd

	// Load connect monitor
	l.connectObjs = &connect_monitorObjects{}
	if err := loadConnect_monitorObjects(l.connectObjs, nil); err != nil {
		l.Close()
		return nil, fmt.Errorf("load connect objects: %w", err)
	}

	tp, err = link.Tracepoint("syscalls", "sys_enter_connect", l.connectObjs.TracepointSyscallsSysEnterConnect, nil)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach connect tracepoint: %w", err)
	}
	l.connectLink = tp

	rd, err = ringbuf.NewReader(l.connectObjs.NetworkEvents)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("open network ring buffer: %w", err)
	}
	l.networkReader = rd

	log.Println("eBPF programs loaded: execve, openat, connect")
	return l, nil
}

func (l *Loader) ReadProcessEvent() (*Event, error) {
	return l.readEvent(l.processReader, EventKindProcess)
}

func (l *Loader) ReadFileEvent() (*Event, error) {
	return l.readEvent(l.fileReader, EventKindFile)
}

func (l *Loader) ReadNetworkEvent() (*Event, error) {
	return l.readEvent(l.networkReader, EventKindNetwork)
}

func (l *Loader) readEvent(rd *ringbuf.Reader, kind EventKind) (*Event, error) {
	record, err := rd.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, err
		}
		return nil, fmt.Errorf("read event: %w", err)
	}

	reader := bytes.NewReader(record.RawSample)

	switch kind {
	case EventKindProcess:
		raw, err := decodeExecveEvent(record.RawSample)
		if err != nil {
			return nil, fmt.Errorf("parse execve event: %w", err)
		}
		ev := raw.ToEvent()
		return &ev, nil

	case EventKindFile:
		var raw OpenatEvent
		if err := binary.Read(reader, binary.NativeEndian, &raw); err != nil {
			return nil, fmt.Errorf("parse openat event: %w", err)
		}
		ev := raw.ToEvent()
		return &ev, nil

	case EventKindNetwork:
		var raw ConnectEvent
		if err := binary.Read(reader, binary.NativeEndian, &raw); err != nil {
			return nil, fmt.Errorf("parse connect event: %w", err)
		}
		ev := raw.ToEvent()
		return &ev, nil
	}

	return nil, fmt.Errorf("unknown event kind: %d", kind)
}

// perCPUMap is the subset of *ebpf.Map used to read a drop counter. Keeping
// it narrow lets the summation be unit-tested without a kernel.
type perCPUMap interface {
	Lookup(key, value any) error
}

// sumTracepointDrops sums one PERCPU_ARRAY slot across all CPUs.
func sumTracepointDrops(m perCPUMap) (uint64, error) {
	var perCPU []uint64
	if err := m.Lookup(uint32(0), &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, n := range perCPU {
		total += n
	}
	return total, nil
}

// TracepointDrops returns, per tracepoint hook name, how many events could
// not be queued because the ring buffer was full, summed across CPUs. A hook
// with no drops is omitted. Objects that were never loaded are skipped so
// callers holding a zero-value Loader get an empty result rather than a panic.
func (l *Loader) TracepointDrops() (map[string]uint64, error) {
	type hookMap struct {
		name string
		m    *ebpf.Map
	}
	var maps []hookMap
	if l.execveObjs != nil {
		maps = append(maps, hookMap{"execve", l.execveObjs.TracepointDrops})
	}
	if l.openatObjs != nil {
		maps = append(maps, hookMap{"openat", l.openatObjs.TracepointDrops})
	}
	if l.connectObjs != nil {
		maps = append(maps, hookMap{"connect", l.connectObjs.TracepointDrops})
	}

	out := make(map[string]uint64)
	for _, hm := range maps {
		if hm.m == nil {
			continue
		}
		n, err := sumTracepointDrops(hm.m)
		if err != nil {
			return nil, fmt.Errorf("read tracepoint_drops[%s]: %w", hm.name, err)
		}
		if n > 0 {
			out[hm.name] = n
		}
	}
	return out, nil
}

// SetCgroupFilter populates the eBPF cgroup_filter maps across all monitors.
// A sentinel key=0 is inserted to mark the filter as active. Pass nil or empty
// to clear the filter (allow all cgroups).
func (l *Loader) SetCgroupFilter(ids []uint64) error {
	return l.setCgroupFilter(ids, len(ids) > 0)
}

// ReplaceCgroupFilter keeps filtering active even for an empty scope.
func (l *Loader) ReplaceCgroupFilter(ids []uint64) error {
	return l.setCgroupFilter(ids, true)
}

func (l *Loader) setCgroupFilter(ids []uint64, scoped bool) error {
	maps := []*ebpf.Map{
		l.execveObjs.CgroupFilter,
		l.openatObjs.CgroupFilter,
		l.connectObjs.CgroupFilter,
	}

	for _, m := range maps {
		if m == nil {
			return fmt.Errorf("cgroup filter map is not loaded")
		}
		if err := replaceCgroupFilter(kernelCgroupFilter{m}, ids, scoped); err != nil {
			return err
		}
	}

	return nil
}

// ClearCgroupFilter removes all entries from the cgroup filter maps, disabling filtering.
func (l *Loader) ClearCgroupFilter() error {
	return l.SetCgroupFilter(nil)
}

// StopReaders interrupts pending reads without detaching hooks or closing maps.
// The platform must do this before waiting for monitor goroutines to exit.
// ringbuf.Reader.Close is idempotent and safe alongside a blocked Read.
func (l *Loader) StopReaders() error {
	var errs []error
	for _, rd := range []*ringbuf.Reader{l.processReader, l.fileReader, l.networkReader} {
		if rd != nil {
			if err := rd.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (l *Loader) Close() error {
	var errs []error
	if err := l.StopReaders(); err != nil {
		errs = append(errs, err)
	}

	for _, lnk := range []link.Link{l.execveLink, l.openatLink, l.connectLink} {
		if lnk != nil {
			if err := lnk.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}

	// Guard the pointer value, not just the interface: a nil *xxxObjects (a
	// load step that never ran) is a non-nil interface holding a nil pointer,
	// and calling Close() on it panics. See LSMLoader.Close.
	for _, obj := range []interface{ Close() error }{l.execveObjs, l.openatObjs, l.connectObjs} {
		if obj != nil && !reflect.ValueOf(obj).IsNil() {
			if err := obj.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}
	return nil
}
