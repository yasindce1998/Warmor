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
		var raw ExecveEvent
		if err := binary.Read(reader, binary.NativeEndian, &raw); err != nil {
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

// SetCgroupFilter populates the eBPF cgroup_filter maps across all monitors.
// A sentinel key=0 is inserted to mark the filter as active. Pass nil or empty
// to clear the filter (allow all cgroups).
func (l *Loader) SetCgroupFilter(ids []uint64) error {
	maps := []*ebpf.Map{
		l.execveObjs.CgroupFilter,
		l.openatObjs.CgroupFilter,
		l.connectObjs.CgroupFilter,
	}

	for _, m := range maps {
		if m == nil {
			continue
		}
		// Clear existing entries by iterating and deleting
		var key uint64
		iter := m.Iterate()
		for iter.Next(&key, new(uint8)) {
			_ = m.Delete(key)
		}

		if len(ids) == 0 {
			continue
		}

		// Insert sentinel key=0 to activate the filter
		var sentinel uint64
		var val uint8 = 1
		if err := m.Put(sentinel, val); err != nil {
			return fmt.Errorf("set cgroup filter sentinel: %w", err)
		}

		// Insert each allowed cgroup ID
		for _, id := range ids {
			if err := m.Put(id, val); err != nil {
				return fmt.Errorf("set cgroup filter id %d: %w", id, err)
			}
		}
	}

	return nil
}

// ClearCgroupFilter removes all entries from the cgroup filter maps, disabling filtering.
func (l *Loader) ClearCgroupFilter() error {
	return l.SetCgroupFilter(nil)
}

func (l *Loader) Close() error {
	var errs []error

	for _, rd := range []*ringbuf.Reader{l.processReader, l.fileReader, l.networkReader} {
		if rd != nil {
			if err := rd.Close(); err != nil {
				errs = append(errs, err)
			}
		}
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
