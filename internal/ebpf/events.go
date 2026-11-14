package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

var bootTimeOffset time.Duration

func init() {
	bootTimeOffset = computeBootTimeOffset()
}

func bootTimeToWallClock(bootNs uint64) time.Time {
	return time.Unix(0, int64(bootNs)).Add(bootTimeOffset)
}

// EventKind distinguishes which ring buffer produced an event.
type EventKind int

const (
	EventKindProcess EventKind = iota
	EventKindFile
	EventKindNetwork
)

// ExecveArgsMax and ExecveArgLen mirror ARGS_MAX/ARG_LEN in
// execve_monitor.bpf.c.
const (
	ExecveArgsMax = 16
	ExecveArgLen  = 64
)

type ExecveEvent struct {
	PID        uint32
	UID        uint32
	GID        uint32
	Comm       [16]byte
	Filename   [256]byte
	_          [4]byte
	Timestamp  uint64
	CgroupID   uint64
	PPID       uint32
	ParentComm [16]byte
	Args       [ExecveArgsMax][ExecveArgLen]byte
}

func (e *ExecveEvent) ToEvent() Event {
	ev := Event{
		Kind:              EventKindProcess,
		PID:               e.PID,
		UID:               e.UID,
		GID:               e.GID,
		Comm:              nullTerminatedString(e.Comm[:]),
		Filename:          nullTerminatedString(e.Filename[:]),
		Timestamp:         bootTimeToWallClock(e.Timestamp),
		KernelTimestampNS: e.Timestamp,
		CgroupID:          e.CgroupID,
		PPID:              e.PPID,
		ParentComm:        nullTerminatedString(e.ParentComm[:]),
	}
	ev.Args = execveArgs(e.Args)
	return ev
}

// execveArgs decodes the fixed argv block: each slot is a NUL-padded
// string, and the first all-zero slot ends the list.
func execveArgs(raw [ExecveArgsMax][ExecveArgLen]byte) []string {
	args := make([]string, 0, ExecveArgsMax)
	for _, a := range raw {
		if a[0] == 0 {
			break
		}
		args = append(args, nullTerminatedString(a[:]))
	}
	return args
}

type OpenatEvent struct {
	PID       uint32
	UID       uint32
	GID       uint32
	Comm      [16]byte
	Path      [256]byte
	Flags     uint32
	Mode      uint32
	_         [4]byte
	Timestamp uint64
	CgroupID  uint64
}

func (e *OpenatEvent) ToEvent() Event {
	return Event{
		Kind:              EventKindFile,
		PID:               e.PID,
		UID:               e.UID,
		GID:               e.GID,
		Comm:              nullTerminatedString(e.Comm[:]),
		Filename:          nullTerminatedString(e.Path[:]),
		Flags:             e.Flags,
		Mode:              e.Mode,
		Timestamp:         bootTimeToWallClock(e.Timestamp),
		KernelTimestampNS: e.Timestamp,
		CgroupID:          e.CgroupID,
	}
}

type ConnectEvent struct {
	PID          uint32
	UID          uint32
	GID          uint32
	Comm         [16]byte
	Family       uint16
	RemotePort   uint16
	RemoteAddrV4 uint32
	RemoteAddrV6 [16]byte
	_            [4]byte
	Timestamp    uint64
	CgroupID     uint64
}

func (e *ConnectEvent) ToEvent() Event {
	addr := e.remoteAddrString()
	return Event{
		Kind:              EventKindNetwork,
		PID:               e.PID,
		UID:               e.UID,
		GID:               e.GID,
		Comm:              nullTerminatedString(e.Comm[:]),
		RemoteAddr:        addr,
		RemotePort:        ntohs(e.RemotePort),
		Family:            e.Family,
		Timestamp:         bootTimeToWallClock(e.Timestamp),
		KernelTimestampNS: e.Timestamp,
		CgroupID:          e.CgroupID,
	}
}

func (e *ConnectEvent) remoteAddrString() string {
	if e.Family == 2 { // AF_INET
		// RemoteAddrV4 is the raw network-order sin_addr, decoded as a native
		// uint32; write it back natively to recover the original byte order.
		return intToIPv4(e.RemoteAddrV4)
	}
	if e.Family == 10 { // AF_INET6
		return net.IP(e.RemoteAddrV6[:]).String()
	}
	return fmt.Sprintf("unknown-family-%d", e.Family)
}

// Event is the user-friendly event structure produced by the eBPF layer.
type Event struct {
	Kind       EventKind
	PID        uint32
	UID        uint32
	GID        uint32
	Comm       string
	Filename   string
	Flags      uint32
	Mode       uint32
	RemoteAddr string
	RemotePort uint16
	Family     uint16
	Timestamp  time.Time
	// KernelTimestampNS preserves bpf_ktime_get_ns in the initial clock domain.
	KernelTimestampNS uint64
	CgroupID          uint64
	// PolicyGeneration is the kernel policy snapshot ID, or 0 for legacy and
	// observation-only hooks. Preserve it when dispatching versioned work.
	PolicyGeneration uint64

	// Process events (exec tracepoint): the parent's PID and comm and the
	// executed command's argv (bounded; see ExecveArgsMax). Zero values
	// mean the sensor could not capture them.
	PPID       uint32
	ParentComm string
	Args       []string

	// LSM ring buffer events only: the raw hook event type
	// (EventTypeExec, ...) and the kernel's decision (1 = policy_map deny
	// hit, 0 = sent up for userspace evaluation).
	LSMHook     uint8
	LSMDecision uint8
	// KernelDenied is set for LSM events the kernel already refused (a
	// policy-map deny or an integrity failure in enforce mode); userspace
	// must record them, not evaluate and act on them again.
	KernelDenied bool
	// IntegrityViolation marks an exec whose SHA-256 was not allowlisted.
	IntegrityViolation bool

	// Hook names the LSM hook for LSM events: exec, file, connect,
	// connect_unix, bind, listen, ptrace, mount. Empty for tracepoint events.
	Hook string
	// MountSource is the mount source (dev_name) for mount events.
	MountSource string
	// TargetCgroupID is the ptrace target's cgroup id for ptrace events.
	TargetCgroupID uint64
}

func nullTerminatedString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// intToIPv4 converts a raw sin_addr (network-order bytes loaded as a native
// uint32 by the BPF program) to a dotted-decimal IPv4 string.
func intToIPv4(addr uint32) string {
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, addr)
	return ip.String()
}

func ntohs(v uint16) uint16 {
	return (v>>8)&0xff | (v&0xff)<<8
}
