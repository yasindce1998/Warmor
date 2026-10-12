// Package efw loads Warmor's eBPF-for-Windows programs, reads their events
// and keeps their policy maps in sync with WASM decisions.
//
// The programs (bpf-windows/) are built as native, signed .sys images and
// loaded with cilium/ebpf. This file holds the portable encoding of records,
// keys and values; the layouts mirror bpf-windows/warmor_efw.h.
package efw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf16"
)

// Record kinds.
const (
	recProcessCreate = 1
	recProcessExit   = 2
	recNetwork       = 3
)

// Verdict is what the kernel did with an operation.
type Verdict uint32

const (
	VerdictAllowed Verdict = 0
	VerdictBlocked Verdict = 1
	VerdictAudit   Verdict = 2
)

// Network directions.
const (
	DirConnect = 0
	DirAccept  = 1
)

// Windows address families.
const (
	afInet  = 2
	afInet6 = 23
)

// IP protocols.
const (
	protoTCP = 6
	protoUDP = 17
)

const (
	imagePathChars = 512
	cmdlineBytes   = 2048

	recHdrSize      = 16
	procRecSize     = 3120
	procExitRecSize = 24
	netRecSize      = 64
	netKeySize      = 32
	policyValueSize = 4
	procInfoSize    = 8
)

// Offsets inside struct warmor_proc_rec.
const (
	procOffPPID      = 16
	procOffCreation  = 24
	procOffImageHash = 32
	procOffExitCode  = 40
	procOffImageLen  = 44
	procOffCmdLen    = 46
	procOffImage     = 48
	procOffCmd       = procOffImage + imagePathChars*2
)

// Offsets inside struct warmor_net_rec.
const (
	netOffImageHash  = 16
	netOffFamily     = 24
	netOffDirection  = 25
	netOffProtocol   = 26
	netOffRemotePort = 28
	netOffLocalPort  = 30
	netOffRemoteAddr = 32
	netOffLocalAddr  = 48
)

// ProcessRecord is a decoded process create or exit record.
type ProcessRecord struct {
	Exit         bool
	Verdict      Verdict
	PID          uint32
	PPID         uint32
	CreationTime int64 // FILETIME
	ImageHash    uint64
	ExitCode     uint32
	NTImage      string
	CmdLine      string
}

// NetworkRecord is a decoded connect/accept record.
type NetworkRecord struct {
	Verdict    Verdict
	PID        uint32
	ImageHash  uint64
	Direction  uint8
	Protocol   uint8
	Remote     netip.AddrPort
	Local      netip.AddrPort
	IPv6Family bool
}

var errShortRecord = errors.New("efw: short record")

// parseRecord decodes one ring buffer record into a *ProcessRecord or a
// *NetworkRecord.
func parseRecord(b []byte) (any, error) {
	if len(b) < recHdrSize {
		return nil, errShortRecord
	}
	kind := binary.LittleEndian.Uint32(b[0:4])
	verdict := Verdict(binary.LittleEndian.Uint32(b[4:8]))
	pid := uint32(binary.LittleEndian.Uint64(b[8:16]))

	switch kind {
	case recProcessCreate:
		if len(b) < procRecSize {
			return nil, errShortRecord
		}
		imageLen := int(binary.LittleEndian.Uint16(b[procOffImageLen:]))
		cmdLen := int(binary.LittleEndian.Uint16(b[procOffCmdLen:]))
		return &ProcessRecord{
			Verdict:      verdict,
			PID:          pid,
			PPID:         uint32(binary.LittleEndian.Uint64(b[procOffPPID:])),
			CreationTime: int64(binary.LittleEndian.Uint64(b[procOffCreation:])),
			ImageHash:    binary.LittleEndian.Uint64(b[procOffImageHash:]),
			ExitCode:     binary.LittleEndian.Uint32(b[procOffExitCode:]),
			NTImage:      utf16le(b[procOffImage:procOffImage+imagePathChars*2], imageLen),
			CmdLine:      utf16le(b[procOffCmd:procOffCmd+cmdlineBytes], cmdLen),
		}, nil

	case recProcessExit:
		if len(b) < procExitRecSize {
			return nil, errShortRecord
		}
		return &ProcessRecord{
			Exit:     true,
			PID:      pid,
			ExitCode: binary.LittleEndian.Uint32(b[16:20]),
		}, nil

	case recNetwork:
		if len(b) < netRecSize {
			return nil, errShortRecord
		}
		rec := &NetworkRecord{
			Verdict:   verdict,
			PID:       pid,
			ImageHash: binary.LittleEndian.Uint64(b[netOffImageHash:]),
			Direction: b[netOffDirection],
			Protocol:  b[netOffProtocol],
		}
		remotePort := binary.BigEndian.Uint16(b[netOffRemotePort:])
		localPort := binary.BigEndian.Uint16(b[netOffLocalPort:])
		switch b[netOffFamily] {
		case afInet:
			rec.Remote = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[netOffRemoteAddr:netOffRemoteAddr+4])), remotePort)
			rec.Local = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[netOffLocalAddr:netOffLocalAddr+4])), localPort)
		case afInet6:
			rec.IPv6Family = true
			rec.Remote = netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[netOffRemoteAddr:netOffRemoteAddr+16])).Unmap(), remotePort)
			rec.Local = netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[netOffLocalAddr:netOffLocalAddr+16])).Unmap(), localPort)
		default:
			return nil, fmt.Errorf("efw: unknown address family %d", b[netOffFamily])
		}
		return rec, nil

	default:
		return nil, fmt.Errorf("efw: unknown record kind %d", kind)
	}
}

// utf16le decodes n bytes of UTF-16LE (clamped to the buffer), stopping at a
// NUL.
func utf16le(b []byte, n int) string {
	if n > len(b) {
		n = len(b)
	}
	units := make([]uint16, 0, n/2)
	for i := 0; i+1 < n; i += 2 {
		u := binary.LittleEndian.Uint16(b[i:])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return string(utf16.Decode(units))
}

// Operation and protocol names, matching the ETW backend and Linux.
func (r *NetworkRecord) Operation() string {
	if r.Direction == DirAccept {
		return "accept"
	}
	if r.Protocol == protoUDP {
		return "sendto"
	}
	return "connect"
}

func (r *NetworkRecord) ProtocolName() string {
	var name string
	switch r.Protocol {
	case protoTCP:
		name = "tcp"
	case protoUDP:
		name = "udp"
	default:
		return fmt.Sprintf("proto(%d)", r.Protocol)
	}
	if r.Remote.Addr().Is6() {
		name += "6"
	}
	return name
}

// netKey encodes a net_policy key for the given endpoint. op and proto are
// the names carried by enforcer events.
func netKey(imageHash uint64, op, proto string, remote netip.AddrPort) ([]byte, error) {
	if imageHash == 0 {
		return nil, errors.New("efw: unknown image")
	}
	k := make([]byte, netKeySize)
	binary.LittleEndian.PutUint64(k[0:8], imageHash)

	switch op {
	case "connect", "sendto":
		k[9] = DirConnect
	case "accept":
		k[9] = DirAccept
	default:
		return nil, fmt.Errorf("efw: operation %q has no kernel hook", op)
	}
	switch strings.TrimSuffix(proto, "6") {
	case "tcp":
		k[10] = protoTCP
	case "udp":
		k[10] = protoUDP
	default:
		return nil, fmt.Errorf("efw: protocol %q has no kernel hook", proto)
	}

	binary.BigEndian.PutUint16(k[12:14], remote.Port())
	// The family is the socket's, which for an IPv4-mapped peer seen by a
	// dual-stack socket is still IPv6. Events unmap the address, so the
	// family cannot be recovered from it: encode IPv4 peers as AF_INET and
	// let a dual-stack connection miss the fast path (userspace still
	// enforces it).
	addr := remote.Addr()
	switch {
	case addr.Is4():
		k[8] = afInet
		a := addr.As4()
		copy(k[16:20], a[:])
	case addr.Is6():
		k[8] = afInet6
		a := addr.As16()
		copy(k[16:32], a[:])
	default:
		return nil, errors.New("efw: invalid address")
	}
	return k, nil
}

// policyValue encodes a warmor_policy_value.
func policyValue(deny, audit bool) []byte {
	v := make([]byte, policyValueSize)
	if deny {
		v[0] = 1
	}
	if audit {
		v[1] = 1
	}
	return v
}

func u64Bytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

func u32Bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}
