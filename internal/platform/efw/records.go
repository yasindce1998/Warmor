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

// Network directions. bind/listen use the local endpoint as their key.
const (
	DirConnect = 0
	DirAccept  = 1
	DirBind    = 2
	DirListen  = 3
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
	procRecSize     = 3384
	procExitRecSize = 24
	netRecSize      = 96
	netKeySize      = 32
	policyValueSize = 4
	procInfoSize    = 16
)

// Offsets inside struct warmor_proc_rec.
const (
	procOffPPID       = 16
	procOffCreation   = 24
	procOffImageHash  = 32
	procOffExitCode   = 40
	procOffImageLen   = 44
	procOffCmdLen     = 46
	procOffImage      = 48
	procOffCmd        = procOffImage + imagePathChars*2
	accountChars      = 64
	procOffAccountLen = procOffCmd + cmdlineBytes       // 3120
	procOffDomainLen  = procOffAccountLen + 2           // 3122
	procOffAccount    = procOffAccountLen + 8           // 3128
	procOffDomain     = procOffAccount + accountChars*2 // 3256
)

// Offsets inside struct warmor_net_rec.
const (
	netOffImageHash  = 16
	netOffCreation   = 24 // FILETIME of the process at hook time, 0 = unknown
	netOffFamily     = 32
	netOffDirection  = 33
	netOffProtocol   = 34
	netOffRemotePort = 36
	netOffLocalPort  = 38
	netOffRemoteAddr = 40
	netOffLocalAddr  = 56
	netOffIsAdmin    = 72
	netOffLogonID    = 80
	netOffCookie     = 88
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
	// Account and Domain come from the process token via ntosebpfext. Empty
	// means the helper failed or the information was unavailable.
	Account string
	Domain  string
}

// NetworkRecord is a decoded connect/accept/bind/listen record.
type NetworkRecord struct {
	Verdict Verdict
	PID     uint32
	// CreationTime is the FILETIME captured from proc_info when the hook
	// ran. It identifies the process that made the call even if the PID is
	// recycled before userspace reads the record; 0 means unknown.
	CreationTime uint64
	ImageHash    uint64
	Direction    uint8
	Protocol     uint8
	Remote       netip.AddrPort
	Local        netip.AddrPort
	IPv6Family   bool
	// Requesting-user identity from netebpfext. IsAdmin is -1 when the
	// runtime could not determine it; LogonID/Cookie are 0 when unknown.
	IsAdmin      int32
	LogonID      uint64
	SocketCookie uint64
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
		accountLen := int(binary.LittleEndian.Uint16(b[procOffAccountLen:]))
		domainLen := int(binary.LittleEndian.Uint16(b[procOffDomainLen:]))
		return &ProcessRecord{
			Verdict:      verdict,
			PID:          pid,
			PPID:         uint32(binary.LittleEndian.Uint64(b[procOffPPID:])),
			CreationTime: int64(binary.LittleEndian.Uint64(b[procOffCreation:])),
			ImageHash:    binary.LittleEndian.Uint64(b[procOffImageHash:]),
			ExitCode:     binary.LittleEndian.Uint32(b[procOffExitCode:]),
			NTImage:      utf16le(b[procOffImage:procOffImage+imagePathChars*2], imageLen),
			CmdLine:      utf16le(b[procOffCmd:procOffCmd+cmdlineBytes], cmdLen),
			Account:      utf16le(b[procOffAccount:procOffAccount+accountChars*2], accountLen),
			Domain:       utf16le(b[procOffDomain:procOffDomain+accountChars*2], domainLen),
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
			Verdict:      verdict,
			PID:          pid,
			CreationTime: binary.LittleEndian.Uint64(b[netOffCreation:]),
			ImageHash:    binary.LittleEndian.Uint64(b[netOffImageHash:]),
			Direction:    b[netOffDirection],
			Protocol:     b[netOffProtocol],
			IsAdmin:      int32(binary.LittleEndian.Uint32(b[netOffIsAdmin:])),
			LogonID:      binary.LittleEndian.Uint64(b[netOffLogonID:]),
			SocketCookie: binary.LittleEndian.Uint64(b[netOffCookie:]),
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

// Operation and protocol names, matching the ETW backend and Linux. bind and
// listen intentionally keep the "connect" operation and carry their identity
// in Hook, exactly as the Linux LSM sensor does, so policies are portable.
func (r *NetworkRecord) Operation() string {
	if r.Direction == DirAccept {
		return "accept"
	}
	if r.Direction == DirBind || r.Direction == DirListen {
		return "connect"
	}
	if r.Protocol == protoUDP {
		return "sendto"
	}
	return "connect"
}

// Hook returns the Linux-compatible hook name for bind/listen records. Other
// directions leave it empty, which the enforcer treats as a plain connect.
func (r *NetworkRecord) Hook() string {
	switch r.Direction {
	case DirBind:
		return "bind"
	case DirListen:
		return "listen"
	}
	return ""
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
	case "bind":
		k[9] = DirBind
	case "listen":
		k[9] = DirListen
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
