// Package etw consumes the Microsoft-Windows-Kernel-{Process,File,Network}
// ETW providers. It is the Windows fallback for every event type
// eBPF-for-Windows does not cover, and the only source of file events.
//
// ETW is asynchronous: events describe operations that already happened, so
// enforcement on this path is detect-then-terminate.
//
// Event payloads are decoded by property name through TDH, using the schema
// each provider registers, never by hand-coded offsets. This file holds the
// portable part of the decoding so it can be tested on any OS.
package etw

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

// Provider selects which kernel provider a session enables.
type Provider int

const (
	ProviderProcess Provider = iota
	ProviderFile
	ProviderNetwork
)

func (p Provider) String() string {
	switch p {
	case ProviderProcess:
		return "process"
	case ProviderFile:
		return "file"
	case ProviderNetwork:
		return "network"
	default:
		return fmt.Sprintf("provider(%d)", int(p))
	}
}

// Microsoft-Windows-Kernel-Process event IDs and keywords.
const (
	processEventStart = 1
	processEventStop  = 2

	processKeywordProcess = 0x10 // WINEVENT_KEYWORD_PROCESS
)

// Microsoft-Windows-Kernel-File event IDs and keywords.
const (
	fileEventCreate        = 12
	fileEventWrite         = 16
	fileEventDeletePath    = 26
	fileEventRenamePath    = 27
	fileEventCreateNewFile = 30

	fileKeywordCreate        = 0x80
	fileKeywordWrite         = 0x200
	fileKeywordDeletePath    = 0x400
	fileKeywordRenamePath    = 0x800
	fileKeywordCreateNewFile = 0x1000
)

// Microsoft-Windows-Kernel-Network event IDs and keywords.
const (
	netEventTCPConnect4 = 12
	netEventTCPAccept4  = 15
	netEventTCPConnect6 = 28
	netEventTCPAccept6  = 31
	netEventUDPSend4    = 42
	netEventUDPSend6    = 58

	netKeywordIPv4 = 0x10
	netKeywordIPv6 = 0x20
)

// Keywords returns the MatchAnyKeyword mask enabled for a provider.
func (p Provider) Keywords() uint64 {
	switch p {
	case ProviderProcess:
		return processKeywordProcess
	case ProviderFile:
		// Opens/creates, writes, deletes and renames. Reads are left out:
		// they are by far the noisiest operation and policies key on opens.
		return fileKeywordCreate | fileKeywordWrite | fileKeywordDeletePath |
			fileKeywordRenamePath | fileKeywordCreateNewFile
	case ProviderNetwork:
		return netKeywordIPv4 | netKeywordIPv6
	default:
		return 0
	}
}

// fileTimeEpochDelta is the number of 100ns ticks between 1601-01-01 and
// 1970-01-01 UTC.
const fileTimeEpochDelta = 116444736000000000

// filetimeToTime converts a FILETIME (100ns ticks since 1601 UTC), the
// format of EVENT_HEADER.TimeStamp when the session uses system time, to a
// time.Time. Non-positive values fall back to now.
func filetimeToTime(ft int64) time.Time {
	if ft <= 0 {
		return time.Now()
	}
	return time.Unix(0, (ft-fileTimeEpochDelta)*100).UTC()
}

// netRecord is a decoded Kernel-Network event.
type netRecord struct {
	EventID uint16
	PID     uint32
	Daddr   []byte // 4 or 16 bytes, network order
	Saddr   []byte
	Dport   []byte // 2 bytes, network order
	Sport   []byte
}

// netOperation maps a Kernel-Network event ID to (operation, protocol). ok is
// false for events that are not forwarded (send/recv data, disconnects...).
func netOperation(id uint16) (op, proto string, ok bool) {
	switch id {
	case netEventTCPConnect4, netEventTCPConnect6:
		return "connect", "tcp", true
	case netEventTCPAccept4, netEventTCPAccept6:
		return "accept", "tcp", true
	case netEventUDPSend4, netEventUDPSend6:
		return "sendto", "udp", true
	default:
		return "", "", false
	}
}

// toNetworkEvent converts a decoded record. For every forwarded event the
// "d" fields are the remote endpoint: the provider reports connects and
// sends from the sender's view, and accepts with daddr/dport as the peer.
func (r *netRecord) toNetworkEvent(ts time.Time) (*api.NetworkEvent, bool) {
	op, proto, ok := netOperation(r.EventID)
	if !ok {
		return nil, false
	}
	remote, ok := addrFromBytes(r.Daddr)
	if !ok {
		return nil, false
	}
	ev := &api.NetworkEvent{
		BaseEvent:  api.BaseEvent{Type: api.EventTypeNetwork, PID: r.PID, Timestamp: ts},
		Operation:  op,
		Protocol:   proto,
		RemoteAddr: remote.String(),
		RemotePort: portFromBytes(r.Dport),
		LocalPort:  portFromBytes(r.Sport),
	}
	if local, ok := addrFromBytes(r.Saddr); ok {
		ev.LocalAddr = local.String()
	}
	if remote.Is6() {
		ev.Protocol += "6"
	}
	return ev, true
}

// addrFromBytes parses a 4- or 16-byte network-order address. IPv4-mapped
// IPv6 addresses are unmapped so policies see the IPv4 form.
func addrFromBytes(b []byte) (netip.Addr, bool) {
	switch len(b) {
	case 4:
		return netip.AddrFrom4([4]byte(b)), true
	case 16:
		return netip.AddrFrom16([16]byte(b)).Unmap(), true
	default:
		return netip.Addr{}, false
	}
}

// portFromBytes reads a network-order port.
func portFromBytes(b []byte) uint16 {
	if len(b) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

// fileRecord is a decoded Kernel-File event.
type fileRecord struct {
	EventID       uint16
	FileObject    uint64
	CreateOptions uint32
	Path          string // NT path; empty for writes
}

// NT create dispositions (CreateOptions >> 24).
const (
	fileSupersede   = 0
	fileCreate      = 2
	fileOverwriteIf = 5
)

// fileOperation names a Kernel-File event the way policies match it.
func fileOperation(r *fileRecord) (string, bool) {
	switch r.EventID {
	case fileEventCreate:
		switch r.CreateOptions >> 24 {
		case fileSupersede, fileCreate, fileOverwriteIf:
			return "create", true
		}
		return "open", true
	case fileEventCreateNewFile:
		return "create", true
	case fileEventWrite:
		return "write", true
	case fileEventDeletePath:
		return "delete", true
	case fileEventRenamePath:
		return "rename", true
	default:
		return "", false
	}
}

// maxFileObjects bounds the FileObject → path table. Close events are not
// subscribed (they come with the very noisy FILEIO keyword), so entries are
// evicted by age instead.
const maxFileObjects = 65536

// fileObjectTable resolves write events, which only carry a FileObject, to
// the path seen when that FileObject was created. It also reports only the
// first write per opened file: every WriteFile call is an event, and policy
// decisions do not change between writes to the same handle.
type fileObjectTable struct {
	mu      sync.Mutex
	entries map[uint64]*fileObjectEntry
	order   []uint64 // insertion order for eviction
}

type fileObjectEntry struct {
	path    string
	written bool
}

func newFileObjectTable() *fileObjectTable {
	return &fileObjectTable{entries: make(map[uint64]*fileObjectEntry)}
}

// opened records the path for a FileObject (FileObjects are reused after
// close, so this always replaces).
func (t *fileObjectTable) opened(obj uint64, path string) {
	if obj == 0 || path == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.entries[obj]; !ok {
		t.order = append(t.order, obj)
		if len(t.order) > maxFileObjects {
			// Drop the oldest quarter at once to amortise the copy.
			drop := maxFileObjects / 4
			for _, old := range t.order[:drop] {
				delete(t.entries, old)
			}
			t.order = append([]uint64(nil), t.order[drop:]...)
		}
	}
	t.entries[obj] = &fileObjectEntry{path: path}
}

// firstWrite returns the path of obj and whether this is the first write
// since it was opened. Unknown FileObjects return ok=false.
func (t *fileObjectTable) firstWrite(obj uint64) (path string, first, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[obj]
	if !ok {
		return "", false, false
	}
	first = !e.written
	e.written = true
	return e.path, first, true
}

// udpDedupWindow suppresses repeated UDP sends to the same peer: the
// provider emits one event per datagram.
const udpDedupWindow = 10 * time.Second

const maxUDPFlows = 16384

type udpFlowKey struct {
	pid  uint32
	addr string
	port uint16
}

type udpDeduper struct {
	mu   sync.Mutex
	seen map[udpFlowKey]time.Time
}

func newUDPDeduper() *udpDeduper {
	return &udpDeduper{seen: make(map[udpFlowKey]time.Time)}
}

// first reports whether this flow has not been seen within the window.
func (d *udpDeduper) first(pid uint32, addr string, port uint16, now time.Time) bool {
	k := udpFlowKey{pid, addr, port}
	d.mu.Lock()
	defer d.mu.Unlock()
	if last, ok := d.seen[k]; ok && now.Sub(last) < udpDedupWindow {
		return false
	}
	if len(d.seen) >= maxUDPFlows {
		for fk, t := range d.seen {
			if now.Sub(t) >= udpDedupWindow {
				delete(d.seen, fk)
			}
		}
		if len(d.seen) >= maxUDPFlows {
			d.seen = make(map[udpFlowKey]time.Time)
		}
	}
	d.seen[k] = now
	return true
}
