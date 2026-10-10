//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"
)

// rawLSMEvent builds a struct warmor_event exactly as laid out by the C
// compiler in bpf/warmor_lsm.h (little-endian, natural alignment).
func rawLSMEvent(eventType, decision uint8, filename string, portLE uint16, v4 [4]byte, v6 [16]byte, family uint16) []byte {
	buf := make([]byte, 336)
	binary.LittleEndian.PutUint32(buf[0:], 1234)
	binary.LittleEndian.PutUint32(buf[4:], 1000)
	binary.LittleEndian.PutUint32(buf[8:], 1000)
	putCString(buf, 12, 16, "proc")
	putCString(buf, 28, 256, filename)
	// 4 bytes of padding at 284..288
	binary.LittleEndian.PutUint64(buf[288:], 42)
	binary.LittleEndian.PutUint64(buf[296:], 777)
	buf[304] = eventType
	buf[305] = decision
	binary.LittleEndian.PutUint16(buf[306:], portLE)
	copy(buf[308:312], v4[:])
	copy(buf[312:328], v6[:])
	binary.LittleEndian.PutUint16(buf[328:], family)
	// 6 bytes of padding at 330..336
	return buf
}

func TestLSMEvent_Size(t *testing.T) {
	if got := binary.Size(LSMEvent{}); got != 336 {
		t.Errorf("binary.Size(LSMEvent) = %d, want 336 (sizeof(struct warmor_event))", got)
	}
}

func TestLSMEvent_DecodeFieldOffsets(t *testing.T) {
	var v6 [16]byte
	v6[0], v6[15] = 0xfe, 0x01
	raw := rawLSMEvent(EventTypeBind, 1, "/bin/sh", 0xabcd, [4]byte{192, 168, 1, 10}, v6, 2)

	var ev LSMEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		t.Fatalf("binary.Read failed: %v", err)
	}
	if ev.PID != 1234 || ev.UID != 1000 || ev.GID != 1000 {
		t.Errorf("PID/UID/GID = %d/%d/%d", ev.PID, ev.UID, ev.GID)
	}
	if ev.Timestamp != 42 || ev.CgroupID != 777 {
		t.Errorf("Timestamp=%d CgroupID=%d, want 42/777", ev.Timestamp, ev.CgroupID)
	}
	if ev.EventType != EventTypeBind || ev.Decision != 1 {
		t.Errorf("EventType=%d Decision=%d", ev.EventType, ev.Decision)
	}
	if ev.RemotePort != 0xabcd {
		t.Errorf("RemotePort = 0x%x, want 0xabcd", ev.RemotePort)
	}
	if ev.RemoteAddrV6 != v6 {
		t.Errorf("RemoteAddrV6 = %v, want %v", ev.RemoteAddrV6, v6)
	}
	if ev.Family != 2 {
		t.Errorf("Family = %d, want 2", ev.Family)
	}
	got := ev.ToEvent()
	if got.RemoteAddr != "192.168.1.10" {
		t.Errorf("RemoteAddr = %q, want 192.168.1.10 (network-order bytes decoded via intToIPv4)", got.RemoteAddr)
	}
	if got.Filename != "/bin/sh" || got.Comm != "proc" {
		t.Errorf("Filename=%q Comm=%q", got.Filename, got.Comm)
	}
}

func TestLSMEvent_DecodeShortInput(t *testing.T) {
	var ev LSMEvent
	if err := binary.Read(bytes.NewReader(make([]byte, 335)), binary.LittleEndian, &ev); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("err = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestLSMEvent_ToEvent_Kinds(t *testing.T) {
	tests := []struct {
		eventType uint8
		want      EventKind
	}{
		{EventTypeExec, EventKindProcess},
		{EventTypeFile, EventKindFile},
		{EventTypeNetwork, EventKindNetwork},
		{EventTypeBind, EventKindNetwork},
		{EventTypeListen, EventKindNetwork},
		{EventTypePtrace, EventKindProcess},
		{EventTypeMount, EventKindFile},
	}

	for _, tc := range tests {
		e := LSMEvent{EventType: tc.eventType, PID: 5, CgroupID: 6, Timestamp: 7}
		copy(e.Comm[:], "comm")
		copy(e.Filename[:], "/some/file")

		got := e.ToEvent()
		if got.Kind != tc.want {
			t.Errorf("event type %d: Kind = %d, want %d", tc.eventType, got.Kind, tc.want)
		}
		if got.PID != 5 || got.CgroupID != 6 || got.Comm != "comm" || got.Filename != "/some/file" {
			t.Errorf("event type %d: common fields not copied: %+v", tc.eventType, got)
		}
		if !got.Timestamp.Equal(bootTimeToWallClock(7)) {
			t.Errorf("event type %d: Timestamp mismatch", tc.eventType)
		}
	}
}

func TestLSMEvent_ToEvent_UnknownType(t *testing.T) {
	e := LSMEvent{EventType: 99, PID: 1}
	got := e.ToEvent()
	if got.Kind != EventKindProcess { // zero value
		t.Errorf("Kind = %d, want zero value", got.Kind)
	}
	if got.RemoteAddr != "" || got.Family != 0 {
		t.Errorf("unexpected network fields for unknown type: %+v", got)
	}
}

func TestLSMEvent_ToEvent_NetworkIPv4(t *testing.T) {
	for _, et := range []uint8{EventTypeNetwork, EventTypeBind} {
		e := LSMEvent{
			EventType:    et,
			Family:       2,
			RemoteAddrV4: binary.NativeEndian.Uint32([]byte{10, 0, 0, 1}),
			// Raw sin_port: network-order bytes of 443, loaded natively.
			RemotePort: binary.NativeEndian.Uint16([]byte{0x01, 0xbb}),
		}
		got := e.ToEvent()
		if got.Family != 2 {
			t.Errorf("type %d: Family = %d, want 2", et, got.Family)
		}
		if got.RemoteAddr != "10.0.0.1" {
			t.Errorf("type %d: RemoteAddr = %q, want 10.0.0.1", et, got.RemoteAddr)
		}
		if got.RemotePort != 443 {
			t.Errorf("type %d: RemotePort = %d, want 443 (network order converted)", et, got.RemotePort)
		}
	}
}

func TestLSMEvent_ToEvent_BindIPv4Any(t *testing.T) {
	// Regression: bind to 0.0.0.0 has a zero address, which used to be
	// mistaken for IPv6 "::". The family comes from the kernel now.
	e := LSMEvent{EventType: EventTypeBind, Family: 2}
	got := e.ToEvent()
	if got.Family != 2 || got.RemoteAddr != "0.0.0.0" {
		t.Errorf("Family/RemoteAddr = %d/%q, want 2/0.0.0.0", got.Family, got.RemoteAddr)
	}
}

func TestLSMEvent_ToEvent_NetworkIPv6(t *testing.T) {
	var v6 [16]byte
	v6[0], v6[1], v6[15] = 0xfe, 0x80, 0x01
	e := LSMEvent{EventType: EventTypeNetwork, Family: 10, RemoteAddrV6: v6}

	got := e.ToEvent()
	if got.Family != 10 {
		t.Errorf("Family = %d, want 10", got.Family)
	}
	if got.RemoteAddr != "fe80::1" {
		t.Errorf("RemoteAddr = %q, want fe80::1", got.RemoteAddr)
	}

	// IPv6 any must stay "::" even though the v4 field is also zero.
	any6 := (&LSMEvent{EventType: EventTypeBind, Family: 10}).ToEvent()
	if any6.RemoteAddr != "::" {
		t.Errorf("RemoteAddr = %q, want ::", any6.RemoteAddr)
	}
}

func TestLSMEvent_MatchesGeneratedLayout(t *testing.T) {
	// LSMEvent is hand-written; the bpf2go type is generated from the C
	// struct. Their sizes must agree or every ring-buffer read misparses.
	if got, want := binary.Size(LSMEvent{}), binary.Size(lsm_execWarmorEvent{}); got != want {
		t.Errorf("binary.Size(LSMEvent) = %d, generated warmor_event = %d", got, want)
	}
}

func TestLSMEvent_ToEvent_Listen(t *testing.T) {
	// Listen events carry skc_num (host byte order) and no address.
	e := LSMEvent{EventType: EventTypeListen, RemotePort: 8080, Family: 10}
	got := e.ToEvent()
	if got.RemotePort != 8080 {
		t.Errorf("RemotePort = %d, want 8080", got.RemotePort)
	}
	if got.RemoteAddr != "" || got.Family != 10 {
		t.Errorf("listen event should have family but no address: %+v", got)
	}
}

func TestLSMEvent_ToEvent_NonNetworkIgnoresPort(t *testing.T) {
	e := LSMEvent{EventType: EventTypeExec, RemotePort: 443, RemoteAddrV4: 1}
	got := e.ToEvent()
	if got.RemotePort != 0 || got.RemoteAddr != "" {
		t.Errorf("exec event leaked network fields: %+v", got)
	}
}

func TestIntToIPv4(t *testing.T) {
	tests := []struct {
		raw  [4]byte // network-order bytes as found in sin_addr
		want string
	}{
		{[4]byte{0, 0, 0, 0}, "0.0.0.0"},
		{[4]byte{127, 0, 0, 1}, "127.0.0.1"},
		{[4]byte{169, 254, 169, 254}, "169.254.169.254"},
		{[4]byte{255, 255, 255, 255}, "255.255.255.255"},
	}
	for _, tc := range tests {
		addr := binary.LittleEndian.Uint32(tc.raw[:])
		if got := intToIPv4(addr); got != tc.want {
			t.Errorf("intToIPv4(0x%08x) = %q, want %q", addr, got, tc.want)
		}
	}
}

func TestLSMLoader_CloseZeroValue(t *testing.T) {
	// A loader whose load steps never ran must close cleanly (regression for
	// typed-nil *lsm_xxxObjects in the Close interface slice).
	l := &LSMLoader{}
	if err := l.Close(); err != nil {
		t.Errorf("Close() on zero LSMLoader = %v, want nil", err)
	}
}

func TestLoader_CloseZeroValue(t *testing.T) {
	// Regression: Load failing part-way leaves typed-nil *xxxObjects in the
	// Close interface slice; Close must skip them instead of panicking.
	l := &Loader{execveObjs: &execve_monitorObjects{}}
	if err := l.Close(); err != nil {
		t.Errorf("Close() on partially loaded Loader = %v, want nil", err)
	}
	if err := (&Loader{}).Close(); err != nil {
		t.Errorf("Close() on zero Loader = %v, want nil", err)
	}
}

func TestLSMLoader_PolicyMapAccessor(t *testing.T) {
	l := &LSMLoader{}
	if l.PolicyMap() != nil {
		t.Error("PolicyMap() on zero LSMLoader should be nil")
	}
	pm := NewPolicyMapManager(nil)
	l.policyMap = pm
	if l.PolicyMap() != pm {
		t.Error("PolicyMap() should return the configured manager")
	}
}

func TestKernelBTFAvailable(t *testing.T) {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	if got := kernelBTFAvailable(); got != (err == nil) {
		t.Errorf("kernelBTFAvailable() = %v, want %v", got, err == nil)
	}
}

func TestIsLSMSupported_Smoke(t *testing.T) {
	// Result depends on the host kernel; only verify it is deterministic and
	// does not panic when securityfs or /proc/cmdline is unreadable.
	a := IsLSMSupported()
	b := IsLSMSupported()
	if a != b {
		t.Errorf("IsLSMSupported() not deterministic: %v then %v", a, b)
	}
}
