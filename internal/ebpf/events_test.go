package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestNullTerminatedString(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"nil", nil, ""},
		{"empty", []byte{}, ""},
		{"leading NUL", []byte{0, 'a', 'b'}, ""},
		{"terminated", []byte{'b', 'a', 's', 'h', 0, 0, 0}, "bash"},
		{"garbage after NUL", []byte{'s', 'h', 0, 'x', 'y'}, "sh"},
		{"no terminator", []byte{'a', 'b', 'c'}, "abc"},
		{"all NUL", make([]byte, 16), ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := nullTerminatedString(tc.input); got != tc.want {
				t.Errorf("nullTerminatedString(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNullTerminatedString_FullBuffer(t *testing.T) {
	// A comm that exactly fills the 16-byte buffer with no NUL must be returned whole.
	var comm [16]byte
	copy(comm[:], "abcdefghijklmnop")
	if got := nullTerminatedString(comm[:]); got != "abcdefghijklmnop" {
		t.Errorf("got %q, want full 16-byte string", got)
	}
}

func TestNtohs(t *testing.T) {
	tests := []struct {
		in, want uint16
	}{
		{0x0000, 0x0000},
		{0x5000, 0x0050}, // port 80 in network order read as LE
		{0xbb01, 0x01bb}, // port 443
		{0x901f, 0x1f90}, // port 8080
		{0xffff, 0xffff},
		{0x1234, 0x3412},
	}

	for _, tc := range tests {
		if got := ntohs(tc.in); got != tc.want {
			t.Errorf("ntohs(0x%04x) = 0x%04x, want 0x%04x", tc.in, got, tc.want)
		}
		if got := ntohs(ntohs(tc.in)); got != tc.in {
			t.Errorf("ntohs(ntohs(0x%04x)) = 0x%04x, want round trip", tc.in, got)
		}
	}
}

func TestBootTimeToWallClock(t *testing.T) {
	// Zero boot ns maps to the boot-time offset itself.
	if got := bootTimeToWallClock(0); !got.Equal(time.Unix(0, 0).Add(bootTimeOffset)) {
		t.Errorf("bootTimeToWallClock(0) = %v, want %v", got, time.Unix(0, 0).Add(bootTimeOffset))
	}

	// Monotonic ordering is preserved.
	a := bootTimeToWallClock(1_000_000_000)
	b := bootTimeToWallClock(2_000_000_000)
	if d := b.Sub(a); d != time.Second {
		t.Errorf("delta = %v, want 1s", d)
	}
}

// putCString writes s into buf at off, truncated to n bytes.
func putCString(buf []byte, off, n int, s string) {
	copy(buf[off:off+n], s)
}

// rawExecveEvent builds a struct execve_event exactly as laid out by the C
// compiler in bpf/execve_monitor.bpf.c (little-endian, natural alignment).
func rawExecveEvent(pid, uid, gid uint32, comm, filename string, ts, cgid uint64) []byte {
	buf := make([]byte, 304)
	binary.LittleEndian.PutUint32(buf[0:], pid)
	binary.LittleEndian.PutUint32(buf[4:], uid)
	binary.LittleEndian.PutUint32(buf[8:], gid)
	putCString(buf, 12, 16, comm)
	putCString(buf, 28, 256, filename)
	// 4 bytes of padding at 284..288
	binary.LittleEndian.PutUint64(buf[288:], ts)
	binary.LittleEndian.PutUint64(buf[296:], cgid)
	return buf
}

func rawOpenatEvent(pid, uid, gid uint32, comm, path string, flags, mode uint32, ts, cgid uint64) []byte {
	buf := make([]byte, 312)
	binary.LittleEndian.PutUint32(buf[0:], pid)
	binary.LittleEndian.PutUint32(buf[4:], uid)
	binary.LittleEndian.PutUint32(buf[8:], gid)
	putCString(buf, 12, 16, comm)
	putCString(buf, 28, 256, path)
	binary.LittleEndian.PutUint32(buf[284:], flags)
	binary.LittleEndian.PutUint32(buf[288:], mode)
	// 4 bytes of padding at 292..296
	binary.LittleEndian.PutUint64(buf[296:], ts)
	binary.LittleEndian.PutUint64(buf[304:], cgid)
	return buf
}

func rawConnectEvent(pid uint32, comm string, family uint16, portBytes [2]byte, v4 [4]byte, v6 [16]byte, ts, cgid uint64) []byte {
	buf := make([]byte, 72)
	binary.LittleEndian.PutUint32(buf[0:], pid)
	putCString(buf, 12, 16, comm)
	binary.LittleEndian.PutUint16(buf[28:], family)
	copy(buf[30:32], portBytes[:]) // sin_port, network byte order
	copy(buf[32:36], v4[:])        // sin_addr, network byte order
	copy(buf[36:52], v6[:])
	// 4 bytes of padding at 52..56
	binary.LittleEndian.PutUint64(buf[56:], ts)
	binary.LittleEndian.PutUint64(buf[64:], cgid)
	return buf
}

func TestEventStructSizes(t *testing.T) {
	// Sizes must match sizeof() of the C structs, otherwise binary.Read on a
	// ring-buffer sample silently misaligns every field after the mismatch.
	tests := []struct {
		name string
		v    any
		want int
	}{
		{"ExecveEvent", ExecveEvent{}, 304},
		{"OpenatEvent", OpenatEvent{}, 312},
		{"ConnectEvent", ConnectEvent{}, 72},
	}
	for _, tc := range tests {
		if got := binary.Size(tc.v); got != tc.want {
			t.Errorf("binary.Size(%s) = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestExecveEvent_DecodeAndConvert(t *testing.T) {
	raw := rawExecveEvent(4242, 1000, 1001, "bash", "/usr/bin/curl", 5_000_000_000, 0xdeadbeef)

	var ev ExecveEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		t.Fatalf("binary.Read failed: %v", err)
	}

	got := ev.ToEvent()
	if got.Kind != EventKindProcess {
		t.Errorf("Kind = %d, want EventKindProcess", got.Kind)
	}
	if got.PID != 4242 || got.UID != 1000 || got.GID != 1001 {
		t.Errorf("PID/UID/GID = %d/%d/%d, want 4242/1000/1001", got.PID, got.UID, got.GID)
	}
	if got.Comm != "bash" {
		t.Errorf("Comm = %q, want bash", got.Comm)
	}
	if got.Filename != "/usr/bin/curl" {
		t.Errorf("Filename = %q, want /usr/bin/curl", got.Filename)
	}
	if got.CgroupID != 0xdeadbeef {
		t.Errorf("CgroupID = 0x%x, want 0xdeadbeef", got.CgroupID)
	}
	if !got.Timestamp.Equal(bootTimeToWallClock(5_000_000_000)) {
		t.Errorf("Timestamp = %v, want %v", got.Timestamp, bootTimeToWallClock(5_000_000_000))
	}
	if got.Flags != 0 || got.Mode != 0 || got.RemoteAddr != "" || got.RemotePort != 0 || got.Family != 0 {
		t.Errorf("unexpected non-process fields set: %+v", got)
	}
}

func TestExecveEvent_MaxLengthFilename(t *testing.T) {
	long := strings.Repeat("a", 256) // fills buffer, no NUL terminator
	raw := rawExecveEvent(1, 0, 0, "x", long, 0, 0)

	var ev ExecveEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		t.Fatalf("binary.Read failed: %v", err)
	}
	got := ev.ToEvent()
	if got.Filename != long {
		t.Errorf("Filename length = %d, want 256", len(got.Filename))
	}
	// Bytes of the following padding/timestamp must not leak into the string.
	if got.Timestamp != bootTimeToWallClock(0) {
		t.Errorf("Timestamp = %v, want zero boot time", got.Timestamp)
	}
}

func TestOpenatEvent_DecodeAndConvert(t *testing.T) {
	raw := rawOpenatEvent(77, 0, 0, "cat", "/etc/shadow", 0o2|0o100, 0o644, 123, 9)

	var ev OpenatEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		t.Fatalf("binary.Read failed: %v", err)
	}

	got := ev.ToEvent()
	if got.Kind != EventKindFile {
		t.Errorf("Kind = %d, want EventKindFile", got.Kind)
	}
	if got.PID != 77 || got.Comm != "cat" || got.Filename != "/etc/shadow" {
		t.Errorf("got PID=%d Comm=%q Filename=%q", got.PID, got.Comm, got.Filename)
	}
	if got.Flags != 0o102 {
		t.Errorf("Flags = %o, want 102", got.Flags)
	}
	if got.Mode != 0o644 {
		t.Errorf("Mode = %o, want 644", got.Mode)
	}
	if got.CgroupID != 9 {
		t.Errorf("CgroupID = %d, want 9", got.CgroupID)
	}
	if !got.Timestamp.Equal(bootTimeToWallClock(123)) {
		t.Errorf("Timestamp mismatch: %v", got.Timestamp)
	}
}

func TestConnectEvent_DecodeIPv6(t *testing.T) {
	var v6 [16]byte
	v6[0], v6[1], v6[2], v6[3], v6[15] = 0x20, 0x01, 0x0d, 0xb8, 0x01
	raw := rawConnectEvent(10, "curl", 10, [2]byte{0x01, 0xbb}, [4]byte{}, v6, 55, 66)

	var ev ConnectEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		t.Fatalf("binary.Read failed: %v", err)
	}

	got := ev.ToEvent()
	if got.Kind != EventKindNetwork {
		t.Errorf("Kind = %d, want EventKindNetwork", got.Kind)
	}
	if got.Family != 10 {
		t.Errorf("Family = %d, want 10", got.Family)
	}
	if got.RemoteAddr != "2001:db8::1" {
		t.Errorf("RemoteAddr = %q, want 2001:db8::1", got.RemoteAddr)
	}
	if got.RemotePort != 443 {
		t.Errorf("RemotePort = %d, want 443 (network order converted)", got.RemotePort)
	}
	if got.Comm != "curl" || got.PID != 10 || got.CgroupID != 66 {
		t.Errorf("got Comm=%q PID=%d CgroupID=%d", got.Comm, got.PID, got.CgroupID)
	}
	if !got.Timestamp.Equal(bootTimeToWallClock(55)) {
		t.Errorf("Timestamp mismatch: %v", got.Timestamp)
	}
}

func TestConnectEvent_RemoteAddrString(t *testing.T) {
	var v6 [16]byte
	v6[15] = 1

	tests := []struct {
		name string
		ev   ConnectEvent
		want string
	}{
		// remoteAddrString treats RemoteAddrV4 as a host-order integer
		// (most significant byte = first octet).
		{"ipv4", ConnectEvent{Family: 2, RemoteAddrV4: 0x0a000001}, "10.0.0.1"},
		{"ipv4 any", ConnectEvent{Family: 2}, "0.0.0.0"},
		{"ipv6 loopback", ConnectEvent{Family: 10, RemoteAddrV6: v6}, "::1"},
		{"ipv6 any", ConnectEvent{Family: 10}, "::"},
		{"unix", ConnectEvent{Family: 1}, "unknown-family-1"},
		{"unspec", ConnectEvent{Family: 0}, "unknown-family-0"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ev.remoteAddrString(); got != tc.want {
				t.Errorf("remoteAddrString() = %q, want %q", got, tc.want)
			}
			if got := tc.ev.ToEvent().RemoteAddr; got != tc.want {
				t.Errorf("ToEvent().RemoteAddr = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEventDecode_ShortInput(t *testing.T) {
	tests := []struct {
		name string
		dst  any
		size int
	}{
		{"execve", &ExecveEvent{}, 304},
		{"openat", &OpenatEvent{}, 312},
		{"connect", &ConnectEvent{}, 72},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Empty sample.
			if err := binary.Read(bytes.NewReader(nil), binary.LittleEndian, tc.dst); !errors.Is(err, io.EOF) {
				t.Errorf("empty input: err = %v, want io.EOF", err)
			}
			// One byte short.
			short := make([]byte, tc.size-1)
			if err := binary.Read(bytes.NewReader(short), binary.LittleEndian, tc.dst); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("truncated input: err = %v, want io.ErrUnexpectedEOF", err)
			}
			// Trailing bytes (ring buffer samples are 8-byte padded) are ignored.
			long := make([]byte, tc.size+8)
			if err := binary.Read(bytes.NewReader(long), binary.LittleEndian, tc.dst); err != nil {
				t.Errorf("oversized input: unexpected err %v", err)
			}
		})
	}
}
