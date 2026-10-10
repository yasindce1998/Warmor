//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestHashPattern_KnownVectors(t *testing.T) {
	tests := []struct {
		input    string
		expected uint32
	}{
		{"/usr/bin/nc", 2189914968},
		{"/tmp/malicious", 1023760618},
		{"/etc/passwd", 196983191},
		{"/var/run/secrets/kubernetes.io/serviceaccount/token", 3368653459},
		{"", 2166136261}, // FNV offset basis (empty string)
	}

	for _, tc := range tests {
		got := HashPattern(tc.input)
		if got != tc.expected {
			t.Errorf("HashPattern(%q) = %d, want %d", tc.input, got, tc.expected)
		}
	}
}

func TestHashPattern_Consistency(t *testing.T) {
	patterns := []string{
		"/usr/bin/bash",
		"/proc/self/exe",
		"/etc/shadow",
		"/home/user/.ssh/id_rsa",
		"/usr/local/bin/kubectl",
	}

	for _, p := range patterns {
		h1 := HashPattern(p)
		h2 := HashPattern(p)
		if h1 != h2 {
			t.Errorf("HashPattern(%q) not consistent: %d != %d", p, h1, h2)
		}
	}
}

func TestHashPattern_Distribution(t *testing.T) {
	patterns := []string{
		"/usr/bin/nc",
		"/usr/bin/ncat",
		"/usr/bin/socat",
		"/usr/bin/telnet",
		"/usr/bin/curl",
		"/usr/bin/wget",
		"/bin/bash",
		"/bin/sh",
		"/bin/zsh",
		"/bin/dash",
	}

	hashes := make(map[uint32]string)
	for _, p := range patterns {
		h := HashPattern(p)
		if existing, ok := hashes[h]; ok {
			t.Errorf("collision: HashPattern(%q) == HashPattern(%q) == %d", p, existing, h)
		}
		hashes[h] = p
	}
}

func TestHashIPv4Endpoint_KnownVectors(t *testing.T) {
	tests := []struct {
		name     string
		addr     uint32
		port     uint16
		expected uint32
	}{
		{"169.254.169.254:80", 0xfea9fea9, 80, 2381707833},
		{"10.0.0.1:443", 0x0100000a, 443, 4260736092},
		{"127.0.0.1:8080", 0x0100007f, 8080, 1452744712},
	}

	for _, tc := range tests {
		got := HashIPv4Endpoint(tc.addr, tc.port)
		if got != tc.expected {
			t.Errorf("HashIPv4Endpoint(%s) = %d, want %d", tc.name, got, tc.expected)
		}
	}
}

func TestHashIPv4Endpoint_DifferentPorts(t *testing.T) {
	addr := uint32(0x0100007f) // 127.0.0.1

	h80 := HashIPv4Endpoint(addr, 80)
	h443 := HashIPv4Endpoint(addr, 443)
	h8080 := HashIPv4Endpoint(addr, 8080)

	if h80 == h443 || h80 == h8080 || h443 == h8080 {
		t.Error("same IP with different ports should produce different hashes")
	}
}

func TestHashIPv4Endpoint_DifferentAddrs(t *testing.T) {
	port := uint16(80)

	h1 := HashIPv4Endpoint(0x0100007f, port) // 127.0.0.1
	h2 := HashIPv4Endpoint(0x0100000a, port) // 10.0.0.1
	h3 := HashIPv4Endpoint(0xfea9fea9, port) // 169.254.169.254

	if h1 == h2 || h1 == h3 || h2 == h3 {
		t.Error("different IPs with same port should produce different hashes")
	}
}

func TestHashIPv6Endpoint(t *testing.T) {
	// ::1 port 443
	var loopback [16]byte
	loopback[15] = 1
	h1 := HashIPv6Endpoint(loopback, 443)

	// fe80::1 port 443
	var linkLocal [16]byte
	linkLocal[0] = 0xfe
	linkLocal[1] = 0x80
	linkLocal[15] = 1
	h2 := HashIPv6Endpoint(linkLocal, 443)

	if h1 == h2 {
		t.Error("different IPv6 addresses should produce different hashes")
	}

	// Same addr different port
	h3 := HashIPv6Endpoint(loopback, 80)
	if h1 == h3 {
		t.Error("same IPv6 addr with different port should produce different hashes")
	}
}

func TestHashIPv6Endpoint_Consistency(t *testing.T) {
	var addr [16]byte
	addr[0] = 0x20
	addr[1] = 0x01
	addr[2] = 0x0d
	addr[3] = 0xb8
	addr[15] = 1

	h1 := HashIPv6Endpoint(addr, 8443)
	h2 := HashIPv6Endpoint(addr, 8443)
	if h1 != h2 {
		t.Errorf("HashIPv6Endpoint not consistent: %d != %d", h1, h2)
	}
}

func TestPolicyKey_MarshalBinary(t *testing.T) {
	key := PolicyKey{
		CgroupID:  0x0102030405060708,
		RuleHash:  0xAABBCCDD,
		EventType: EventTypeExec,
	}

	data, err := key.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(data))
	}

	// Verify layout: CgroupID (8 bytes LE) + RuleHash (4 bytes LE) + EventType (1) + Pad (3)
	gotCgroup := binary.LittleEndian.Uint64(data[0:8])
	if gotCgroup != 0x0102030405060708 {
		t.Errorf("CgroupID = 0x%x, want 0x0102030405060708", gotCgroup)
	}

	gotHash := binary.LittleEndian.Uint32(data[8:12])
	if gotHash != 0xAABBCCDD {
		t.Errorf("RuleHash = 0x%x, want 0xAABBCCDD", gotHash)
	}

	if data[12] != EventTypeExec {
		t.Errorf("EventType = %d, want %d", data[12], EventTypeExec)
	}

	// Padding must be zero
	if data[13] != 0 || data[14] != 0 || data[15] != 0 {
		t.Errorf("padding not zero: [%d, %d, %d]", data[13], data[14], data[15])
	}
}

func TestPolicyKey_MarshalBinary_AllEventTypes(t *testing.T) {
	types := []uint8{EventTypeExec, EventTypeFile, EventTypeNetwork}

	for _, et := range types {
		key := PolicyKey{
			CgroupID:  1,
			RuleHash:  12345,
			EventType: et,
		}

		data, err := key.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary failed for event type %d: %v", et, err)
		}

		if data[12] != et {
			t.Errorf("event type %d: got byte %d", et, data[12])
		}
	}
}

func TestPolicyKey_MarshalBinary_ZeroValue(t *testing.T) {
	key := PolicyKey{}

	data, err := key.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	for i, b := range data {
		if b != 0 {
			t.Errorf("byte[%d] = %d, want 0 for zero-value key", i, b)
		}
	}
}

func TestHashPort_KnownVectors(t *testing.T) {
	tests := []struct {
		port uint16
	}{
		{0}, {22}, {80}, {443}, {8080}, {65535},
	}

	for _, tc := range tests {
		// Reference: FNV-1a over the port's two bytes, low byte first.
		want := uint32(2166136261)
		want ^= uint32(tc.port & 0xFF)
		want *= 16777619
		want ^= uint32(tc.port >> 8)
		want *= 16777619

		if got := HashPort(tc.port); got != want {
			t.Errorf("HashPort(%d) = %d, want %d", tc.port, got, want)
		}
	}
}

func TestHashPort_MatchesHashPatternOfLEBytes(t *testing.T) {
	// hash_port in BPF is FNV-1a over the little-endian bytes of the port.
	for _, port := range []uint16{1, 80, 443, 8080, 65535} {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, port)
		if got, want := HashPort(port), HashPattern(string(b)); got != want {
			t.Errorf("HashPort(%d) = %d, want FNV-1a(LE bytes) = %d", port, got, want)
		}
	}
}

func TestHashPort_Distinct(t *testing.T) {
	seen := make(map[uint32]uint16)
	for _, p := range []uint16{22, 80, 443, 3306, 5432, 6379, 8080, 8443} {
		h := HashPort(p)
		if prev, ok := seen[h]; ok {
			t.Errorf("collision: HashPort(%d) == HashPort(%d)", p, prev)
		}
		seen[h] = p
	}
}

func TestHashIPv4Endpoint_MatchesHashPatternOfBytes(t *testing.T) {
	// The endpoint hash is FNV-1a over the 4 address bytes (LE order of the
	// u32) followed by the 2 port bytes (LE order of the u16).
	addr := uint32(0x0100007f)
	port := uint16(0x5000)
	b := make([]byte, 6)
	binary.LittleEndian.PutUint32(b[0:4], addr)
	binary.LittleEndian.PutUint16(b[4:6], port)
	if got, want := HashIPv4Endpoint(addr, port), HashPattern(string(b)); got != want {
		t.Errorf("HashIPv4Endpoint = %d, want %d", got, want)
	}
}

func TestHashIPv6Endpoint_MatchesHashPatternOfBytes(t *testing.T) {
	var addr [16]byte
	for i := range addr {
		addr[i] = byte(i * 7)
	}
	port := uint16(0xbb01)
	b := append(addr[:0:0], addr[:]...)
	b = append(b, byte(port), byte(port>>8))
	if got, want := HashIPv6Endpoint(addr, port), HashPattern(string(b)); got != want {
		t.Errorf("HashIPv6Endpoint = %d, want %d", got, want)
	}
}

func TestPolicyStructSizes(t *testing.T) {
	if got := binary.Size(PolicyKey{}); got != 16 {
		t.Errorf("binary.Size(PolicyKey) = %d, want 16", got)
	}
	if got := binary.Size(PolicyValue{}); got != 8 {
		t.Errorf("binary.Size(PolicyValue) = %d, want 8", got)
	}
}

func TestPolicyKey_MarshalBinary_IgnoresPad(t *testing.T) {
	// Non-zero Pad must not leak into the map key, or lookups from the BPF
	// side (which zero-initialises pad) would miss.
	key := PolicyKey{CgroupID: 1, RuleHash: 2, EventType: EventTypeMount, Pad: [3]uint8{9, 9, 9}}
	data, err := key.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	if data[13] != 0 || data[14] != 0 || data[15] != 0 {
		t.Errorf("padding not zeroed: %v", data[13:])
	}
	if data[12] != EventTypeMount {
		t.Errorf("EventType byte = %d, want %d", data[12], EventTypeMount)
	}
}

func TestPolicyKey_MarshalBinary_MatchesBinaryWrite(t *testing.T) {
	key := PolicyKey{CgroupID: 0xfeedface, RuleHash: HashPattern("/bin/sh"), EventType: EventTypePtrace}
	data, err := key.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	// The kernel reads the key in host byte order.
	want := make([]byte, 0, 16)
	want = binary.NativeEndian.AppendUint64(want, key.CgroupID)
	want = binary.NativeEndian.AppendUint32(want, key.RuleHash)
	want = append(want, key.EventType, 0, 0, 0)
	if string(data) != string(want) {
		t.Errorf("MarshalBinary = %x, want %x", data, want)
	}
}

func TestNewPolicyMapManager(t *testing.T) {
	m := NewPolicyMapManager(nil)
	if m == nil {
		t.Fatal("NewPolicyMapManager returned nil")
	}
	if m.policyMap != nil {
		t.Error("expected wrapped map to be the one passed in")
	}
}

// cFnv1aHash is a line-by-line Go port of fnv1a_hash in bpf/warmor_lsm.h,
// operating on the fixed buffer the BPF program filled and the length
// bpf_probe_read_kernel_str returned (including the NUL).
func cFnv1aHash(data []byte, length int) uint32 {
	const warmorHashStrMax = 256
	hash := uint32(2166136261)
	for i := 0; i < warmorHashStrMax; i++ {
		if i >= length || data[i] == 0 {
			break
		}
		hash ^= uint32(data[i]) // (__u32)(__u8)data[i]
		hash *= 16777619
	}
	return hash
}

// kernelReadStr mimics bpf_probe_read_kernel_str into a bufSize buffer.
func kernelReadStr(s string, bufSize int) ([]byte, int) {
	buf := make([]byte, bufSize)
	n := copy(buf[:bufSize-1], s)
	buf[n] = 0
	return buf, n + 1
}

func TestHashPattern_MatchesKernelFnv1a(t *testing.T) {
	long := "/usr/lib/x86_64-linux-gnu/" + strings.Repeat("abcdefgh", 30) // 266 bytes
	vectors := []string{
		"",
		"/bin/sh",
		"/usr/bin/python3",         // exactly 16 bytes
		"/usr/bin/python3.12",      // > 16 bytes, shares the 16-byte prefix above
		"/usr/local/bin/kubectl",   // > 16 bytes
		"/opt/caf\xc3\xa9/bin/run", // non-ASCII: char is signed on BPF
		"\xff\x80\x7f",
		long[:maxExecPatternLen],
	}
	for _, v := range vectors {
		buf, n := kernelReadStr(v, 256)
		if got, want := HashPattern(v), cFnv1aHash(buf, n); got != want {
			t.Errorf("HashPattern(%q) = %#x, kernel fnv1a_hash = %#x", v, got, want)
		}
	}
	// A string longer than the buffer is truncated by the kernel read; Go
	// refuses to write a rule for it (see TestRuleHash_RejectsUnmatchable).
	if buf, n := kernelReadStr(long, 256); HashPattern(long) == cFnv1aHash(buf, n) {
		t.Error("truncated kernel read unexpectedly hashed the full string")
	}
	// The old 16-byte-prefix kernel hash made these two collide.
	if HashPattern("/usr/bin/python3") == HashPattern("/usr/bin/python3.12") {
		t.Error("distinct paths sharing a 16-byte prefix must hash differently")
	}
}

func TestRuleHash_KernelMatchable(t *testing.T) {
	for _, tc := range []struct {
		eventType uint8
		pattern   string
		bufSize   int
	}{
		{EventTypeExec, "/usr/local/bin/some-long-binary-name", 256},
		{EventTypeExec, strings.Repeat("a", maxExecPatternLen), 256},
		{EventTypeMount, "overlay", 64},
		{EventTypeMount, strings.Repeat("m", maxMountPatternLen), 64},
		{EventTypePtrace, "gdb", 16},
		{EventTypePtrace, strings.Repeat("c", maxPtracePatternLen), 16},
	} {
		got, err := ruleHash(tc.eventType, tc.pattern)
		if err != nil {
			t.Errorf("ruleHash(%d, len %d) unexpected error: %v", tc.eventType, len(tc.pattern), err)
			continue
		}
		buf, n := kernelReadStr(tc.pattern, tc.bufSize)
		if tc.eventType == EventTypePtrace {
			// lsm_ptrace hashes the whole comm buffer (len 16); comm is
			// always NUL-terminated within it.
			n = tc.bufSize
		} else if n >= tc.bufSize {
			// The kernel only consults the map when the read did not fill
			// the buffer.
			t.Errorf("event type %d: pattern of len %d would be skipped by the kernel", tc.eventType, len(tc.pattern))
		}
		if want := cFnv1aHash(buf, n); got != want {
			t.Errorf("ruleHash(%d, %q) = %#x, kernel = %#x", tc.eventType, tc.pattern, got, want)
		}
	}
}

func TestRuleHash_RejectsUnmatchable(t *testing.T) {
	for _, tc := range []struct {
		name      string
		eventType uint8
		pattern   string
	}{
		// The kernel sees only the basename for file_open.
		{"file", EventTypeFile, "/etc/shadow"},
		// Endpoint events are keyed by binary hashes, not strings.
		{"network string", EventTypeNetwork, "10.0.0.1"},
		{"bind string", EventTypeBind, "0.0.0.0"},
		{"listen string", EventTypeListen, "8080"},
		// Would be truncated by the kernel read, so only a prefix is hashed.
		{"exec too long", EventTypeExec, strings.Repeat("a", maxExecPatternLen+1)},
		{"mount too long", EventTypeMount, strings.Repeat("m", maxMountPatternLen+1)},
		{"ptrace too long", EventTypePtrace, strings.Repeat("c", maxPtracePatternLen+1)},
		// The kernel stops at the first NUL.
		{"embedded NUL", EventTypeExec, "/bin/sh\x00/evil"},
	} {
		if _, err := ruleHash(tc.eventType, tc.pattern); !errors.Is(err, ErrNotKernelMatchable) {
			t.Errorf("%s: err = %v, want ErrNotKernelMatchable", tc.name, err)
		}
	}
}

func TestSetRule_RefusesUnmatchableWithoutTouchingMap(t *testing.T) {
	// A nil map would panic on Put; refusal must happen first.
	m := NewPolicyMapManager(nil)
	if err := m.SetRule(0, EventTypeFile, "/etc/passwd", ActionDeny, false); !errors.Is(err, ErrNotKernelMatchable) {
		t.Errorf("SetRule(file) err = %v, want ErrNotKernelMatchable", err)
	}
	if err := m.SetEndpointRule(0, EventTypeListen, "10.0.0.1", 80, ActionDeny, false); !errors.Is(err, ErrNotKernelMatchable) {
		t.Errorf("SetEndpointRule(listen) err = %v, want ErrNotKernelMatchable", err)
	}
	if err := m.SetEndpointRule(0, EventTypeNetwork, "not-an-ip", 80, ActionDeny, false); err == nil {
		t.Error("SetEndpointRule with invalid address should fail")
	}
	if err := m.SyncFromWASM([]CachedDecision{{EventType: EventTypeFile, Pattern: "/etc/passwd", Action: ActionDeny}}); err != nil {
		t.Errorf("SyncFromWASM should skip unmatchable decisions, got %v", err)
	}
}

// cHashIPv4Endpoint ports hash_ipv4_endpoint from bpf/lsm_connect.bpf.c,
// fed exactly what the program loads from a struct sockaddr_in in memory.
func cHashIPv4Endpoint(sinPort [2]byte, sinAddr [4]byte) uint32 {
	addr := binary.NativeEndian.Uint32(sinAddr[:])
	port := binary.NativeEndian.Uint16(sinPort[:])
	hash := uint32(2166136261)
	hash ^= addr & 0xFF
	hash *= 16777619
	hash ^= (addr >> 8) & 0xFF
	hash *= 16777619
	hash ^= (addr >> 16) & 0xFF
	hash *= 16777619
	hash ^= (addr >> 24) & 0xFF
	hash *= 16777619
	hash ^= uint32(port & 0xFF)
	hash *= 16777619
	hash ^= uint32((port >> 8) & 0xFF)
	hash *= 16777619
	return hash
}

// cHashIPv6Endpoint ports hash_ipv6_endpoint from bpf/lsm_connect.bpf.c.
func cHashIPv6Endpoint(sinPort [2]byte, sinAddr [16]byte) uint32 {
	port := binary.NativeEndian.Uint16(sinPort[:])
	hash := uint32(2166136261)
	for i := 0; i < 16; i++ {
		hash ^= uint32(sinAddr[i])
		hash *= 16777619
	}
	hash ^= uint32(port & 0xFF)
	hash *= 16777619
	hash ^= uint32((port >> 8) & 0xFF)
	hash *= 16777619
	return hash
}

func TestEndpointHash_MatchesKernel(t *testing.T) {
	v4 := []struct {
		addr string
		port uint16
		raw  [4]byte
	}{
		{"10.0.0.1", 443, [4]byte{10, 0, 0, 1}},
		{"192.168.1.20", 8080, [4]byte{192, 168, 1, 20}},
		{"0.0.0.0", 0, [4]byte{}},
	}
	for _, tc := range v4 {
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], tc.port) // sin_port is network order
		got, err := endpointHash(tc.addr, tc.port)
		if err != nil {
			t.Fatalf("endpointHash(%s): %v", tc.addr, err)
		}
		if want := cHashIPv4Endpoint(port, tc.raw); got != want {
			t.Errorf("endpointHash(%s, %d) = %#x, kernel = %#x", tc.addr, tc.port, got, want)
		}
		// Must differ from the string hash the enforcer used to write.
		if got == HashPattern(tc.addr) {
			t.Errorf("endpoint hash for %s equals its string hash", tc.addr)
		}
	}

	var raw6 [16]byte
	raw6[0], raw6[1], raw6[15] = 0x20, 0x01, 0x01
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], 53)
	got, err := endpointHash("2001::1", 53)
	if err != nil {
		t.Fatalf("endpointHash(2001::1): %v", err)
	}
	if want := cHashIPv6Endpoint(port, raw6); got != want {
		t.Errorf("endpointHash(2001::1, 53) = %#x, kernel = %#x", got, want)
	}

	if _, err := endpointHash("bogus", 1); err == nil {
		t.Error("endpointHash(bogus) should fail")
	}
}
