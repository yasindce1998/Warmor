package efw

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"unicode/utf16"
)

func putUTF16(dst []byte, s string) int {
	n := 0
	for _, u := range utf16.Encode([]rune(s)) {
		binary.LittleEndian.PutUint16(dst[n:], u)
		n += 2
	}
	return n
}

func TestLayoutConstants(t *testing.T) {
	// Pinned against bpf-windows/warmor_efw.h.
	if procOffCmd != 1072 || procOffCmd+cmdlineBytes != procRecSize {
		t.Fatalf("warmor_proc_rec layout: cmd at %d, size %d", procOffCmd, procRecSize)
	}
	if netOffLocalAddr+16 != netRecSize {
		t.Fatalf("warmor_net_rec layout: size %d", netRecSize)
	}
}

func TestParseProcessCreate(t *testing.T) {
	b := make([]byte, procRecSize)
	binary.LittleEndian.PutUint32(b[0:], recProcessCreate)
	binary.LittleEndian.PutUint32(b[4:], uint32(VerdictBlocked))
	binary.LittleEndian.PutUint64(b[8:], 4242)
	binary.LittleEndian.PutUint64(b[procOffPPID:], 100)
	binary.LittleEndian.PutUint64(b[procOffCreation:], 133500000000000000)
	binary.LittleEndian.PutUint64(b[procOffImageHash:], 0xfeed)
	img := `\Device\HarddiskVolume3\Windows\System32\cmd.exe`
	n := putUTF16(b[procOffImage:], img)
	binary.LittleEndian.PutUint16(b[procOffImageLen:], uint16(n))
	cmd := `cmd.exe /c whoami`
	n = putUTF16(b[procOffCmd:], cmd)
	binary.LittleEndian.PutUint16(b[procOffCmdLen:], uint16(n))

	v, err := parseRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	r := v.(*ProcessRecord)
	if r.Exit || r.Verdict != VerdictBlocked || r.PID != 4242 || r.PPID != 100 ||
		r.CreationTime != 133500000000000000 || r.ImageHash != 0xfeed ||
		r.NTImage != img || r.CmdLine != cmd {
		t.Fatalf("unexpected record: %+v", r)
	}
}

func TestParseProcessExit(t *testing.T) {
	b := make([]byte, procExitRecSize)
	binary.LittleEndian.PutUint32(b[0:], recProcessExit)
	binary.LittleEndian.PutUint64(b[8:], 77)
	binary.LittleEndian.PutUint32(b[16:], 3)
	v, err := parseRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	if r := v.(*ProcessRecord); !r.Exit || r.PID != 77 || r.ExitCode != 3 {
		t.Fatalf("unexpected exit record: %+v", r)
	}
}

func TestParseNetwork(t *testing.T) {
	b := make([]byte, netRecSize)
	binary.LittleEndian.PutUint32(b[0:], recNetwork)
	binary.LittleEndian.PutUint64(b[8:], 9)
	binary.LittleEndian.PutUint64(b[netOffImageHash:], 0xabc)
	b[netOffFamily] = afInet
	b[netOffDirection] = DirConnect
	b[netOffProtocol] = protoTCP
	binary.BigEndian.PutUint16(b[netOffRemotePort:], 443)
	binary.BigEndian.PutUint16(b[netOffLocalPort:], 50000)
	copy(b[netOffRemoteAddr:], []byte{1, 2, 3, 4})
	copy(b[netOffLocalAddr:], []byte{10, 0, 0, 1})

	v, err := parseRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	r := v.(*NetworkRecord)
	if r.Remote != netip.MustParseAddrPort("1.2.3.4:443") || r.Local != netip.MustParseAddrPort("10.0.0.1:50000") ||
		r.Operation() != "connect" || r.ProtocolName() != "tcp" || r.ImageHash != 0xabc || r.PID != 9 {
		t.Fatalf("unexpected record: %+v", r)
	}

	b[netOffFamily] = afInet6
	b[netOffDirection] = DirAccept
	b[netOffProtocol] = protoUDP
	copy(b[netOffRemoteAddr:], netip.MustParseAddr("2001:db8::7").AsSlice())
	v, _ = parseRecord(b)
	r = v.(*NetworkRecord)
	if r.Remote.Addr().String() != "2001:db8::7" || r.Operation() != "accept" || r.ProtocolName() != "udp6" || !r.IPv6Family {
		t.Fatalf("unexpected IPv6 record: %+v", r)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	if _, err := parseRecord(make([]byte, 8)); err == nil {
		t.Error("short header accepted")
	}
	b := make([]byte, 100)
	binary.LittleEndian.PutUint32(b, recProcessCreate)
	if _, err := parseRecord(b); err == nil {
		t.Error("truncated process record accepted")
	}
	binary.LittleEndian.PutUint32(b, 99)
	if _, err := parseRecord(b); err == nil {
		t.Error("unknown kind accepted")
	}
}

func TestUTF16LEClampsLength(t *testing.T) {
	b := make([]byte, 8)
	putUTF16(b, "abcd")
	if got := utf16le(b, 1000); got != "abcd" {
		t.Fatalf("utf16le = %q", got)
	}
}

func TestNetKey(t *testing.T) {
	k, err := netKey(0x1122334455667788, "connect", "tcp", netip.MustParseAddrPort("93.184.216.34:443"))
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, netKeySize)
	binary.LittleEndian.PutUint64(want[0:], 0x1122334455667788)
	want[8] = afInet
	want[9] = DirConnect
	want[10] = protoTCP
	want[12], want[13] = 0x01, 0xbb
	copy(want[16:], []byte{93, 184, 216, 34})
	if string(k) != string(want) {
		t.Fatalf("netKey = %x, want %x", k, want)
	}

	// A key must match what the kernel builds from the record of the same
	// operation: the record's fields are copied into the key verbatim.
	rec := make([]byte, netRecSize)
	binary.LittleEndian.PutUint32(rec[0:], recNetwork)
	binary.LittleEndian.PutUint64(rec[netOffImageHash:], 0x99)
	rec[netOffFamily] = afInet6
	rec[netOffDirection] = DirAccept
	rec[netOffProtocol] = protoTCP
	binary.BigEndian.PutUint16(rec[netOffRemotePort:], 22)
	copy(rec[netOffRemoteAddr:], netip.MustParseAddr("2001:db8::1").AsSlice())
	v, _ := parseRecord(rec)
	r := v.(*NetworkRecord)
	k, err = netKey(r.ImageHash, r.Operation(), r.ProtocolName(), r.Remote)
	if err != nil {
		t.Fatal(err)
	}
	kernelKey := make([]byte, netKeySize)
	copy(kernelKey[0:8], rec[netOffImageHash:netOffImageHash+8])
	kernelKey[8], kernelKey[9], kernelKey[10] = rec[netOffFamily], rec[netOffDirection], rec[netOffProtocol]
	copy(kernelKey[12:14], rec[netOffRemotePort:netOffRemotePort+2])
	copy(kernelKey[16:32], rec[netOffRemoteAddr:netOffRemoteAddr+16])
	if string(k) != string(kernelKey) {
		t.Fatalf("userspace key %x != kernel key %x", k, kernelKey)
	}

	if _, err := netKey(0, "connect", "tcp", netip.MustParseAddrPort("1.1.1.1:1")); err == nil {
		t.Error("unknown image must not produce a key")
	}
	if _, err := netKey(1, "bind", "tcp", netip.MustParseAddrPort("1.1.1.1:1")); err == nil {
		t.Error("operations without a hook must not produce a key")
	}
}

func TestPolicyValue(t *testing.T) {
	if v := policyValue(true, false); v[0] != 1 || v[1] != 0 || len(v) != policyValueSize {
		t.Fatalf("deny value = %v", v)
	}
	if v := policyValue(true, true); v[1] != 1 {
		t.Fatalf("audit value = %v", v)
	}
}
