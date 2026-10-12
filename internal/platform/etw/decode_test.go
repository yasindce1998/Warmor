package etw

import (
	"testing"
	"time"
)

func TestFiletimeToTime(t *testing.T) {
	// 2021-01-01T00:00:00Z expressed as a Windows FILETIME (100ns ticks since
	// 1601-01-01 UTC).
	want := time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)
	const epochDeltaSeconds = 11644473600
	ft := (want.Unix() + epochDeltaSeconds) * 10_000_000

	got := filetimeToTime(ft)
	if !got.Equal(want) {
		t.Errorf("filetimeToTime(%d) = %v, want %v", ft, got, want)
	}
}

func TestFiletimeToTime_NonPositiveFallsBackToNow(t *testing.T) {
	before := time.Now()
	got := filetimeToTime(0)
	after := time.Now()

	if got.Before(before) || got.After(after) {
		t.Errorf("filetimeToTime(0) = %v, want a value within [%v, %v]", got, before, after)
	}
}

func TestNetRecordIPv4Connect(t *testing.T) {
	r := &netRecord{
		EventID: netEventTCPConnect4,
		PID:     1234,
		Daddr:   []byte{93, 184, 216, 34},
		Saddr:   []byte{10, 0, 0, 5},
		Dport:   []byte{0x01, 0xbb}, // 443, network order
		Sport:   []byte{0xc3, 0x50}, // 50000
	}
	ev, ok := r.toNetworkEvent(time.Unix(0, 0))
	if !ok {
		t.Fatal("connect must be forwarded")
	}
	if ev.Operation != "connect" || ev.Protocol != "tcp" ||
		ev.RemoteAddr != "93.184.216.34" || ev.RemotePort != 443 ||
		ev.LocalAddr != "10.0.0.5" || ev.LocalPort != 50000 || ev.PID != 1234 {
		t.Fatalf("unexpected event: %+v", ev)
	}
}

func TestNetRecordIPv6AndMapped(t *testing.T) {
	v6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	r := &netRecord{EventID: netEventTCPAccept6, Daddr: v6, Saddr: v6, Dport: []byte{0, 22}, Sport: []byte{0, 80}}
	ev, ok := r.toNetworkEvent(time.Now())
	if !ok || ev.Operation != "accept" || ev.Protocol != "tcp6" || ev.RemoteAddr != "2001:db8::1" || ev.RemotePort != 22 {
		t.Fatalf("unexpected IPv6 event: %+v ok=%v", ev, ok)
	}

	mapped := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1}
	r = &netRecord{EventID: netEventUDPSend6, Daddr: mapped, Dport: []byte{0, 53}}
	ev, ok = r.toNetworkEvent(time.Now())
	if !ok || ev.Operation != "sendto" || ev.RemoteAddr != "192.168.1.1" || ev.Protocol != "udp" {
		t.Fatalf("IPv4-mapped address must be unmapped: %+v", ev)
	}
}

func TestNetRecordIgnoredAndMalformed(t *testing.T) {
	// 10 = TCP send data: not forwarded.
	if _, ok := (&netRecord{EventID: 10, Daddr: []byte{1, 2, 3, 4}}).toNetworkEvent(time.Now()); ok {
		t.Fatal("data send events must be dropped")
	}
	if _, ok := (&netRecord{EventID: netEventTCPConnect4, Daddr: []byte{1, 2, 3}}).toNetworkEvent(time.Now()); ok {
		t.Fatal("malformed address must be dropped")
	}
}

func TestFileOperation(t *testing.T) {
	cases := []struct {
		r    fileRecord
		want string
	}{
		{fileRecord{EventID: fileEventCreate, CreateOptions: 1 << 24}, "open"}, // FILE_OPEN
		{fileRecord{EventID: fileEventCreate, CreateOptions: 2 << 24}, "create"},
		{fileRecord{EventID: fileEventCreate, CreateOptions: 3 << 24}, "open"}, // FILE_OPEN_IF
		{fileRecord{EventID: fileEventCreateNewFile}, "create"},
		{fileRecord{EventID: fileEventWrite}, "write"},
		{fileRecord{EventID: fileEventDeletePath}, "delete"},
		{fileRecord{EventID: fileEventRenamePath}, "rename"},
	}
	for _, c := range cases {
		got, ok := fileOperation(&c.r)
		if !ok || got != c.want {
			t.Errorf("fileOperation(%+v) = %q,%v want %q", c.r, got, ok, c.want)
		}
	}
	if _, ok := fileOperation(&fileRecord{EventID: 15}); ok {
		t.Error("reads are not forwarded")
	}
}

func TestFileObjectTable(t *testing.T) {
	ft := newFileObjectTable()
	ft.opened(0xabc, `\Device\HarddiskVolume1\a.txt`)

	path, first, ok := ft.firstWrite(0xabc)
	if !ok || !first || path != `\Device\HarddiskVolume1\a.txt` {
		t.Fatalf("first write = %q %v %v", path, first, ok)
	}
	if _, first, _ = ft.firstWrite(0xabc); first {
		t.Fatal("second write to the same handle must be suppressed")
	}
	// FileObject reuse after close resets the write state.
	ft.opened(0xabc, `\Device\HarddiskVolume1\b.txt`)
	if path, first, _ = ft.firstWrite(0xabc); !first || path != `\Device\HarddiskVolume1\b.txt` {
		t.Fatalf("reused FileObject = %q %v", path, first)
	}
	if _, _, ok = ft.firstWrite(0xdead); ok {
		t.Fatal("unknown FileObject must not resolve")
	}

	for i := uint64(1); i <= maxFileObjects+10; i++ {
		ft.opened(i<<8, "p")
	}
	if len(ft.entries) > maxFileObjects || len(ft.order) > maxFileObjects {
		t.Fatalf("table grew to %d/%d", len(ft.entries), len(ft.order))
	}
}

func TestUDPDeduper(t *testing.T) {
	d := newUDPDeduper()
	now := time.Unix(100, 0)
	if !d.first(1, "8.8.8.8", 53, now) {
		t.Fatal("first send must pass")
	}
	if d.first(1, "8.8.8.8", 53, now.Add(time.Second)) {
		t.Fatal("repeat within window must be suppressed")
	}
	if !d.first(2, "8.8.8.8", 53, now) {
		t.Fatal("different pid is a different flow")
	}
	if !d.first(1, "8.8.8.8", 53, now.Add(udpDedupWindow+time.Second)) {
		t.Fatal("send after window must pass")
	}
}

func TestProviderKeywords(t *testing.T) {
	if ProviderNetwork.Keywords()&netKeywordIPv6 == 0 {
		t.Error("network provider must include IPv6")
	}
	if ProviderFile.Keywords()&0x100 != 0 {
		t.Error("file reads must not be subscribed")
	}
}
