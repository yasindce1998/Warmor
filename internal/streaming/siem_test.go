package streaming

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestToCEF_DenyEvent(t *testing.T) {
	event := &SecurityEvent{
		EventType: "file_open",
		Decision:  "deny",
		Hostname:  "node-1",
		PID:       4321,
		UID:       1000,
		Comm:      "malware",
		Filename:  "/etc/shadow",
		Reason:    "policy violation",
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
	}

	cef := ToCEF(event)

	if !strings.HasPrefix(cef, "CEF:0|Warmor|warmor-agent|1.0|") {
		t.Errorf("bad CEF prefix: %s", cef)
	}
	if !strings.Contains(cef, "|file_open|file_open_deny|8|") {
		t.Errorf("expected signatureID, name, severity=8: %s", cef)
	}
	if !strings.Contains(cef, "src=node-1") {
		t.Error("missing src field")
	}
	if !strings.Contains(cef, "dvcpid=4321") {
		t.Error("missing dvcpid field")
	}
	if !strings.Contains(cef, "filePath=/etc/shadow") {
		t.Error("missing filePath field")
	}
	if !strings.Contains(cef, "msg=policy violation") {
		t.Error("missing msg field")
	}
}

func TestToCEF_AllowEvent(t *testing.T) {
	event := &SecurityEvent{
		EventType: "socket_connect",
		Decision:  "allow",
		Hostname:  "node-2",
		PID:       100,
		UID:       0,
		Comm:      "curl",
		Timestamp: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
	}

	cef := ToCEF(event)
	if !strings.Contains(cef, "|1|") {
		t.Errorf("expected severity=1 for allow: %s", cef)
	}
}

func TestToCEF_NetworkEvent(t *testing.T) {
	event := &SecurityEvent{
		EventType:  "socket_connect",
		Decision:   "log",
		Hostname:   "node-3",
		PID:        555,
		UID:        1000,
		Comm:       "wget",
		RemoteAddr: "93.184.216.34",
		RemotePort: 443,
		LocalPort:  54321,
		Protocol:   "tcp",
		Timestamp:  time.Date(2024, 3, 20, 12, 0, 0, 0, time.UTC),
	}

	cef := ToCEF(event)
	if !strings.Contains(cef, "dst=93.184.216.34") {
		t.Error("missing dst field")
	}
	if !strings.Contains(cef, "dpt=443") {
		t.Error("missing dpt field")
	}
	if !strings.Contains(cef, "spt=54321") {
		t.Error("missing spt field")
	}
	if !strings.Contains(cef, "proto=tcp") {
		t.Error("missing proto field")
	}
}

func TestCEFEscape(t *testing.T) {
	event := &SecurityEvent{
		EventType: "file_open",
		Decision:  "deny",
		Hostname:  "h",
		Comm:      "cat",
		Filename:  `/path/with|pipe\and=equals`,
		Timestamp: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	cef := ToCEF(event)
	if strings.Contains(cef, `/path/with|pipe\and=equals`) {
		t.Error("CEF special chars should be escaped")
	}
	if !strings.Contains(cef, `\\|`) || !strings.Contains(cef, `\\=`) {
		t.Logf("CEF: %s", cef)
	}
}

func TestCEFSeverity(t *testing.T) {
	tests := []struct {
		decision string
		expected int
	}{
		{"deny", 8},
		{"log", 4},
		{"allow", 1},
		{"", 0},
		{"unknown", 0},
	}
	for _, tc := range tests {
		if got := CEFSeverity(tc.decision); got != tc.expected {
			t.Errorf("CEFSeverity(%q) = %d, want %d", tc.decision, got, tc.expected)
		}
	}
}

func TestCEFSink(t *testing.T) {
	var mu sync.Mutex
	var messages []string

	sink := NewCEFSink("test", func(msg string) error {
		mu.Lock()
		messages = append(messages, msg)
		mu.Unlock()
		return nil
	})

	event := &SecurityEvent{
		EventType: "exec",
		Decision:  "deny",
		Hostname:  "test-host",
		PID:       1,
		Comm:      "bash",
		Timestamp: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	if err := sink.Write(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
	if !strings.HasPrefix(messages[0], "CEF:0|") {
		t.Errorf("message not CEF: %s", messages[0])
	}
	if sink.Name() != "cef:test" {
		t.Errorf("unexpected name: %s", sink.Name())
	}
}

func TestSyslogSink_Integration(t *testing.T) {
	// Start a UDP listener to act as a syslog server
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	sink, err := NewSyslogSink(SyslogConfig{
		Network: "udp",
		Addr:    pc.LocalAddr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	event := &SecurityEvent{
		EventType: "exec",
		Decision:  "deny",
		Hostname:  "test-host",
		PID:       42,
		UID:       0,
		Comm:      "exploit",
		Filename:  "/tmp/payload",
		Reason:    "blocked",
		Timestamp: time.Date(2024, 6, 15, 14, 30, 0, 0, time.UTC),
	}

	if err := sink.Write(context.Background(), event); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 4096)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}

	msg := string(buf[:n])
	if !strings.Contains(msg, "CEF:0|Warmor|") {
		t.Errorf("syslog message missing CEF: %s", msg)
	}
	if !strings.Contains(msg, "warmor:") {
		t.Errorf("syslog message missing app tag: %s", msg)
	}
	if !strings.Contains(msg, "dvcpid=42") {
		t.Errorf("syslog message missing PID: %s", msg)
	}
	if sink.Name() != "syslog:udp://"+pc.LocalAddr().String() {
		t.Errorf("unexpected sink name: %s", sink.Name())
	}
}

func TestSyslogSeverity(t *testing.T) {
	tests := map[string]int{"deny": 2, "log": 5, "allow": 6, "": 6, "other": 6}
	for decision, want := range tests {
		if got := syslogSeverity(decision); got != want {
			t.Errorf("syslogSeverity(%q) = %d, want %d", decision, got, want)
		}
	}
}

func TestSyslogSink_Defaults(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	sink, err := NewSyslogSink(SyslogConfig{Addr: pc.LocalAddr().String()})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if sink.network != "udp" {
		t.Errorf("expected default network udp, got %s", sink.network)
	}
	if sink.facility != 1 {
		t.Errorf("expected default facility 1, got %d", sink.facility)
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Errorf("flush: %v", err)
	}

	// PRI = facility*8 + severity. Allow -> 1*8+6 = 14.
	ev := &SecurityEvent{EventType: "exec", Decision: "allow", Hostname: "h", Timestamp: time.Now()}
	if err := sink.Write(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if msg := string(buf[:n]); !strings.HasPrefix(msg, "<14>") || !strings.HasSuffix(msg, "\n") {
		t.Errorf("unexpected syslog framing: %q", msg)
	}
}

func TestSyslogSink_ConnectError(t *testing.T) {
	if _, err := NewSyslogSink(SyslogConfig{Network: "bogus", Addr: "127.0.0.1:1"}); err == nil {
		t.Fatal("expected error for unknown network")
	}

	// A TCP port with nothing listening must fail to connect.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if _, err := NewSyslogSink(SyslogConfig{Network: "tcp", Addr: addr}); err == nil {
		t.Fatal("expected connection refused")
	}
}

func TestSyslogSink_TCPWriteErrorAndReconnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	received := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					received <- line
				}
			}(c)
		}
	}()

	sink, err := NewSyslogSink(SyslogConfig{Network: "tcp", Addr: ln.Addr().String(), Facility: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	ev := &SecurityEvent{EventType: "exec", Decision: "deny", Hostname: "h", Comm: "x", Timestamp: time.Now()}

	// Break the underlying connection: the next write fails and the conn is dropped.
	sink.mu.Lock()
	_ = sink.conn.Close()
	sink.mu.Unlock()
	if err := sink.Write(context.Background(), ev); err == nil || !strings.Contains(err.Error(), "syslog write") {
		t.Fatalf("expected syslog write error, got %v", err)
	}
	sink.mu.Lock()
	if sink.conn != nil {
		t.Error("expected conn to be reset after write failure")
	}
	sink.mu.Unlock()

	// Next write reconnects transparently.
	if err := sink.Write(context.Background(), ev); err != nil {
		t.Fatalf("expected reconnect to succeed, got %v", err)
	}
	select {
	case line := <-received:
		// facility 4 * 8 + deny severity 2 = 34
		if !strings.HasPrefix(line, "<34>") {
			t.Errorf("unexpected PRI: %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for reconnected syslog message")
	}

	// Reconnect failure: drop conn and stop listener.
	sink.mu.Lock()
	_ = sink.conn.Close()
	sink.conn = nil
	sink.mu.Unlock()
	ln.Close()
	if err := sink.Write(context.Background(), ev); err == nil || !strings.Contains(err.Error(), "reconnect") {
		t.Fatalf("expected reconnect error, got %v", err)
	}
	// Close with nil conn is a no-op.
	if err := sink.Close(); err != nil {
		t.Errorf("close with nil conn: %v", err)
	}
}

func TestCEFSink_FlushCloseAndError(t *testing.T) {
	wantErr := errors.New("downstream failed")
	sink := NewCEFSink("err", func(string) error { return wantErr })
	if err := sink.Write(context.Background(), &SecurityEvent{}); !errors.Is(err, wantErr) {
		t.Errorf("expected write error to propagate, got %v", err)
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Errorf("flush: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestToCEF_OptionalFieldsOmitted(t *testing.T) {
	cef := ToCEF(&SecurityEvent{EventType: "exec", Decision: "unknown", Timestamp: time.UnixMilli(1234)})
	for _, field := range []string{"filePath=", "dst=", "dpt=", "spt=", "proto=", "msg="} {
		if strings.Contains(cef, field) {
			t.Errorf("expected %s to be omitted: %s", field, cef)
		}
	}
	if !strings.Contains(cef, "|exec|exec_unknown|0|") {
		t.Errorf("expected severity 0 for unknown decision: %s", cef)
	}
	if !strings.HasSuffix(cef, "rt=1234") {
		t.Errorf("expected rt as final extension: %s", cef)
	}
}

func TestToCEF_EscapesFilenameAndReason(t *testing.T) {
	cef := ToCEF(&SecurityEvent{
		EventType: "file",
		Decision:  "deny",
		Filename:  "/tmp/a=b|c",
		Reason:    "line1\nline2",
	})
	// '|' needs no escaping in extension values; only '\\' and '=' do.
	if !strings.Contains(cef, `filePath=/tmp/a\=b|c`) {
		t.Errorf("filename not escaped: %s", cef)
	}
	if strings.Contains(cef, "\n") {
		t.Errorf("newline leaked into CEF output: %q", cef)
	}
	if !strings.Contains(cef, `msg=line1\nline2`) {
		t.Errorf("newline not encoded as \\n: %s", cef)
	}
}

// hostileEvent carries injection attempts in every attacker-influenced field.
func hostileEvent() *SecurityEvent {
	return &SecurityEvent{
		EventType:  "exec|x",
		Decision:   "deny",
		Hostname:   "host dst=6.6.6.6\n<13>fake",
		Comm:       "sh dst=1.2.3.4",
		Filename:   "/tmp/x\n<13>Jan 1 00:00:00 evil warmor: CEF:0|forged",
		RemoteAddr: "10.0.0.1 act=allow",
		Protocol:   "tcp\r\nproto=udp",
		Reason:     "a|b\\",
		Timestamp:  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// cefExtensionKeys parses the extension section of a CEF record the way a
// SIEM does (keys are tokens immediately followed by an unescaped '=') and
// returns the keys in order.
func cefExtensionKeys(t *testing.T, cef string) []string {
	t.Helper()
	// Skip the 7 header fields, honouring \| and \\ escapes.
	fields, i := 0, 0
	for ; i < len(cef) && fields < 7; i++ {
		switch cef[i] {
		case '\\':
			i++
		case '|':
			fields++
		}
	}
	if fields != 7 {
		t.Fatalf("CEF header has %d unescaped separators, want 7: %s", fields, cef)
	}
	var keys []string
	ext := cef[i:]
	start := 0 // start of the current whitespace-delimited token
	for j := 0; j < len(ext); j++ {
		switch ext[j] {
		case '\\':
			j++
		case ' ':
			start = j + 1
		case '=':
			keys = append(keys, ext[start:j])
		}
	}
	return keys
}

func TestToCEF_HostileValuesCannotInjectFields(t *testing.T) {
	cef := ToCEF(hostileEvent())

	if strings.ContainsAny(cef, "\r\n") {
		t.Fatalf("raw line break in CEF output: %q", cef)
	}
	want := []string{"src", "dvcpid", "duser", "cs1", "cs1Label", "filePath", "dst", "proto", "msg", "rt"}
	got := cefExtensionKeys(t, cef)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("extension keys = %v, want %v\n%s", got, want, cef)
	}
	for _, sub := range []string{
		`cs1=sh dst\=1.2.3.4 `,
		`dst=10.0.0.1 act\=allow `,
		`proto=tcp\r\nproto\=udp `,
		`msg=a|b\\ `,
		`|exec\|x|exec\|x_deny|`,
	} {
		if !strings.Contains(cef, sub) {
			t.Errorf("CEF missing %q: %s", sub, cef)
		}
	}
}

func TestCEFHeaderEscape(t *testing.T) {
	if got := cefHeaderEscape("a|b\\c\nd\re"); got != `a\|b\\c d e` {
		t.Errorf("cefHeaderEscape = %q", got)
	}
}

func TestSyslogHostname(t *testing.T) {
	for in, want := range map[string]string{
		"":           "-",
		"node-1":     "node-1",
		"a b\n<13>c": "a_b_<13>c",
		"x\ty\x7f":   "x_y_",
	} {
		if got := syslogHostname(in); got != want {
			t.Errorf("syslogHostname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSyslogSink_HostileValuesStayOnOneLine(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		// Read everything until the sink closes the connection.
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				break
			}
		}
		received <- sb.String()
	}()

	sink, err := NewSyslogSink(SyslogConfig{Network: "tcp", Addr: ln.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(context.Background(), hostileEvent()); err != nil {
		t.Fatal(err)
	}
	_ = sink.Close()

	var data string
	select {
	case data = <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for syslog data")
	}
	lines := strings.Split(strings.TrimSuffix(data, "\n"), "\n")
	if len(lines) != 1 || strings.Contains(data, "\r") {
		t.Fatalf("hostile event produced %d syslog records: %q", len(lines), data)
	}
	// Header: <PRI>TIMESTAMP HOSTNAME TAG: - the hostname must be one token.
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) != 3 || parts[1] != "host_dst=6.6.6.6_<13>fake" || !strings.HasPrefix(parts[2], "warmor: CEF:0|") {
		t.Errorf("syslog header was corrupted: %q", lines[0])
	}
}
