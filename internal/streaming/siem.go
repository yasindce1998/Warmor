package streaming

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// CEFSeverity maps policy decisions to CEF severity levels (0-10).
func CEFSeverity(decision string) int {
	switch decision {
	case "deny":
		return 8
	case "log":
		return 4
	case "allow":
		return 1
	default:
		return 0
	}
}

// ToCEF converts a SecurityEvent to Common Event Format (CEF) string.
// Format: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions
func ToCEF(event *SecurityEvent) string {
	severity := CEFSeverity(event.Decision)
	signatureID := cefHeaderEscape(event.EventType)
	name := cefHeaderEscape(fmt.Sprintf("%s_%s", event.EventType, event.Decision))

	// Every extension value is escaped: an unescaped '=' or newline in an
	// attacker-controlled field (comm, filename, ...) could otherwise forge
	// additional key=value pairs or whole syslog records.
	var ext strings.Builder
	fmt.Fprintf(&ext, "src=%s ", cefEscape(event.Hostname))
	fmt.Fprintf(&ext, "dvcpid=%d ", event.PID)
	fmt.Fprintf(&ext, "duser=%d ", event.UID)
	fmt.Fprintf(&ext, "cs1=%s cs1Label=comm ", cefEscape(event.Comm))

	if event.Filename != "" {
		fmt.Fprintf(&ext, "filePath=%s ", cefEscape(event.Filename))
	}
	if event.RemoteAddr != "" {
		fmt.Fprintf(&ext, "dst=%s ", cefEscape(event.RemoteAddr))
	}
	if event.RemotePort > 0 {
		fmt.Fprintf(&ext, "dpt=%d ", event.RemotePort)
	}
	if event.LocalPort > 0 {
		fmt.Fprintf(&ext, "spt=%d ", event.LocalPort)
	}
	if event.Protocol != "" {
		fmt.Fprintf(&ext, "proto=%s ", cefEscape(event.Protocol))
	}
	if event.Reason != "" {
		fmt.Fprintf(&ext, "msg=%s ", cefEscape(event.Reason))
	}
	fmt.Fprintf(&ext, "rt=%d", event.Timestamp.UnixMilli())

	return fmt.Sprintf("CEF:0|Warmor|warmor-agent|1.0|%s|%s|%d|%s",
		signatureID, name, severity, strings.TrimSpace(ext.String()))
}

var cefExtReplacer = strings.NewReplacer(
	"\\", "\\\\",
	"=", "\\=",
	"\n", "\\n",
	"\r", "\\r",
)

// cefEscape escapes a CEF extension value: backslash and '=' are
// backslash-escaped and CR/LF are encoded as the literal sequences \r and \n,
// so a value can neither start a new key nor break the record.
func cefEscape(s string) string {
	return cefExtReplacer.Replace(s)
}

var cefHeaderReplacer = strings.NewReplacer(
	"\\", "\\\\",
	"|", "\\|",
	"\n", " ",
	"\r", " ",
)

// cefHeaderEscape escapes a CEF header field: backslash and '|' are
// backslash-escaped. Line breaks are not representable in the header, so
// they are replaced with spaces.
func cefHeaderEscape(s string) string {
	return cefHeaderReplacer.Replace(s)
}

// syslogHostname makes a value safe for the HOSTNAME field of a syslog
// header, which must be a single token: whitespace and control characters
// are replaced and an empty value becomes the RFC 5424 nil value "-".
func syslogHostname(s string) string {
	if s == "" {
		return "-"
	}
	return strings.Map(func(r rune) rune {
		if r <= ' ' || r == 0x7f {
			return '_'
		}
		return r
	}, s)
}

// SyslogSink sends events to a syslog server over UDP or TCP in CEF format.
type SyslogSink struct {
	network  string
	addr     string
	facility int
	conn     net.Conn
	mu       sync.Mutex
}

// SyslogConfig configures the syslog SIEM sink.
type SyslogConfig struct {
	Network  string // "udp" or "tcp"
	Addr     string // host:port
	Facility int    // syslog facility (default 1 = LOG_USER)
}

// NewSyslogSink creates a sink that writes CEF-formatted events to syslog.
func NewSyslogSink(cfg SyslogConfig) (*SyslogSink, error) {
	if cfg.Network == "" {
		cfg.Network = "udp"
	}
	if cfg.Facility <= 0 {
		cfg.Facility = 1 // LOG_USER
	}

	conn, err := net.DialTimeout(cfg.Network, cfg.Addr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("syslog connect %s://%s: %w", cfg.Network, cfg.Addr, err)
	}

	return &SyslogSink{
		network:  cfg.Network,
		addr:     cfg.Addr,
		facility: cfg.Facility,
		conn:     conn,
	}, nil
}

func (s *SyslogSink) Write(_ context.Context, event *SecurityEvent) error {
	cef := ToCEF(event)
	pri := s.facility*8 + syslogSeverity(event.Decision)
	msg := fmt.Sprintf("<%d>%s %s warmor: %s\n",
		pri,
		event.Timestamp.Format(time.RFC3339),
		syslogHostname(event.Hostname),
		cef,
	)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn == nil {
		conn, err := net.DialTimeout(s.network, s.addr, 5*time.Second)
		if err != nil {
			return fmt.Errorf("syslog reconnect: %w", err)
		}
		s.conn = conn
	}

	_, err := s.conn.Write([]byte(msg))
	if err != nil {
		s.conn.Close()
		s.conn = nil
		return fmt.Errorf("syslog write: %w", err)
	}
	return nil
}

func (s *SyslogSink) Flush(_ context.Context) error { return nil }

func (s *SyslogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *SyslogSink) Name() string {
	return fmt.Sprintf("syslog:%s://%s", s.network, s.addr)
}

func syslogSeverity(decision string) int {
	switch decision {
	case "deny":
		return 2 // LOG_CRIT
	case "log":
		return 5 // LOG_NOTICE
	default:
		return 6 // LOG_INFO
	}
}

// CEFSink writes CEF-formatted events to any io.Writer (for testing or file output).
type CEFSink struct {
	write func(string) error
	mu    sync.Mutex
	name  string
}

// NewCEFSink creates a CEF sink that calls the given write function for each event.
func NewCEFSink(name string, writeFn func(string) error) *CEFSink {
	return &CEFSink{write: writeFn, name: name}
}

func (s *CEFSink) Write(_ context.Context, event *SecurityEvent) error {
	cef := ToCEF(event)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.write(cef)
}

func (s *CEFSink) Flush(_ context.Context) error { return nil }
func (s *CEFSink) Close() error                  { return nil }
func (s *CEFSink) Name() string                  { return "cef:" + s.name }
