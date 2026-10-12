//go:build windows
// +build windows

package logging

import (
	"io"

	"golang.org/x/sys/windows/svc/eventlog"
)

// EventLogWriter implements io.Writer by forwarding messages to the Windows Event Log.
// It maps zerolog JSON severity to Event Viewer levels (Info/Warning/Error).
type EventLogWriter struct {
	elog *eventlog.Log
}

// NewEventLogWriter opens a connection to the Windows Event Log for the given source.
// The event source must be registered beforehand (see eventlog.InstallAsEventCreate).
func NewEventLogWriter(source string) (*EventLogWriter, error) {
	elog, err := eventlog.Open(source)
	if err != nil {
		return nil, err
	}
	return &EventLogWriter{elog: elog}, nil
}

// Write sends the log line to the Windows Event Log at the severity zerolog
// recorded in it. zerolog writes complete JSON lines; we log the raw JSON to
// preserve structured data.
func (w *EventLogWriter) Write(p []byte) (int, error) {
	msg := string(p)
	switch eventLogLevel(p) {
	case levelError:
		_ = w.elog.Error(1, msg)
	case levelWarning:
		_ = w.elog.Warning(1, msg)
	default:
		_ = w.elog.Info(1, msg)
	}
	return len(p), nil
}

// Close releases the event log handle.
func (w *EventLogWriter) Close() error {
	return w.elog.Close()
}

// NewLoggerWithEventLog creates a logger that writes to both the given writer
// and the Windows Event Log.
func NewLoggerWithEventLog(level string, w io.Writer, source string) (*Logger, error) {
	elw, err := NewEventLogWriter(source)
	if err != nil {
		return nil, err
	}
	multi := io.MultiWriter(w, elw)
	return NewLoggerWithWriter(level, multi), nil
}
