package logging

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Logger wraps zerolog with warmor-specific methods
type Logger struct {
	logger zerolog.Logger
}

// NewLogger creates a new logger with the specified level, writing to os.Stdout.
func NewLogger(level string) *Logger {
	return NewLoggerWithWriter(level, os.Stdout)
}

// NewLoggerWithWriter creates a new logger with the specified level and output writer.
func NewLoggerWithWriter(level string, w io.Writer) *Logger {
	zerolog.TimeFieldFormat = time.RFC3339Nano

	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		logLevel = zerolog.InfoLevel
	}

	logger := zerolog.New(w).
		Level(logLevel).
		With().
		Timestamp().
		Str("service", "warmor").
		Logger()

	return &Logger{logger: logger}
}

// LogEvent logs a policy evaluation event
func (l *Logger) LogEvent(event *api.Event, result *api.ActionResult) {
	e := l.logger.Info().
		Uint32("pid", event.PID).
		Uint32("uid", event.UID).
		Uint32("gid", event.GID).
		Str("comm", event.Comm).
		Str("filename", event.Filename).
		Str("action", result.Action.String()).
		Str("reason", result.Reason).
		Bool("cached", result.Cached).
		Dur("latency_us", result.Latency)
	if result.Audit {
		e = e.Bool("audit", true)
	}
	e.Msg("policy_evaluation")
}

// LogDenial logs a denied action
func (l *Logger) LogDenial(event *api.Event, result *api.ActionResult) {
	e := l.logger.Warn().
		Uint32("pid", event.PID).
		Uint32("uid", event.UID).
		Str("comm", event.Comm).
		Str("filename", event.Filename).
		Str("reason", result.Reason)
	if result.Audit {
		e = e.Bool("audit", true)
	}
	e.Msg("action_denied")
}

// LogError logs an error
func (l *Logger) LogError(err error, msg string) {
	l.logger.Error().
		Err(err).
		Msg(msg)
}

// LogInfo logs an informational message
func (l *Logger) LogInfo(msg string) {
	l.logger.Info().Msg(msg)
}

// LogStats logs enforcement statistics
func (l *Logger) LogStats(stats *api.EnforcementStats) {
	total := stats.Allowed + stats.Denied + stats.Logged
	var avgLatency time.Duration
	if total > 0 {
		avgLatency = stats.TotalLatency / time.Duration(total)
	}

	l.logger.Info().
		Uint64("allowed", stats.Allowed).
		Uint64("denied", stats.Denied).
		Uint64("logged", stats.Logged).
		Uint64("audit_denied", stats.AuditDenied).
		Uint64("cache_hits", stats.CacheHits).
		Uint64("cache_misses", stats.CacheMisses).
		Dur("avg_latency", avgLatency).
		Msg("enforcement_stats")
}

// LogStartup logs startup information
func (l *Logger) LogStartup(policyPath string) {
	l.logger.Info().
		Str("policy", policyPath).
		Msg("warmor_starting")
}

// LogShutdown logs shutdown information
func (l *Logger) LogShutdown() {
	l.logger.Info().Msg("warmor_shutting_down")
}

// Level returns the minimum level this logger emits (e.g. "info").
func (l *Logger) Level() string {
	return l.logger.GetLevel().String()
}
