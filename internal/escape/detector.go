package escape

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Alert represents a detected escape attempt.
type Alert struct {
	Timestamp   time.Time   `json:"timestamp"`
	TechniqueID TechniqueID `json:"technique_id"`
	Name        string      `json:"name"`
	Severity    Severity    `json:"severity"`
	CgroupID    uint64      `json:"cgroup_id"`
	PID         uint32      `json:"pid"`
	Comm        string      `json:"comm"`
	Details     string      `json:"details"`
}

// DetectorConfig configures the escape detector.
type DetectorConfig struct {
	Patterns      []*Pattern
	DenyOnDetect  bool
	AlertCallback func(*Alert)
	// IsContainer limits detection to container cgroups. Escape techniques
	// are only escapes from inside a container: a host administrator running
	// nsenter or mounting a disk is not one. Nil treats every non-zero
	// cgroup as a container (tests, or a daemon scoped by --cgroup-filter).
	IsContainer func(cgroupID uint64) bool
}

// Detector correlates security events against known container escape patterns.
// It maintains per-cgroup sliding windows for multi-step pattern matching.
type Detector struct {
	patterns      []*Pattern
	denyOnDetect  bool
	alertCallback func(*Alert)
	isContainer   func(uint64) bool

	windows   map[uint64]*cgroupWindow
	windowsMu sync.Mutex
	sweptSize int
	lastSweep time.Time

	alerts   []*Alert
	alertsMu sync.Mutex
}

type cgroupWindow struct {
	events []windowEvent
}

type windowEvent struct {
	view      EventView
	timestamp time.Time
}

// NewDetector creates an escape detector with the given configuration.
func NewDetector(cfg DetectorConfig) *Detector {
	patterns := cfg.Patterns
	if patterns == nil {
		patterns = DefaultPatterns()
	}
	return &Detector{
		patterns:      patterns,
		denyOnDetect:  cfg.DenyOnDetect,
		alertCallback: cfg.AlertCallback,
		isContainer:   cfg.IsContainer,
		windows:       make(map[uint64]*cgroupWindow),
	}
}

// maxAlerts bounds the in-memory alert history (Alerts); older alerts are
// dropped. Every alert is still delivered to AlertCallback.
const maxAlerts = 1024

// windowTTL is how long a cgroup's event window is kept without new events.
// It must cover the longest multi-step pattern window.
const windowTTL = 30 * time.Second

func (d *Detector) inScope(cgroupID uint64) bool {
	if cgroupID == 0 {
		return false
	}
	return d.isContainer == nil || d.isContainer(cgroupID)
}

func viewOf(event *streaming.SecurityEvent) EventView {
	return EventView{
		EventType:          event.EventType,
		Comm:               event.Comm,
		Filename:           event.Filename,
		CgroupID:           event.CgroupID,
		PID:                event.PID,
		PPID:               event.PPID,
		UID:                event.UID,
		MountType:          event.MountType,
		MountSource:        event.MountSource,
		PtraceComm:         event.PtraceComm,
		PtraceTargetCgroup: event.PtraceTargetCgroup,
		RemoteAddr:         event.RemoteAddr,
		LocalPort:          event.LocalPort,
	}
}

// CheckEvent evaluates a security event against all escape patterns and
// records an alert for each match. It returns a deny result when a pattern
// matched and deny mode is on, nil otherwise. Events outside a container
// are ignored.
func (d *Detector) CheckEvent(_ context.Context, event *streaming.SecurityEvent) *api.ActionResult {
	if !d.inScope(event.CgroupID) {
		return nil
	}

	view := viewOf(event)
	now := time.Now()

	var deny *api.ActionResult
	for _, pattern := range d.patterns {
		if !d.matchPattern(pattern, event.CgroupID, view, now) {
			continue
		}
		d.recordAlert(&Alert{
			Timestamp:   now,
			TechniqueID: pattern.ID,
			Name:        pattern.Name,
			Severity:    pattern.Severity,
			CgroupID:    event.CgroupID,
			PID:         event.PID,
			Comm:        event.Comm,
			Details:     fmt.Sprintf("%s: %s (file=%s)", pattern.ID, pattern.Description, event.Filename),
		})
		if d.denyOnDetect && deny == nil {
			deny = &api.ActionResult{
				Action:    api.ActionDeny,
				Reason:    fmt.Sprintf("escape detected: %s (%s)", pattern.Name, pattern.ID),
				Timestamp: now,
			}
		}
	}

	d.recordEvent(event.CgroupID, view, now)
	return deny
}

func (d *Detector) matchPattern(pattern *Pattern, cgroupID uint64, current EventView, now time.Time) bool {
	if len(pattern.Steps) == 0 {
		return false
	}

	// Single-step patterns: just match the current event
	if len(pattern.Steps) == 1 {
		step := pattern.Steps[0]
		return step.EventType == current.EventType && step.Match(&current)
	}

	// Multi-step: check if last step matches current, and prior steps are in window
	lastStep := pattern.Steps[len(pattern.Steps)-1]
	if lastStep.EventType != current.EventType || !lastStep.Match(&current) {
		return false
	}

	d.windowsMu.Lock()
	w := d.windows[cgroupID]
	d.windowsMu.Unlock()

	if w == nil {
		return false
	}

	// Walk prior steps backwards through the window
	priorSteps := pattern.Steps[:len(pattern.Steps)-1]
	matched := make([]bool, len(priorSteps))

	for i := len(w.events) - 1; i >= 0; i-- {
		ev := w.events[i]
		if pattern.Window > 0 && now.Sub(ev.timestamp) > pattern.Window {
			break
		}
		for j, step := range priorSteps {
			if matched[j] {
				continue
			}
			if step.EventType == ev.view.EventType && step.Match(&ev.view) {
				matched[j] = true
			}
		}
	}

	for _, m := range matched {
		if !m {
			return false
		}
	}
	return true
}

func (d *Detector) recordEvent(cgroupID uint64, view EventView, now time.Time) {
	d.windowsMu.Lock()
	defer d.windowsMu.Unlock()

	w, ok := d.windows[cgroupID]
	if !ok {
		w = &cgroupWindow{}
		d.windows[cgroupID] = w
	}

	w.events = append(w.events, windowEvent{view: view, timestamp: now})

	cutoff := now.Add(-windowTTL)
	trimIdx := 0
	for trimIdx < len(w.events) && w.events[trimIdx].timestamp.Before(cutoff) {
		trimIdx++
	}
	if trimIdx > 0 {
		w.events = w.events[trimIdx:]
	}

	// Containers come and go; drop windows that have gone quiet so the map
	// doesn't grow with every container ever seen. Amortized: when the map
	// has doubled since the last sweep, or a window TTL has passed.
	if len(d.windows) > 2*d.sweptSize+64 || now.Sub(d.lastSweep) >= windowTTL {
		d.lastSweep = now
		for id, cw := range d.windows {
			if n := len(cw.events); n == 0 || cw.events[n-1].timestamp.Before(cutoff) {
				delete(d.windows, id)
			}
		}
		d.sweptSize = len(d.windows)
	}
}

func (d *Detector) recordAlert(alert *Alert) {
	d.alertsMu.Lock()
	d.alerts = append(d.alerts, alert)
	if len(d.alerts) > maxAlerts {
		d.alerts = append(d.alerts[:0:0], d.alerts[len(d.alerts)-maxAlerts:]...)
	}
	d.alertsMu.Unlock()

	if d.alertCallback != nil {
		d.alertCallback(alert)
	}
}

// Alerts returns all recorded escape alerts.
func (d *Detector) Alerts() []*Alert {
	d.alertsMu.Lock()
	defer d.alertsMu.Unlock()
	out := make([]*Alert, len(d.alerts))
	copy(out, d.alerts)
	return out
}

// ClearAlerts removes all recorded alerts.
func (d *Detector) ClearAlerts() {
	d.alertsMu.Lock()
	d.alerts = nil
	d.alertsMu.Unlock()
}

// ClearWindow removes the event window for a specific cgroup.
func (d *Detector) ClearWindow(cgroupID uint64) {
	d.windowsMu.Lock()
	delete(d.windows, cgroupID)
	d.windowsMu.Unlock()
}

// Enrich implements streaming.Enricher: it labels events that match an
// escape pattern. It does not record alerts or update windows (CheckEvent
// does), so it can run alongside CheckEvent without double counting.
func (d *Detector) Enrich(event *streaming.SecurityEvent) {
	if !d.inScope(event.CgroupID) {
		return
	}
	view := viewOf(event)
	for _, pattern := range d.patterns {
		if d.matchPattern(pattern, event.CgroupID, view, time.Now()) {
			if event.Labels == nil {
				event.Labels = make(map[string]string)
			}
			event.Labels["escape_technique"] = string(pattern.ID)
			event.Labels["escape_name"] = pattern.Name
			return
		}
	}
}
