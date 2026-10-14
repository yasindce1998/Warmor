package escape

import (
	"context"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/pkg/api"
)

func makeEvent(eventType, comm, filename string, cgroupID uint64) *streaming.SecurityEvent {
	return &streaming.SecurityEvent{
		EventType: eventType,
		Comm:      comm,
		Filename:  filename,
		CgroupID:  cgroupID,
		PID:       1000,
		PPID:      1,
		UID:       0,
	}
}

func TestDetectNsenter(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	ev := makeEvent("exec", "nsenter", "/usr/bin/nsenter", 100)
	result := d.CheckEvent(context.Background(), ev)

	if result == nil {
		t.Fatal("expected deny for nsenter")
	}
	if result.Action != api.ActionDeny {
		t.Errorf("expected ActionDeny, got %d", result.Action)
	}

	alerts := d.Alerts()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].TechniqueID != TechNsenter {
		t.Errorf("expected TechNsenter, got %s", alerts[0].TechniqueID)
	}
	if alerts[0].Severity != SeverityCritical {
		t.Errorf("expected Critical severity, got %d", alerts[0].Severity)
	}
}

func TestDetectHostMount(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	// What lsm/sb_mount reports for `mount /dev/sda1 /mnt`: the filesystem
	// type and the source device.
	ev := makeEvent("mount", "mount", "ext4", 200)
	ev.MountType, ev.MountSource = "ext4", "/dev/sda1"
	result := d.CheckEvent(context.Background(), ev)

	if result == nil {
		t.Fatal("expected deny for host mount")
	}
	alerts := d.Alerts()
	if alerts[0].TechniqueID != TechHostMount {
		t.Errorf("expected TechHostMount, got %s", alerts[0].TechniqueID)
	}
}

func TestDetectPtraceCross(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	ev := &streaming.SecurityEvent{
		EventType:  "ptrace",
		Comm:       "gdb",
		PtraceComm: "target",
		CgroupID:   300,
		PID:        1001,
		// The target lives in another cgroup (e.g. the host's init).
		PtraceTargetCgroup: 1,
	}
	result := d.CheckEvent(context.Background(), ev)

	if result == nil {
		t.Fatal("expected deny for cross-cgroup ptrace")
	}
	alerts := d.Alerts()
	if alerts[0].TechniqueID != TechPtraceCross {
		t.Errorf("expected TechPtraceCross, got %s", alerts[0].TechniqueID)
	}
}

func TestDetectProcNSAccess(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	ev := makeEvent("file", "cat", "/proc/1/ns/mnt", 400)
	result := d.CheckEvent(context.Background(), ev)

	if result == nil {
		t.Fatal("expected deny for /proc/*/ns/* access")
	}
	alerts := d.Alerts()
	if alerts[0].TechniqueID != TechProcNS {
		t.Errorf("expected TechProcNS, got %s", alerts[0].TechniqueID)
	}
}

func TestDetectDockerSocket(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	// lsm/socket_connect reports watched AF_UNIX connects as connect_unix.
	ev := makeEvent("connect_unix", "curl", "/var/run/docker.sock", 500)
	result := d.CheckEvent(context.Background(), ev)

	if result == nil {
		t.Fatal("expected deny for docker socket access")
	}
	alerts := d.Alerts()
	if alerts[0].TechniqueID != TechDockerSocket {
		t.Errorf("expected TechDockerSocket, got %s", alerts[0].TechniqueID)
	}
}

func TestDetectSensitiveExec(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	tools := []string{"runc", "ctr", "crictl", "kubectl", "docker", "chroot", "capsh"}
	for _, tool := range tools {
		d.ClearAlerts()
		// At exec time Comm is still the parent (the shell), so matching
		// must use the binary being executed.
		ev := makeEvent("exec", "sh", "/usr/bin/"+tool, 600)
		result := d.CheckEvent(context.Background(), ev)

		if result == nil {
			t.Errorf("expected deny for sensitive exec: %s", tool)
		}
	}
}

func TestDetectUnshareSetnsMultiStep(t *testing.T) {
	// Use DenyOnDetect: false so all patterns are evaluated (procNS single-step
	// also matches the second event but doesn't short-circuit).
	d := NewDetector(DetectorConfig{DenyOnDetect: false})

	// Step 1: unshare exec
	ev1 := makeEvent("exec", "unshare", "/usr/bin/unshare", 700)
	result := d.CheckEvent(context.Background(), ev1)
	if result != nil {
		t.Fatal("unshare alone should not trigger (first step only)")
	}

	// Step 2: ns file access within window
	ev2 := makeEvent("file", "bash", "/proc/1/ns/mnt", 700)
	result = d.CheckEvent(context.Background(), ev2)
	if result != nil {
		t.Fatal("deny_on_detect=false should always return nil")
	}

	alerts := d.Alerts()
	found := false
	for _, a := range alerts {
		if a.TechniqueID == TechUnshareSetns {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected TechUnshareSetns alert for unshare + ns access sequence")
	}
}

func TestMultiStepOutsideWindow(t *testing.T) {
	// Use a custom pattern with a very short window
	shortPattern := &Pattern{
		ID:       TechUnshareSetns,
		Name:     "test short window",
		Severity: SeverityCritical,
		Window:   1 * time.Millisecond,
		Steps: []StepMatcher{
			{
				EventType: "exec",
				Match:     func(ev *EventView) bool { return ev.Comm == "unshare" },
			},
			{
				EventType: "file",
				Match:     func(ev *EventView) bool { return containsNS(ev.Filename) },
			},
		},
	}

	d := NewDetector(DetectorConfig{
		Patterns:     []*Pattern{shortPattern},
		DenyOnDetect: true,
	})

	ev1 := makeEvent("exec", "unshare", "/usr/bin/unshare", 800)
	d.CheckEvent(context.Background(), ev1)

	// Wait longer than window
	time.Sleep(5 * time.Millisecond)

	ev2 := makeEvent("file", "bash", "/proc/1/ns/mnt", 800)
	result := d.CheckEvent(context.Background(), ev2)

	if result != nil {
		t.Error("should not match when events are outside the time window")
	}
}

func TestNoMatchForBenignEvents(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	benign := []*streaming.SecurityEvent{
		makeEvent("exec", "nginx", "/usr/bin/nginx", 100),
		makeEvent("file", "cat", "/etc/passwd", 100),
		makeEvent("exec", "ls", "/usr/bin/ls", 100),
		makeEvent("file", "app", "/tmp/data.json", 100),
	}

	for _, ev := range benign {
		result := d.CheckEvent(context.Background(), ev)
		if result != nil {
			t.Errorf("unexpected deny for benign event: %s %s", ev.Comm, ev.Filename)
		}
	}

	if len(d.Alerts()) != 0 {
		t.Errorf("expected 0 alerts for benign events, got %d", len(d.Alerts()))
	}
}

func TestZeroCgroupIgnored(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	ev := makeEvent("exec", "nsenter", "/usr/bin/nsenter", 0)
	result := d.CheckEvent(context.Background(), ev)

	if result != nil {
		t.Error("events with cgroup_id=0 should be ignored")
	}
}

func TestDenyOnDetectFalse(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: false})

	ev := makeEvent("exec", "nsenter", "/usr/bin/nsenter", 100)
	result := d.CheckEvent(context.Background(), ev)

	if result != nil {
		t.Error("deny_on_detect=false should return nil even on detection")
	}

	if len(d.Alerts()) != 1 {
		t.Error("alert should still be recorded when deny is off")
	}
}

func TestAlertCallback(t *testing.T) {
	var received *Alert
	d := NewDetector(DetectorConfig{
		DenyOnDetect: true,
		AlertCallback: func(a *Alert) {
			received = a
		},
	})

	ev := makeEvent("exec", "nsenter", "/usr/bin/nsenter", 100)
	d.CheckEvent(context.Background(), ev)

	if received == nil {
		t.Fatal("alert callback was not called")
	}
	if received.TechniqueID != TechNsenter {
		t.Errorf("callback received wrong technique: %s", received.TechniqueID)
	}
}

func TestClearAlerts(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	ev := makeEvent("exec", "nsenter", "/usr/bin/nsenter", 100)
	d.CheckEvent(context.Background(), ev)

	if len(d.Alerts()) != 1 {
		t.Fatal("expected 1 alert before clear")
	}

	d.ClearAlerts()
	if len(d.Alerts()) != 0 {
		t.Error("expected 0 alerts after clear")
	}
}

func TestClearWindow(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	// Record some benign events to populate window
	ev := makeEvent("exec", "ls", "/usr/bin/ls", 900)
	d.CheckEvent(context.Background(), ev)

	d.ClearWindow(900)

	// Multi-step pattern should not find prior events
	ev2 := makeEvent("file", "bash", "/proc/1/ns/mnt", 900)
	d.CheckEvent(context.Background(), ev2)

	// Only procNS single-step should trigger, not unshare+setns
	for _, a := range d.Alerts() {
		if a.TechniqueID == TechUnshareSetns {
			t.Error("should not match unshare+setns after window clear")
		}
	}
}

func TestEnrichLabelsEscape(t *testing.T) {
	d := NewDetector(DetectorConfig{})

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "nsenter",
		Filename:  "/usr/bin/nsenter",
		CgroupID:  100,
		PID:       1000,
	}

	d.Enrich(ev)

	if ev.Labels == nil {
		t.Fatal("expected labels to be set")
	}
	if ev.Labels["escape_technique"] != string(TechNsenter) {
		t.Errorf("expected escape_technique=%s, got %s", TechNsenter, ev.Labels["escape_technique"])
	}
	if ev.Labels["escape_name"] != "nsenter from container" {
		t.Errorf("unexpected escape_name: %s", ev.Labels["escape_name"])
	}
}

func TestEnrichNoLabelForBenign(t *testing.T) {
	d := NewDetector(DetectorConfig{})

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "nginx",
		Filename:  "/usr/bin/nginx",
		CgroupID:  100,
		PID:       1000,
	}

	d.Enrich(ev)

	if ev.Labels != nil {
		t.Error("benign event should not get escape labels")
	}
}

func TestEnrichZeroCgroupIgnored(t *testing.T) {
	d := NewDetector(DetectorConfig{})

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "nsenter",
		Filename:  "/usr/bin/nsenter",
		CgroupID:  0,
		PID:       1000,
	}

	d.Enrich(ev)

	if ev.Labels != nil {
		t.Error("cgroup_id=0 events should not be enriched")
	}
}

func TestDefaultPatternsCount(t *testing.T) {
	patterns := DefaultPatterns()
	if len(patterns) != 7 {
		t.Errorf("expected 7 default patterns, got %d", len(patterns))
	}
}

func TestContainsNS(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/proc/1/ns/mnt", true},
		{"/proc/123/ns/pid", true},
		{"/proc/1/ns/net", true},
		{"/proc/1/status", false},
		{"/proc/1/n", false},
		{"/etc/passwd", false},
		{"short", false},
		{"/proc/self/ns/net", true},
		{"/proc/thread-self/ns/mnt", true},
		{"/abcde1/ns/mnt", false},        // not under /proc
		{"/proc/1a/ns/mnt", false},       // not a pid
		{"/proc/1/ns/", false},           // no namespace type
		{"/proc/1/ns/mnt/extra", false},  // deeper than a handle
		{"/proc/1/task/2/ns/mnt", false}, // per-thread handles not matched
		{"/sys/proc/1/ns/mnt", false},
	}

	for _, tt := range tests {
		got := containsNS(tt.path)
		if got != tt.want {
			t.Errorf("containsNS(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestHostProcessesIgnored(t *testing.T) {
	const ctr, host = 100, 200
	d := NewDetector(DetectorConfig{
		DenyOnDetect: true,
		IsContainer:  func(id uint64) bool { return id == ctr },
	})
	if r := d.CheckEvent(context.Background(), makeEvent("exec", "bash", "/usr/bin/nsenter", host)); r != nil {
		t.Errorf("host nsenter flagged as an escape: %+v", r)
	}
	if r := d.CheckEvent(context.Background(), makeEvent("exec", "bash", "/usr/bin/nsenter", ctr)); r == nil {
		t.Error("container nsenter not flagged")
	}
	if n := len(d.Alerts()); n != 1 {
		t.Errorf("got %d alerts, want 1", n)
	}
}

func TestParentCommDoesNotMatch(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})
	// A process named nsenter (the parent) executing something benign.
	if r := d.CheckEvent(context.Background(), makeEvent("exec", "nsenter", "/bin/ls", 100)); r != nil {
		t.Errorf("matched on the caller's comm: %+v", r)
	}
}

func TestMountFalsePositives(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})
	benign := []struct{ comm, typ, src string }{
		{"mount", "tmpfs", "tmpfs"},
		{"mount", "proc", "proc"},
		{"mount", "overlay", "overlay"},
		{"runc:[2:INIT]", "cgroup", "cgroup"}, // runtime setup on a v1 host
		{"crun", "ext4", "/dev/sda1"},
	}
	for _, b := range benign {
		ev := makeEvent("mount", b.comm, b.typ, 100)
		ev.MountType, ev.MountSource = b.typ, b.src
		if r := d.CheckEvent(context.Background(), ev); r != nil {
			t.Errorf("%s mounting %s from %s flagged: %+v", b.comm, b.typ, b.src, r)
		}
	}
	ev := makeEvent("mount", "mount", "cgroup", 100)
	ev.MountType, ev.MountSource = "cgroup", "cgroup"
	if d.CheckEvent(context.Background(), ev) == nil {
		t.Error("cgroup v1 mount from a workload not flagged (release_agent escape)")
	}
}

func TestPtraceSameCgroupIgnored(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})
	for _, target := range []uint64{0, 300} {
		ev := &streaming.SecurityEvent{EventType: "ptrace", Comm: "strace", PtraceComm: "app", CgroupID: 300, PtraceTargetCgroup: target}
		if r := d.CheckEvent(context.Background(), ev); r != nil {
			t.Errorf("ptrace with target cgroup %d flagged: %+v", target, r)
		}
	}
}

func TestDockerSocketOpenNotConnect(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})
	// open() on a socket node fails with ENXIO and grants nothing; only a
	// connect reaches the runtime API.
	if r := d.CheckEvent(context.Background(), makeEvent("file", "ls", "/var/run/docker.sock", 100)); r != nil {
		t.Errorf("open of the socket node flagged: %+v", r)
	}
}

func TestAlertHistoryBounded(t *testing.T) {
	var delivered int
	d := NewDetector(DetectorConfig{AlertCallback: func(*Alert) { delivered++ }})
	for i := 0; i < maxAlerts+10; i++ {
		d.CheckEvent(context.Background(), makeEvent("exec", "sh", "/usr/bin/nsenter", 100))
	}
	if n := len(d.Alerts()); n != maxAlerts {
		t.Errorf("kept %d alerts, want %d", n, maxAlerts)
	}
	if delivered != maxAlerts+10 {
		t.Errorf("callback got %d alerts, want all %d", delivered, maxAlerts+10)
	}
}

func TestIdleWindowsSwept(t *testing.T) {
	d := NewDetector(DetectorConfig{})
	old := time.Now().Add(-2 * windowTTL)
	for id := uint64(1); id <= 200; id++ {
		d.recordEvent(id, EventView{EventType: "exec"}, old)
	}
	d.recordEvent(9999, EventView{EventType: "exec"}, time.Now())
	d.windowsMu.Lock()
	n := len(d.windows)
	d.windowsMu.Unlock()
	if n > 70 {
		t.Errorf("%d windows kept after sweep; idle ones should be dropped", n)
	}
}
