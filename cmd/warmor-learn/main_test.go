package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/policymerge"
)

const (
	evExec123 = `{"event_type":"exec","cgroup_id":123,"comm":"nginx","filename":"/usr/sbin/nginx"}`
	evFile456 = `{"event_type":"file","cgroup_id":456,"comm":"nginx","filename":"/etc/nginx/nginx.conf"}`
	evExec789 = `{"event_type":"exec","cgroup_id":789,"comm":"sh","filename":"/bin/sh-not-wanted"}`
)

func TestLearn_FileReplayToFile(t *testing.T) {
	dir := t.TempDir()
	events := writeFile(t, filepath.Join(dir, "events.ndjson"),
		evExec123+"\n\n{not json\n"+evFile456+"\n"+evExec789) // no trailing newline
	outPath := filepath.Join(dir, "learned.yaml")
	stdout, stderr := runMain(t, "", "-events", events, "-cgroup", "123, 456,,", "-name", "learned-app", "-o", outPath)
	if stdout != "" {
		t.Errorf("stdout should be empty with -o, got %q", stdout)
	}
	assertContains(t, "stderr", stderr,
		"cgroups: [123 456]",
		"Reading events from "+events,
		"warning: skipping malformed event on line 3",
		"Learning complete: learned 2 containers",
		"1 execs, 1 files",
		"Policy written to "+outPath)

	p, err := policymerge.LoadFile(outPath)
	if err != nil {
		t.Fatalf("learned policy not loadable: %v", err)
	}
	if p.Name != "learned-app" || p.DefaultAction != "deny" {
		t.Errorf("name=%q default=%q", p.Name, p.DefaultAction)
	}
	data, _ := os.ReadFile(outPath)
	assertContains(t, "policy", string(data), "/usr/sbin/nginx", "/etc/nginx/nginx.conf")
	if strings.Contains(string(data), "sh-not-wanted") {
		t.Error("event from a filtered-out cgroup was learned")
	}
}

func TestLearn_StdinAllCgroups(t *testing.T) {
	stdout, stderr := runMain(t, evExec123+"\n"+evExec789+"\n", "-events", "-")
	assertContains(t, "stderr", stderr, "cgroups: []", "learned 2 containers")
	assertContains(t, "stdout", stdout, "/usr/sbin/nginx", "/bin/sh-not-wanted")
}

func TestLearn_EventStoreDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "events-2026-01-01.ndjson"), evExec123) // no trailing newline
	writeFile(t, filepath.Join(dir, "events-2026-01-02.ndjson"), evFile456+"\n")
	writeFile(t, filepath.Join(dir, "unrelated.ndjson"), evExec789+"\n")
	stdout, stderr := runMain(t, "", "-events", dir)
	assertContains(t, "stderr", stderr, "learned 2 containers")
	assertContains(t, "stdout", stdout, "/usr/sbin/nginx", "/etc/nginx/nginx.conf")
	if strings.Contains(stdout, "sh-not-wanted") {
		t.Error("non event-store file was read")
	}
}

// TestLearn_Follow checks that --follow picks up events appended to the log
// after the session starts, including a line written in two pieces.
func TestLearn_Follow(t *testing.T) {
	old := followPollInterval
	followPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { followPollInterval = old })

	events := writeFile(t, filepath.Join(t.TempDir(), "events.ndjson"), evExec123+"\n")
	go func() {
		f, err := os.OpenFile(events, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return
		}
		defer f.Close()
		time.Sleep(50 * time.Millisecond)
		half := len(evFile456) / 2
		_, _ = f.WriteString(evFile456[:half])
		time.Sleep(50 * time.Millisecond)
		_, _ = f.WriteString(evFile456[half:] + "\n")
	}()

	// The duration bounds the session; it is generous so the ~100ms of
	// writes above land even on a heavily loaded CI runner.
	stdout, stderr := runMain(t, "", "-events", events, "-follow", "-duration", "3s")
	assertContains(t, "stderr", stderr, "learned 2 containers")
	if strings.Contains(stderr, "malformed") {
		t.Errorf("partial line was decoded early:\n%s", stderr)
	}
	assertContains(t, "stdout", stdout, "/usr/sbin/nginx", "/etc/nginx/nginx.conf")
}

func TestLearn_Errors(t *testing.T) {
	dir := t.TempDir()
	events := writeFile(t, filepath.Join(dir, "events.ndjson"), evExec123+"\n")
	empty := writeFile(t, filepath.Join(dir, "empty.ndjson"), "")
	emptyDir := filepath.Join(dir, "store")
	if err := os.Mkdir(emptyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no events source", nil, "--events is required"},
		{"bad cgroup", []string{"-events", events, "-cgroup", "12,abc"}, `invalid cgroup ID "abc"`},
		{"negative cgroup", []string{"-events", events, "-cgroup", "-5"}, `invalid cgroup ID "-5"`},
		{"missing events file", []string{"-events", filepath.Join(dir, "nope")}, "open events"},
		{"empty store dir", []string{"-events", emptyDir}, "no events-*.ndjson files"},
		{"follow stdin", []string{"-events", "-", "-follow"}, "--follow requires an event log file"},
		{"follow dir", []string{"-events", dir, "-follow"}, "--follow requires an event log file"},
		{"empty input", []string{"-events", empty}, "no events recorded from " + empty + "; refusing"},
		{"filtered out", []string{"-events", events, "-cgroup", "999"}, "for cgroups [999]; refusing"},
		{"unwritable output", []string{"-events", events, "-o", filepath.Join(dir, "x", "y", "p.yaml")}, "error writing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runChild(t, nil, tt.args...)
			if r.code != 1 {
				t.Errorf("exit = %d, want 1 (stderr: %s)", r.code, r.stderr)
			}
			assertContains(t, "stderr", r.stderr, tt.want)
		})
	}
}

func TestLearn_Version(t *testing.T) {
	r := runChild(t, nil, "-version")
	if r.code != 0 {
		t.Fatalf("exit = %d", r.code)
	}
	assertContains(t, "stdout", r.stdout, "warmor-learn dev")
}
