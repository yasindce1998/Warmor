package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/simulator"
	"github.com/yasindce1998/warmor/internal/streaming"
)

// testWasm is a committed allow-everything policy module.
var testWasm = filepath.Join("..", "..", "internal", "wasm", "testdata", "allow_policy.wasm")

// copyWasm copies the test policy into dir under name and returns its path.
func copyWasm(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(testWasm)
	if err != nil {
		t.Skipf("test policy unavailable: %v", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeEvents writes events in the event-store NDJSON layout.
func writeEvents(t *testing.T, events []streaming.SecurityEvent) string {
	t.Helper()
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "events-0001.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	// Corrupt lines are skipped by the reader.
	if _, err := f.WriteString("not json\n"); err != nil {
		t.Fatal(err)
	}
	return dir
}

func sampleEvents() []streaming.SecurityEvent {
	now := time.Now()
	return []streaming.SecurityEvent{
		{Timestamp: now.Add(-time.Hour), EventType: "exec", Comm: "nginx", Filename: "/usr/sbin/nginx", Decision: "allow"},
		{Timestamp: now.Add(-30 * time.Minute), EventType: "exec", Comm: "nc", Filename: "/usr/bin/nc", Decision: "deny"},
		{Timestamp: now.Add(-10 * time.Minute), EventType: "network", Comm: "curl", RemoteAddr: "10.0.0.1", RemotePort: 443, Protocol: "tcp", Decision: "allow"},
		// Older than --since; excluded.
		{Timestamp: now.Add(-48 * time.Hour), EventType: "exec", Comm: "ancient", Filename: "/bin/old", Decision: "allow"},
	}
}

func TestSimulate_TextReportToStdout(t *testing.T) {
	data := writeEvents(t, sampleEvents())
	policy := copyWasm(t, t.TempDir(), "policy.wasm")

	stdout, stderr := runMain(t, "", "-policy", policy, "-data", data, "-since", "24h")
	assertContains(t, "stderr", stderr, "Loaded 3 events", "Replaying 3 events")
	assertContains(t, "report", stdout, "Policy Simulation Report", "Events replayed: 3", "Decision breakdown:")
}

func TestSimulate_JSONReportToFile_YAMLWithCompiledSibling(t *testing.T) {
	data := writeEvents(t, sampleEvents())
	pdir := t.TempDir()
	// A .yaml policy with a pre-compiled sibling .wasm is loaded without cargo.
	copyWasm(t, pdir, "candidate.wasm")
	yamlPolicy := writeFile(t, filepath.Join(pdir, "candidate.yaml"), "name: candidate\n")
	outPath := filepath.Join(t.TempDir(), "report.json")

	stdout, stderr := runMain(t, "", "-policy", yamlPolicy, "-data", data, "-since", "72h", "-format", "json", "-o", outPath)
	if stdout != "" {
		t.Errorf("stdout should be empty with -o, got %q", stdout)
	}
	assertContains(t, "stderr", stderr, "Loaded 4 events", "Report written to "+outPath)

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var res simulator.SimulationResult
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("report is not JSON: %v\n%s", err, raw)
	}
	if res.TotalEvents != 4 {
		t.Errorf("total_events = %d, want 4", res.TotalEvents)
	}
	if got := res.WouldAllow + res.WouldDeny + res.WouldLog; got != res.TotalEvents {
		t.Errorf("decision counts sum to %d, want %d", got, res.TotalEvents)
	}
}

func TestSimulate_NoEventsExitsZero(t *testing.T) {
	policy := copyWasm(t, t.TempDir(), "policy.wasm")
	r := runChild(t, nil, "-policy", policy, "-data", t.TempDir())
	if r.code != 0 {
		t.Errorf("exit = %d, want 0 (stderr: %s)", r.code, r.stderr)
	}
	assertContains(t, "stderr", r.stderr, "Loaded 0 events", "Nothing to do")
}

func TestSimulate_Errors(t *testing.T) {
	data := writeEvents(t, sampleEvents())
	dir := t.TempDir()
	policy := copyWasm(t, dir, "policy.wasm")
	badWasm := writeFile(t, filepath.Join(dir, "bad.wasm"), "this is not wasm")
	badYAML := writeFile(t, filepath.Join(dir, "broken.yaml"), "rules: [unclosed")

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no policy", []string{"-data", data}, "--policy is required"},
		{"no data", []string{"-policy", policy}, "--data is required"},
		{"bad glob", []string{"-policy", policy, "-data", "[" + dir}, "error reading events"},
		{"missing policy", []string{"-policy", filepath.Join(dir, "nope.wasm"), "-data", data}, "error loading policy"},
		{"invalid wasm", []string{"-policy", badWasm, "-data", data}, "error loading policy"},
		{"unparseable yaml", []string{"-policy", badYAML, "-data", data}, "error loading policy"},
		{"unwritable output", []string{"-policy", policy, "-data", data, "-o", filepath.Join(dir, "x", "y", "r.txt")}, "error creating output file"},
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

func TestSimulate_Version(t *testing.T) {
	r := runChild(t, nil, "-version")
	if r.code != 0 {
		t.Fatalf("exit = %d", r.code)
	}
	assertContains(t, "stdout", r.stdout, "warmor-simulate dev")
}
