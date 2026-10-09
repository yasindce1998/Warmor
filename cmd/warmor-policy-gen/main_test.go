package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
)

// auditLog has repeated nginx behavior (count >= 2) plus a one-off python3 exec.
const auditLog = `{"event_type":"exec","comm":"nginx","filename":"/usr/sbin/nginx","pid":100,"uid":0,"gid":0,"decision":"allow"}
{"event_type":"exec","comm":"nginx","filename":"/usr/sbin/nginx","pid":101,"uid":0,"gid":0,"decision":"allow"}
{"event_type":"file","comm":"nginx","filename":"/etc/nginx/nginx.conf","pid":100,"uid":0,"gid":0,"decision":"allow"}
{"event_type":"file","comm":"nginx","filename":"/etc/nginx/nginx.conf","pid":101,"uid":0,"gid":0,"decision":"allow"}
{"event_type":"network","comm":"nginx","protocol":"tcp","remote_addr":"10.0.1.5","remote_port":443,"pid":100,"uid":0,"gid":0,"decision":"allow"}
{"event_type":"network","comm":"nginx","protocol":"tcp","remote_addr":"10.0.1.6","remote_port":443,"pid":100,"uid":0,"gid":0,"decision":"allow"}
{"event_type":"exec","comm":"python3","filename":"/usr/bin/python3","pid":200,"uid":1000,"gid":1000,"decision":"allow"}
`

func writeLog(t *testing.T) string {
	t.Helper()
	return writeFile(t, filepath.Join(t.TempDir(), "audit.ndjson"), auditLog)
}

func TestGen_FileToStdout(t *testing.T) {
	stdout, stderr := runMain(t, "", "-name", "nginx-app", writeLog(t))
	assertContains(t, "stderr", stderr, "Read 7 events from audit log", "behavior groups")
	assertContains(t, "policy", stdout, "name: nginx-app", "/usr/sbin/nginx")

	// The generated YAML must be a valid compiler policy.
	p, err := compiler.Parse([]byte(stdout))
	if err != nil {
		t.Fatalf("generated policy does not parse: %v\n%s", err, stdout)
	}
	if p.Name != "nginx-app" || len(p.Rules) == 0 {
		t.Errorf("policy = %q with %d rules", p.Name, len(p.Rules))
	}
	// python3 was seen only once and min-count defaults to 2.
	if strings.Contains(stdout, "/usr/bin/python3") {
		t.Errorf("one-off behavior should be excluded at min-count=2:\n%s", stdout)
	}
}

func TestGen_MinCountOneIncludesRareBehavior(t *testing.T) {
	stdout, _ := runMain(t, "", "-min-count", "1", writeLog(t))
	assertContains(t, "policy", stdout, "/usr/bin/python3", "name: generated-policy")
}

func TestGen_CommAndEventTypeFiltersToFile(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "policy.yaml")
	stdout, stderr := runMain(t, "",
		"-o", outPath,
		"-comm-filter", " nginx , ,",
		"-event-types", "exec, ,",
		"-min-count", "1",
		"-description", "custom desc",
		writeLog(t))
	if stdout != "" {
		t.Errorf("stdout should be empty with -o, got %q", stdout)
	}
	assertContains(t, "stderr", stderr, "Read 2 events", "Policy written to "+outPath)
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	assertContains(t, "policy", s, "/usr/sbin/nginx", "custom desc")
	for _, unwanted := range []string{"python3", "nginx.conf", "10.0.1"} {
		if strings.Contains(s, unwanted) {
			t.Errorf("filtered policy should not contain %q:\n%s", unwanted, s)
		}
	}
}

func TestGen_Stdin(t *testing.T) {
	stdout, stderr := runMain(t, auditLog, "-")
	assertContains(t, "stderr", stderr, "Read 7 events")
	assertContains(t, "policy", stdout, "/usr/sbin/nginx")
}

func TestGen_Errors(t *testing.T) {
	dir := t.TempDir()
	logPath := writeLog(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no input", nil, "no input file specified"},
		{"missing file", []string{filepath.Join(dir, "nope.ndjson")}, "error:"},
		{"no matching events", []string{"-comm-filter", "doesnotexist", logPath}, "no matching events"},
		{"unwritable output", []string{"-o", filepath.Join(dir, "no", "such", "p.yaml"), logPath}, "error writing output"},
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

func TestGen_UsageAndVersion(t *testing.T) {
	r := runChild(t, nil)
	assertContains(t, "usage", r.stderr, "Usage: warmor-policy-gen", "-min-count")
	r = runChild(t, nil, "-version")
	if r.code != 0 {
		t.Fatalf("exit = %d", r.code)
	}
	assertContains(t, "stdout", r.stdout, "warmor-policy-gen ")
}
