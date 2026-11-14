//go:build linux

package integration

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOutcomeWorkflow(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/enforcement-outcomes.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		On   map[string]any `yaml:"on"`
		Jobs map[string]struct {
			Continue bool `yaml:"continue-on-error"`
			Steps    []struct {
				Run  string `yaml:"run"`
				Uses string `yaml:"uses"`
				If   string `yaml:"if"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	if _, ok := workflow.On["pull_request"]; !ok {
		t.Fatal("outcome gate must run on pull requests")
	}
	job, ok := workflow.Jobs["whole-daemon-outcomes"]
	if !ok || job.Continue {
		t.Fatal("outcomes job is missing or allowed to fail")
	}
	var regenerate, runVM, retain bool
	for _, step := range job.Steps {
		if strings.Contains(step.Run, "go generate ./internal/ebpf") {
			regenerate = true
		}
		if strings.Contains(step.Run, "bash tests/integration/run-outcomes.sh") {
			if !regenerate || strings.Contains(step.Run, "--build-only") {
				t.Fatal("CI must regenerate BPF before running real VM outcomes, not build-only")
			}
			runVM = true
		}
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") && step.If == "always()" {
			retain = true
		}
	}
	if !runVM || !retain {
		t.Fatal("CI must run VM outcomes and retain evidence on failure")
	}
}

func TestRunnerArguments(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"--help"}, 0},
		{[]string{"--host"}, 2},
		{[]string{"--build-only", "unexpected"}, 2},
	} {
		cmd := exec.Command("bash", append([]string{"run-outcomes.sh"}, tc.args...)...)
		err := cmd.Run()
		code := 0
		if err != nil {
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatal(err)
			}
			code = exit.ExitCode()
		}
		if code != tc.code {
			t.Fatalf("runner %v exit=%d, want %d", tc.args, code, tc.code)
		}
	}
}
