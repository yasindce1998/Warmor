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

func TestRunnerUsesPreparedBinariesInVM(t *testing.T) {
	data, err := os.ReadFile("run-outcomes.sh")
	if err != nil {
		t.Fatal(err)
	}
	runner := string(data)
	for _, required := range []string{
		`go test -c -tags integration -o "$ARTIFACTS/kernel.test" ./internal/ebpf`,
		`WARMOR_REQUIRE_BPF_LSM=1 "$VIMTO" -kernel "$KERNEL" exec --`,
		`WARMOR_OUTCOME_VM=1 "$VIMTO" -kernel "$KERNEL" exec --`,
		`"$ARTIFACTS/kernel.test" -test.v`, `"$ARTIFACTS/outcomes.test" -test.v`,
		`"$ROOT"/internal/ebpf/*_bpf*.o`, `"$ROOT"/internal/ebpf/*_bpf*.go`,
		`^--- PASS: TestLSM_${test} `,
		`grep -qx 'whole-daemon outcomes passed in vimto'`,
	} {
		if !strings.Contains(runner, required) {
			t.Errorf("runner must retain exact binary/object and non-skipped VM evidence: missing %s", required)
		}
	}
	if strings.Contains(runner, `go test -v`) || strings.Contains(runner, `sudo `) {
		t.Fatal("runner must not rebuild the tested suite or use a host enforcement fallback")
	}
}

func TestCompiledStaticPoliciesRequiredInCI(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Run string            `yaml:"run"`
				Env map[string]string `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	for _, step := range workflow.Jobs["build"].Steps {
		if step.Env["WARMOR_REQUIRE_CARGO"] != "1" || !strings.Contains(step.Run, "go test ./internal/wasm/") {
			continue
		}
		for _, name := range []string{"TestCompiledPolicyArgsAndNetworkOperation", "TestCompiledUnknown", "TestTemporalPolicyEndToEnd", "TestCompiledStaticCollisionsAndLengthBoundary", "TestCompiledYAMLStaticRules"} {
			if !strings.Contains(step.Run, name) {
				t.Errorf("required-Cargo CI must preserve and explicitly select %s", name)
			}
		}
		return
	}
	t.Fatal("Rust-equipped build job must require compiled policy tests")
}
