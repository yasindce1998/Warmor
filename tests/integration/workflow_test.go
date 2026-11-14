//go:build linux

package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		`WARMOR_REQUIRE_BPF_LSM=1 bash tests/integration/run-vm.sh verifier "$ARTIFACTS"`,
		`WARMOR_OUTCOME_VM=1 bash tests/integration/run-vm.sh outcomes "$ARTIFACTS"`,
		`"$VIMTO" -kernel "$KERNEL" exec --`,
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

func TestVMDeadlinePropagatesFailureAndCapturesStderr(t *testing.T) {
	// Exercise only a fake vimto. No guest, BPF loader or daemon is executed.
	for _, code := range []string{"0", "7", "124"} {
		t.Run(code, func(t *testing.T) {
			dir := t.TempDir()
			fake := filepath.Join(dir, "vimto")
			if err := os.WriteFile(fake, []byte("#!/bin/sh\necho guest-stdout\necho boot-stderr >&2\nexit "+code+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "run-vm.sh", "verifier", dir, fake)
			output, err := cmd.CombinedOutput()
			if code == "0" && err != nil {
				t.Fatalf("successful fake VM failed: %v %s", err, output)
			}
			if code != "0" {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || fmt.Sprint(exit.ExitCode()) != code {
					t.Fatalf("VM failure must propagate unchanged: want %s got %v %s", code, err, output)
				}
			}
			log, err := os.ReadFile(filepath.Join(dir, "verifier.log"))
			if err != nil || !strings.Contains(string(log), "guest-stdout") || !strings.Contains(string(log), "boot-stderr") {
				t.Fatalf("retain both VM output streams: %q %v", log, err)
			}
			status, err := os.ReadFile(filepath.Join(dir, "verifier-status.txt"))
			if err != nil || !strings.Contains(string(status), "exit="+code) {
				t.Fatalf("retain VM phase exit: %q %v", status, err)
			}
		})
	}
}

func TestVMDeadlineCoversPreGuestStartup(t *testing.T) {
	data, err := os.ReadFile("run-vm.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"verifier) LIMIT=300s", "outcomes) LIMIT=360s", "timeout --verbose --signal=QUIT --kill-after=15s", `"$LIMIT" "$@" 2>&1 | tee`, `exit "$code"`} {
		if !strings.Contains(string(data), required) {
			t.Errorf("host cache/boot deadline or failure propagation missing: %s", required)
		}
	}
	workflow, err := os.ReadFile("../../.github/workflows/enforcement-outcomes.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(workflow), "XDG_CACHE_HOME: ${{ runner.temp }}/warmor-outcome-cache") {
		t.Fatal("kernel root-overlay cache must stay on runner disk outside the shared checkout")
	}
}

func TestVMDeadlineActuallyStopsStalledLauncher(t *testing.T) {
	// Shorten only the test's timeout executable, not the production deadline.
	// The fake launcher never boots a VM or starts enforcement.
	timeout, err := exec.LookPath("timeout")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	wrapper := "#!/bin/sh\nshift 4\nexec " + timeout + " --signal=QUIT --kill-after=1s 0.1s \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "timeout"), []byte(wrapper), 0700); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(bin, "vimto")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho stalled-before-guest >&2\nexec sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "run-vm.sh", "verifier", dir, fake)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 124 {
		t.Fatalf("stalled launcher must fail at host deadline: %v context=%v output=%s", err, ctx.Err(), output)
	}
	status, err := os.ReadFile(filepath.Join(dir, "verifier-status.txt"))
	if err != nil || !strings.Contains(string(status), "exit=124") || !strings.Contains(string(status), "No prevention or termination proof") {
		t.Fatalf("retain failed startup diagnosis, not success: %q %v", status, err)
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
