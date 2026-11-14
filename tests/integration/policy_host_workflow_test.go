//go:build linux

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSupervisedHostWorkflowIsSeparateRequiredVMMatrix(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/supervised-host-outcomes.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		On   map[string]any `yaml:"on"`
		Jobs map[string]struct {
			Continue bool `yaml:"continue-on-error"`
			Strategy struct {
				Matrix struct {
					Maps []string `yaml:"maps"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
			Steps []struct{ Run, Uses, If string } `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	job, ok := workflow.Jobs["supervised-host-outcomes"]
	if !ok || job.Continue || strings.Join(job.Strategy.Matrix.Maps, ",") != "legacy,atomic" {
		t.Fatal("must require both map modes")
	}
	for _, event := range []string{"pull_request", "push"} {
		if _, ok := workflow.On[event]; !ok {
			t.Fatal("missing trigger", event)
		}
	}
	var generated, ran, retained bool
	for _, step := range job.Steps {
		if strings.Contains(step.Run, "go generate ./internal/ebpf") {
			generated = true
		}
		if strings.Contains(step.Run, "bash tests/integration/run-outcomes.sh") {
			if !generated || strings.Contains(step.Run, "--build-only") || !strings.Contains(step.Run, "--policy-host") || !strings.Contains(step.Run, "--atomic-generations") {
				t.Fatal("VM execution must follow generation with explicit modes")
			}
			ran = true
		}
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") && step.If == "always()" {
			retained = true
		}
	}
	if !ran || !retained || !strings.Contains(string(data), "go-version: '1.26.11'") {
		t.Fatal("missing real VM gate, retained evidence, or toolchain pin")
	}
	if !strings.Contains(string(data), "-tags policyhost_phaseproof") || !strings.Contains(string(data), "./internal/testutil/loadphase") {
		t.Fatal("CI must exercise tagged real-worker barrier and negative offline oracle")
	}
}

func TestSupervisedPhaseProfileExcludedFromReleasePackaging(t *testing.T) {
	for _, path := range []string{"../../scripts/release-build.sh", "../../deploy/Dockerfile"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "policyhost_phaseproof") {
			t.Fatalf("test-only profile leaked into release build: %s", path)
		}
	}
}

func TestSupervisedHostRunnerControlsAndTrustEvidence(t *testing.T) {
	for _, args := range [][]string{{"--atomic-generations"}, {"--policy-host", "--host"}, {"--policy-host", "--policy-host"}} {
		cmd := exec.Command("bash", append([]string{"run-outcomes.sh"}, args...)...)
		if err := cmd.Run(); err == nil {
			t.Fatalf("unsafe args accepted: %v", args)
		}
	}
	data, err := os.ReadFile("run-outcomes.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`export GIT_DIR="$(git rev-parse --absolute-git-dir)"`, `export GIT_WORK_TREE="$ROOT"`,
		`unset WARMOR_OUTCOME_POLICY_HOST WARMOR_OUTCOME_ATOMIC_GENERATIONS`,
		`unset WARMOR_TEST_HOST_PHASE_SOCKET WARMOR_TEST_HOST_PHASE_DIGESTS`,
		`go build -tags policyhost_phaseproof -o "$ARTIFACTS/warmor-policy-host" ./cmd/warmor-policy-host`,
		`go build -tags policyhost_phaseproof -o "$ARTIFACTS/warmor-daemon" ./cmd/warmor-daemon`,
		`"$ARTIFACTS/POLICY_HOST_SHA256"`, `"$ARTIFACTS/fixture-public.pem"`,
		`"$ARTIFACTS/"*.sig`, `"$ARTIFACTS/reviewed-declaration-digests.txt"`,
		`bash tests/integration/check-host-outcomes.sh "$ARTIFACTS/outcomes.log"`,
		`bash tests/integration/check-host-outcomes.sh --verifier "$ARTIFACTS/verifier.log"`,
	} {
		if !strings.Contains(string(data), required) {
			t.Error("missing exact host evidence:", required)
		}
	}
}

func TestSupervisedHostPASSCounterRejectsFalseEvidence(t *testing.T) {
	var lines []string
	for _, name := range []string{"baseline-without-daemon", "allow-first-deny-and-rejected-reload-LKG", "global-audit-never-blocks-or-kills", "nonroot-process-actually-terminated", "signed-host-load-failures-keep-LKG", "dead-host-never-serves-cached-allow", "SIGTERM-cancels-candidate-and-reaps-hosts"} {
		lines = append(lines, "    --- PASS: TestDaemonOutcomes/"+name+" (0.01s)")
	}
	for _, name := range []string{"compile-heavy", "init-loop", "signed-malformed"} {
		lines = append(lines, "        --- PASS: TestDaemonOutcomes/signed-host-load-failures-keep-LKG/"+name+" (0.01s)")
	}
	lines = append(lines, "--- PASS: TestDaemonOutcomes (1.00s)", "PASS")
	good := strings.Join(lines, "\n") + "\n"
	for name, log := range map[string]string{
		"good":          good,
		"empty":         "",
		"parent-only":   "--- PASS: TestDaemonOutcomes (1.00s)\nPASS\n",
		"skip":          good + "    --- SKIP: TestDaemonOutcomes/unexpected (0.00s)\n",
		"fail":          good + "FAIL\n",
		"missing":       strings.Replace(good, lines[0]+"\n", "", 1),
		"duplicate":     good + lines[0] + "\n",
		"no-final-pass": strings.TrimSuffix(good, "PASS\n"),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "outcomes.log")
			if err := os.WriteFile(path, []byte(log), 0600); err != nil {
				t.Fatal(err)
			}
			err := exec.Command("bash", "check-host-outcomes.sh", path).Run()
			if (err == nil) != (name == "good") {
				t.Fatalf("false host evidence accepted or good rejected: %v", err)
			}
		})
	}
}

func TestSupervisedHostVerifierRequiresExactNonSkippedPASS(t *testing.T) {
	var lines []string
	for _, name := range []string{"LoadAndAttach", "StopReadersInterruptsIdleMonitors", "ExactExecCollisionFirstMatchDefaultDenyAndScope", "ExactAuditDeniesAreNotKernelRefusals", "ExactEndpointCollisionDefaultDeny", "TruncatedExecCannotHitExactAllow", "ExactIPv6AndMappedEndpointIdentities"} {
		lines = append(lines, "--- PASS: TestLSM_"+name+" (0.01s)")
	}
	good := strings.Join(lines, "\n") + "\nPASS\n"
	for name, log := range map[string]string{
		"good":          good,
		"empty":         "",
		"missing":       strings.Replace(good, lines[0]+"\n", "", 1),
		"duplicate":     good + lines[0] + "\n",
		"skip":          good + "    --- SKIP: TestLSM_ExactExecCollisionFirstMatchDefaultDenyAndScope/nested (0.00s)\n",
		"failure":       good + "FAIL\n",
		"missing-final": strings.TrimSuffix(good, "PASS\n"),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "verifier.log")
			if err := os.WriteFile(path, []byte(log), 0600); err != nil {
				t.Fatal(err)
			}
			err := exec.Command("bash", "check-host-outcomes.sh", "--verifier", path).Run()
			if (err == nil) != (name == "good") {
				t.Fatalf("incorrect verifier evidence accepted/rejected: %v", err)
			}
		})
	}
}
