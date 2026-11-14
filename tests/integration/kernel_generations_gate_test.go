//go:build linux

package integration

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func generationGateManifest(t *testing.T) []string {
	t.Helper()
	data, err := exec.Command("bash", "run-kernel-generations.sh", "--list-tests").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(data))
}

func TestGenerationGatePassOracle(t *testing.T) {
	manifest := generationGateManifest(t)
	var lines []string
	for _, name := range manifest {
		lines = append(lines, fmt.Sprintf("--- PASS: %s (0.01s)", name))
	}
	good := strings.Join(lines, "\n") + "\nPASS\n"
	for name, log := range map[string]string{
		"pass":                           good,
		"empty":                          "",
		"green with no tests":            "testing: warning: no tests to run\nPASS\n",
		"missing fixture":                strings.Replace(good, lines[1]+"\n", "", 1),
		"skip replacing pass":            strings.Replace(good, "--- PASS: "+manifest[1], "--- SKIP: "+manifest[1], 1),
		"skip child despite parent pass": good + "    --- SKIP: " + manifest[1] + "/btf (0.00s)\n",
		"fail despite other passes":      good + "--- FAIL: unexpected (0.01s)\nFAIL\n",
		"panic":                          good + "panic: kernel reader failed\n",
		"duplicate pass":                 good + lines[1] + "\n",
		"no final pass":                  strings.TrimSuffix(good, "PASS\n"),
		"near match":                     strings.Replace(good, manifest[1]+" ", manifest[1]+"Other ", 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vm.log")
			if err := os.WriteFile(path, []byte(log), 0600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("bash", "run-kernel-generations.sh", "--check-log", path).CombinedOutput()
			if (err == nil) != (name == "pass") {
				t.Fatalf("oracle accepted=%v log=%q output=%s", err == nil, log, out)
			}
		})
	}
}

func TestGenerationGateManifestCoversEveryGenerationFixture(t *testing.T) {
	manifest := map[string]bool{}
	for _, name := range generationGateManifest(t) {
		if manifest[name] {
			t.Fatalf("duplicate required test: %s", name)
		}
		manifest[name] = true
	}
	files, err := filepath.Glob("../../internal/ebpf/*_integration_test.go")
	if err != nil {
		t.Fatal(err)
	}
	defined := map[string]bool{}
	for _, path := range files {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok {
				defined[fn.Name.Name] = true
			}
			if ok && strings.HasPrefix(fn.Name.Name, "TestLSM_Generation") && !manifest[fn.Name.Name] {
				t.Errorf("generation VM fixture missing from strict PASS oracle: %s", fn.Name.Name)
			}
		}
	}
	for name := range manifest {
		if !defined[name] {
			t.Errorf("required fixture does not exist (would mis-select the gate): %s", name)
		}
	}
	for _, required := range []string{"TestLSM_LoadAndAttach", "TestLSM_ExactExecCollisionFirstMatchDefaultDenyAndScope", "TestLSM_ExactAuditDeniesAreNotKernelRefusals", "TestLSM_ExactEndpointCollisionDefaultDeny", "TestIntegrity_EnforceAllowsListedBlocksUnlisted"} {
		if !manifest[required] {
			t.Errorf("legacy/integrity coverage missing: %s", required)
		}
	}
}

func TestGenerationGateWorkflow(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/lsm-test.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		On map[string]struct {
			Paths []string `yaml:"paths"`
		} `yaml:"on"`
		Jobs map[string]struct {
			Continue any      `yaml:"continue-on-error"`
			Timeout  int      `yaml:"timeout-minutes"`
			Needs    []string `yaml:"needs"`
			Strategy struct {
				Matrix struct {
					Include []struct{ Version, Minor string } `yaml:"include"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
			Steps []struct {
				Run, Uses, If string
				Env           map[string]string
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	job, ok := workflow.Jobs["kernel-generations-strict"]
	if !ok || (job.Continue != nil && job.Continue != false) || job.Timeout == 0 {
		t.Fatal("missing required bounded generation job (must not allow failure)")
	}
	seen := map[string]bool{}
	for _, entry := range job.Strategy.Matrix.Include {
		seen[entry.Minor] = true
	}
	if !seen["6.1"] || !seen["6.18"] {
		t.Fatal("strict gate must cover oldest LTS and current built IMA kernel")
	}
	if !strings.Contains(strings.Join(job.Needs, ","), "ima-kernel") {
		t.Fatal("strict gate must use the built IMA kernels")
	}
	regenerated, ranVM, retained, checkedOracles := false, false, false, false
	for _, step := range job.Steps {
		if strings.Contains(step.Run, "go generate ./internal/ebpf") {
			regenerated = true
		}
		if strings.Contains(step.Run, "-run '^TestGenerationGate'") {
			checkedOracles = true
		}
		if strings.Contains(step.Run, "bash tests/integration/run-kernel-generations.sh") {
			if !regenerated || strings.Contains(step.Run, "--build-only") || step.If != "" {
				t.Fatal("strict VM evidence must be unconditional, regenerated, and not compile-only")
			}
			if !strings.Contains(step.Env["KERNEL"], "/kernel-out/vmlinuz") || !strings.Contains(step.Env["EXPECT_KERNEL_MINOR"], "matrix.minor") {
				t.Fatal("strict VM must use and verify requested kernel")
			}
			ranVM = true
		}
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") && step.If == "always()" {
			retained = true
		}
	}
	if !ranVM || !retained || !checkedOracles {
		t.Fatal("must run strict VM suite, check oracles offline and retain evidence on failure")
	}
	for _, event := range []string{"push", "pull_request"} {
		if !strings.Contains(strings.Join(workflow.On[event].Paths, ","), "tests/integration/run-kernel-generations.sh") {
			t.Fatalf("%s doesn't trigger gate changes", event)
		}
	}
}

func TestGenerationGateRunnerSafetyAndEvidence(t *testing.T) {
	data, err := os.ReadFile("run-kernel-generations.sh")
	if err != nil {
		t.Fatal(err)
	}
	runner := string(data)
	for _, required := range []string{
		"set -euo pipefail", `go test -c -tags integration -o "$ARTIFACTS/kernel.test" ./internal/ebpf`,
		"WARMOR_REQUIRE_BPF_LSM=1 WARMOR_REQUIRE_IMA=1 WARMOR_GENERATION_VM_GATE=1",
		`WARMOR_EXPECT_KERNEL_MINOR="$EXPECT_KERNEL_MINOR"`, `"$VIMTO" -kernel "$KERNEL" exec -- "$ARTIFACTS/kernel.test"`,
		`check_log "$ARTIFACTS/generations.log"`, `"$ROOT"/internal/ebpf/*_bpf*.o`, `"$ROOT"/internal/ebpf/*_bpf*.go`,
		`sha256sum "$KERNEL"`, `-test.count=1`, `-test.timeout=180s`,
	} {
		if !strings.Contains(runner, required) {
			t.Errorf("missing strict gate requirement: %s", required)
		}
	}
	if strings.Contains(runner, "sudo ") || strings.Contains(runner, "go test -v") {
		t.Fatal("no host enforcement fallback or second untracked VM compilation")
	}
	for _, args := range [][]string{{"--host"}, {"--build-only", "extra"}, {"--check-log"}, {"--help", "extra"}} {
		cmd := exec.Command("bash", append([]string{"run-kernel-generations.sh"}, args...)...)
		err := cmd.Run()
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 {
			t.Fatalf("arguments %v must fail closed with usage exit: %v", args, err)
		}
	}
}
