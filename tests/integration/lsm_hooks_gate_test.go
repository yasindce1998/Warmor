//go:build linux

package integration

import (
	"errors"
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

func lsmHooksGateManifest(t *testing.T) []string {
	t.Helper()
	data, err := exec.Command("bash", "run-lsm-hooks.sh", "--list-tests").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(data))
}

// Same strict pattern as the generation/daemon gates: one non-skipped PASS for
// every manifest fixture, no skips (including children), no duplicates and a
// final PASS line. Never trust go-test exit 0 alone.
func TestLSMHooksGatePassOracle(t *testing.T) {
	manifest := lsmHooksGateManifest(t)
	if len(manifest) < 2 {
		t.Fatalf("manifest too small to exercise oracle: %v", manifest)
	}
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
		"skip child despite parent pass": good + "    --- SKIP: " + manifest[1] + "/hook (0.00s)\n",
		"fail despite other passes":      good + "--- FAIL: unexpected (0.01s)\nFAIL\n",
		"panic":                          good + "panic: BPF LSM hook missing\n",
		"duplicate pass":                 good + lines[1] + "\n",
		"no final pass":                  strings.TrimSuffix(good, "PASS\n"),
		"near match":                     strings.Replace(good, manifest[1]+" ", manifest[1]+"Other ", 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vm.log")
			if err := os.WriteFile(path, []byte(log), 0600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("bash", "run-lsm-hooks.sh", "--check-log", path).CombinedOutput()
			if (err == nil) != (name == "pass") {
				t.Fatalf("oracle accepted=%v log=%q output=%s", err == nil, log, out)
			}
		})
	}
}

// Cover every block/WASM-feedback fixture that exists in the integration
// sources, and reject a manifest that selects a test that does not exist.
func TestLSMHooksGateManifestCoversEveryHookFixture(t *testing.T) {
	manifest := map[string]bool{}
	for _, name := range lsmHooksGateManifest(t) {
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
			if ok && strings.HasPrefix(fn.Name.Name, "Test") {
				defined[fn.Name.Name] = true
			}
		}
	}
	// New *Blocked hook regressions and the WASM feedback loop must be added to
	// the manifest or this gate fails. The explicit list pins the named task.
	for name := range defined {
		if strings.HasPrefix(name, "TestLSM_") && strings.HasSuffix(name, "Blocked") && !manifest[name] {
			t.Errorf("LSM hook fixture missing from strict PASS oracle: %s", name)
		}
	}
	for _, name := range []string{"TestLSM_WASMFeedbackLoop", "TestLSM_ExecBlocked", "TestLSM_ConnectBlocked", "TestLSM_BindBlocked", "TestLSM_ListenBlocked", "TestLSM_PtraceBlocked", "TestLSM_MountBlocked"} {
		if !manifest[name] {
			t.Errorf("required hook/WASM fixture missing from strict PASS oracle: %s", name)
		}
	}
	for name := range manifest {
		if !defined[name] {
			t.Errorf("required fixture does not exist (would mis-select the gate): %s", name)
		}
	}
}

func TestLSMHooksGateRunnerSafetyAndEvidence(t *testing.T) {
	data, err := os.ReadFile("run-lsm-hooks.sh")
	if err != nil {
		t.Fatal(err)
	}
	runner := string(data)
	for _, required := range []string{
		"set -euo pipefail",
		`CGO_ENABLED=0 go test -c -tags integration -o "$ARTIFACTS/kernel.test" ./internal/ebpf`,
		`required_tests > "$ARTIFACTS/required-tests.txt"`,
		`WARMOR_REQUIRE_BPF_LSM=1`,
		`bash tests/integration/run-vm.sh lsm-hooks "$ARTIFACTS"`,
		`"$VIMTO" -kernel "$KERNEL" exec -- "$ARTIFACTS/kernel.test"`,
		`check_log "$ARTIFACTS/lsm-hooks.log"`,
		`-test.count=1`, `-test.timeout=120s`,
		`"$ROOT"/internal/ebpf/*_bpf*.o`, `"$ROOT"/internal/ebpf/*_bpf*.go`,
		`"$ROOT"/bpf/*.bpf.c`, `"$ROOT"/bpf/*.h`, `sha256sum "$KERNEL"`,
	} {
		if !strings.Contains(runner, required) {
			t.Errorf("missing strict gate requirement: %s", required)
		}
	}
	if strings.Contains(runner, "sudo ") || strings.Contains(runner, "go test -v") {
		t.Fatal("no host enforcement fallback or second untracked VM compilation")
	}
	for _, args := range [][]string{{"--host"}, {"--build-only", "extra"}, {"--check-log"}, {"--help", "extra"}} {
		cmd := exec.Command("bash", append([]string{"run-lsm-hooks.sh"}, args...)...)
		err := cmd.Run()
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 {
			t.Fatalf("arguments %v must fail closed with usage exit: %v", args, err)
		}
	}
}

func TestLSMHooksGateWorkflow(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/lsm-test.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		On map[string]struct {
			Paths []string `yaml:"paths"`
		} `yaml:"on"`
		Jobs map[string]struct {
			Continue any `yaml:"continue-on-error"`
			Timeout  int `yaml:"timeout-minutes"`
			Steps    []struct {
				Run, Uses, If string
				Env           map[string]string
				With          struct{ Path string }
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	job, ok := workflow.Jobs["kernel-generations-strict"]
	if !ok || (job.Continue != nil && job.Continue != false) || job.Timeout == 0 {
		t.Fatal("missing required bounded strict VM job (must not allow failure)")
	}
	ran, checkedOracles, retained, checkedRunner := false, false, false, false
	for _, step := range job.Steps {
		if strings.Contains(step.Run, "bash -n tests/integration/run-lsm-hooks.sh") &&
			strings.Contains(step.Run, "-run '^TestLSMHooksGate'") {
			checkedOracles = true
		}
		if strings.Contains(step.Run, "bash tests/integration/run-lsm-hooks.sh") {
			if step.If != "" || strings.Contains(step.Run, "--build-only") ||
				!strings.Contains(step.Env["KERNEL"], "/kernel-out/vmlinuz") ||
				!strings.Contains(step.Env["EXPECT_KERNEL_MINOR"], "matrix.minor") {
				t.Fatal("LSM hook VM phase must be unconditional with an explicit built kernel")
			}
			ran = true
		}
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") && step.If == "always()" &&
			strings.Contains(step.With.Path, "lsm-hooks.*/**") {
			retained = true
		}
		checkedRunner = checkedRunner || strings.Contains(step.Run, "go generate ./internal/ebpf")
	}
	if !ran || !checkedOracles || !retained || !checkedRunner {
		t.Fatal("must regenerate BPF, check strict oracles offline, run the hook VM phase and retain evidence")
	}
	for _, event := range []string{"push", "pull_request"} {
		for _, path := range []string{"tests/integration/run-lsm-hooks.sh", "tests/integration/lsm_hooks_gate_test.go"} {
			if !strings.Contains(strings.Join(workflow.On[event].Paths, ","), path) {
				t.Fatalf("%s doesn't trigger gate changes to %s", event, path)
			}
		}
	}
}

// The new phase must work with the same fake-vimto harness as every other
// run-vm.sh phase: propagate launcher failures and retain both output streams.
func TestLSMHooksGateVMPhaseFailuresPropagate(t *testing.T) {
	for _, code := range []string{"0", "7", "124", "137"} {
		t.Run(code, func(t *testing.T) {
			dir := t.TempDir()
			fake := filepath.Join(dir, "vimto")
			script := "#!/bin/sh\necho guest-stdout\necho boot-stderr >&2\nexit " + code + "\n"
			if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "run-vm.sh", "lsm-hooks", dir, fake)
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
			log, err := os.ReadFile(filepath.Join(dir, "lsm-hooks.log"))
			if err != nil || !strings.Contains(string(log), "guest-stdout") || !strings.Contains(string(log), "boot-stderr") {
				t.Fatalf("retain both VM output streams: %q %v", log, err)
			}
			status, err := os.ReadFile(filepath.Join(dir, "lsm-hooks-status.txt"))
			if err != nil || !strings.Contains(string(status), "phase=lsm-hooks\n") || !strings.Contains(string(status), "exit="+code) {
				t.Fatalf("retain VM phase exit: %q %v", status, err)
			}
			if code != "0" && !strings.Contains(string(status), "deadline_expired=false") {
				t.Fatalf("launcher exit %s without a deadline must not be classified as one: %s", code, status)
			}
		})
	}
}
