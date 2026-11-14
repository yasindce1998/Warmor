//go:build linux

package integration

import (
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

func TestGenerationDaemonGatePassOracle(t *testing.T) {
	const parent = "--- PASS: TestDaemonGenerationOutcomes (1.23s)\n"
	const reload = "    --- PASS: TestDaemonGenerationOutcomes/opposing-captured-reload-LKG-and-idle-shutdown (0.50s)\n"
	const recovery = "    --- PASS: TestDaemonGenerationOutcomes/fleet-live-durable-and-drain-pending-no-false-ack (0.50s)\n"
	const shutdown = "    --- PASS: TestDaemonGenerationOutcomes/SIGTERM-cancels-held-generation-worker (0.20s)\n"
	good := parent + reload + recovery + shutdown + "PASS\n"
	for name, log := range map[string]string{
		"pass":           good,
		"empty":          "",
		"missing child":  parent + reload + "PASS\n",
		"missing parent": reload + recovery + shutdown + "PASS\n",
		"no tests":       "testing: warning: no tests to run\nPASS\n",
		"skip":           good + "    --- SKIP: TestDaemonGenerationOutcomes/required (0.00s)\n",
		"fail":           good + "    --- FAIL: TestDaemonGenerationOutcomes/required (0.00s)\n",
		"panic":          good + "panic: unexpected fault\n",
		"duplicate":      good + parent,
		"no final PASS":  parent + reload + recovery,
		"near match":     strings.Replace(good, "Outcomes (", "OutcomesOther (", 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "log")
			if err := os.WriteFile(path, []byte(log), 0600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("bash", "run-generation-daemon.sh", "--check-log", path).CombinedOutput()
			if (err == nil) != (name == "pass") {
				t.Fatalf("accepted=%v log=%s output=%s", err == nil, log, out)
			}
		})
	}
}

func TestGenerationDaemonGateRunnerAndProfileSafety(t *testing.T) {
	data, err := os.ReadFile("run-generation-daemon.sh")
	if err != nil {
		t.Fatal(err)
	}
	runner := string(data)
	for _, required := range []string{
		"set -euo pipefail", "go build -tags 'integration generation_daemon_vm'", "go build -o \"$ARTIFACTS/warmor-daemon-release\"",
		`go test -c -tags integration -o "$ARTIFACTS/outcomes.test"`, `WARMOR_OUTCOME_PREPARE=1`, `^TestPrepareGenerationDaemonArtifacts$`,
		`WARMOR_OUTCOME_VM=1 WARMOR_GENERATION_DAEMON_VM=1`, `WARMOR_EXPECT_KERNEL_MINOR="$EXPECT_KERNEL_MINOR"`,
		`bash tests/integration/run-vm.sh generation-daemon "$ARTIFACTS"`, `"$VIMTO" -kernel "$KERNEL" exec -- "$ARTIFACTS/outcomes.test"`,
		`-test.timeout=240s -test.run '^TestDaemonGenerationOutcomes$'`, `check_log "$ARTIFACTS/generation-daemon.log"`,
		`"$ROOT"/internal/ebpf/*_bpf*.o`, `"$ROOT"/bpf/*.bpf.c`, `sha256sum "$KERNEL"`, `generation-daemon-success.txt`,
	} {
		if !strings.Contains(runner, required) {
			t.Errorf("missing runner constraint: %s", required)
		}
	}
	if strings.Contains(runner, "sudo ") || strings.Contains(runner, "go test -v") {
		t.Fatal("no host enforcing path or untracked VM build")
	}
	for _, args := range [][]string{{"--host"}, {"--build-only", "extra"}, {"--check-log"}} {
		cmd := exec.Command("bash", append([]string{"run-generation-daemon.sh"}, args...)...)
		if err := cmd.Run(); err == nil {
			t.Fatalf("unsafe arguments accepted: %v", args)
		}
	}
	for _, path := range []string{"../../internal/generationvm/profile.go", "../../cmd/warmor-daemon/generationvm_profile.go"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(data), "//go:build linux && integration && generation_daemon_vm\n") {
			t.Fatalf("fault seam leaked into production build: %s", path)
		}
		if strings.Contains(string(data), "os.Getenv") {
			t.Fatalf("profile must not arm through environment bypass: %s", path)
		}
	}
	guard, err := os.ReadFile("../../internal/generationvm/profile.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`os.Readlink("/proc/1/exe")`, `"/sys/class/virtio-ports/*/name"`, `ValidateGuard(initExe, ports)`, `"ctrl"`, `"stdio"`} {
		if !strings.Contains(string(guard), required) {
			t.Errorf("missing actual VM profile identity guard: %s", required)
		}
	}
}

func TestGenerationDaemonGateWorkflowBothKernels(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/lsm-test.yml")
	if err != nil {
		t.Fatal(err)
	}
	var w struct {
		On   map[string]struct{ Paths []string } `yaml:"on"`
		Jobs map[string]struct {
			Continue any `yaml:"continue-on-error"`
			Strategy struct {
				Matrix struct {
					Include []struct{ Version, Minor string }
				}
			}
			Steps []struct {
				Run, Uses, If string
				Env           map[string]string
				With          struct{ Path string }
			}
		}
	}
	if err := yaml.Unmarshal(data, &w); err != nil {
		t.Fatal(err)
	}
	job := w.Jobs["kernel-generations-strict"]
	if job.Continue != nil && job.Continue != false {
		t.Fatal("daemon outcomes must not allow failure")
	}
	seen := map[string]bool{}
	for _, item := range job.Strategy.Matrix.Include {
		seen[item.Version+"/"+item.Minor] = true
	}
	for _, want := range []string{"6.1.188/6.1", "6.18.53/6.18"} {
		if !seen[want] {
			t.Fatal("missing required kernel", want)
		}
	}
	ran, retained, cargo := false, false, false
	for _, step := range job.Steps {
		if strings.Contains(step.Run, "rustup target add wasm32-unknown-unknown") {
			cargo = true
		}
		if strings.Contains(step.Run, "bash tests/integration/run-generation-daemon.sh") {
			if !cargo || step.If != "" || strings.Contains(step.Run, "--build-only") || !strings.Contains(step.Env["KERNEL"], "/kernel-out/vmlinuz") || !strings.Contains(step.Env["EXPECT_KERNEL_MINOR"], "matrix.minor") {
				t.Fatal("daemon VM phase must be unconditional with real Cargo and built kernel")
			}
			ran = true
		}
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") && step.If == "always()" && strings.Contains(step.With.Path, "generation-daemon.*/**") {
			retained = true
		}
	}
	if !ran || !retained {
		t.Fatal("daemon VM or retained fault/outcome evidence missing")
	}
	for _, event := range []string{"push", "pull_request"} {
		for _, path := range []string{"internal/generationvm/**", "internal/platform/**", "tests/integration/generation_daemon_test.go", "tests/integration/run-generation-daemon.sh"} {
			if !strings.Contains(strings.Join(w.On[event].Paths, ","), path) {
				t.Errorf("%s trigger omits %s", event, path)
			}
		}
	}
}

func TestGenerationDaemonGateManifestHasGuardedFixture(t *testing.T) {
	manifest, err := exec.Command("bash", "run-generation-daemon.sh", "--list-tests").Output()
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "generation_daemon_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	defined := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			defined[fn.Name.Name] = fn
		}
	}
	for _, name := range strings.Fields(string(manifest)) {
		fn := defined[name]
		if fn == nil || fn.Body == nil || len(fn.Body.List) == 0 {
			t.Fatal("manifest mis-selects missing fixture", name)
		}
		expr, ok := fn.Body.List[0].(*ast.ExprStmt)
		if !ok {
			t.Fatal("VM guard must be first statement")
		}
		call, ok := expr.X.(*ast.CallExpr)
		if !ok {
			t.Fatal("first statement not guard call")
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != "requireGenerationDaemonVM" {
			t.Fatal("VM guard must precede side effects")
		}
	}
	if got := strings.TrimSpace(string(manifest)); got != "TestDaemonGenerationOutcomes" {
		t.Fatalf("unexpected manifest: %s", got)
	}
}
