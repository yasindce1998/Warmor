//go:build linux

package integration

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/policyserver"
	"gopkg.in/yaml.v3"
)

type generationHeartbeatReceipt struct {
	ReceivedNS int64 // fixture CLOCK_MONOTONIC sampled at HTTP handler entry
	ObservedNS int64 // fixture clock after reading the atomic phase records
	LiveNS     int64 // actual live-3 checkpoint; zero means no record observed
	RetiredNS  int64 // actual retired-2 checkpoint; zero means no record observed
	Heartbeat  policyserver.HeartbeatRequest
}

// Evaluate EVERY receipt, not just those following an unknown/error heartbeat.
// Phase records read during decoding may be newer than request arrival: they
// cannot retroactively authorize an early B or disqualify a pre-live A.
func validateGenerationHeartbeatReceipt(r generationHeartbeatReceipt) error {
	if r.ReceivedNS <= 0 || r.ObservedNS < r.ReceivedNS || r.LiveNS < 0 || r.RetiredNS < 0 || r.LiveNS > r.ObservedNS || r.RetiredNS > r.ObservedNS {
		return errors.New("invalid/future phase or fixture receipt clock")
	}
	if r.RetiredNS != 0 && (r.LiveNS == 0 || r.RetiredNS < r.LiveNS) {
		return errors.New("retirement without ordered live publication")
	}
	h := r.Heartbeat
	// Any nonempty identity is a claim, even if its version/error is mixed.
	claimed := h.PolicyVersion != 0 || h.PolicyID != "" || h.PolicyHash != ""
	if h.PolicyVersion == 2 && (r.RetiredNS == 0 || r.RetiredNS > r.ReceivedNS) {
		return errors.New("B acknowledged before retirement, independent of pending heartbeat")
	}
	if r.LiveNS != 0 && r.LiveNS <= r.ReceivedNS && claimed {
		if h.PolicyVersion != 2 || h.PolicyID != "generation" || h.PolicyHash == "" || h.ActivationError != "" || r.RetiredNS == 0 || r.RetiredNS > r.ReceivedNS {
			return errors.New("old/mixed or premature active acknowledgement after live publication")
		}
	}
	return nil
}

func TestGenerationDaemonGateHeartbeatTranscriptOracle(t *testing.T) {
	a := policyserver.HeartbeatRequest{PolicyID: "generation", PolicyVersion: 1, PolicyHash: "hash-A"}
	b := policyserver.HeartbeatRequest{PolicyID: "generation", PolicyVersion: 2, PolicyHash: "hash-B"}
	pending := policyserver.HeartbeatRequest{ActivationError: "pending drain"}
	receipt := func(at, live, retired int64, h policyserver.HeartbeatRequest) generationHeartbeatReceipt {
		return generationHeartbeatReceipt{ReceivedNS: at, ObservedNS: 100, LiveNS: live, RetiredNS: retired, Heartbeat: h}
	}
	for name, tc := range map[string]struct {
		receipts []generationHeartbeatReceipt
		valid    bool
	}{
		// Exact reported counterexample: B success appears before the FIRST
		// unknown heartbeat, then pending, retirement, and eventual B success.
		"early B before unknown then pending retired B": {[]generationHeartbeatReceipt{receipt(10, 0, 0, a), receipt(30, 20, 0, b), receipt(40, 20, 0, pending), receipt(60, 20, 50, b)}, false},
		"old A after live without error":                {[]generationHeartbeatReceipt{receipt(10, 0, 0, a), receipt(30, 20, 0, a), receipt(40, 20, 0, pending), receipt(60, 20, 50, b)}, false},
		"correct prelive A pending retired B":           {[]generationHeartbeatReceipt{receipt(10, 0, 0, a), receipt(30, 20, 0, pending), receipt(40, 20, 0, pending), receipt(60, 20, 50, b)}, true},
		"prelive A decoded after live":                  {[]generationHeartbeatReceipt{receipt(10, 20, 0, a), receipt(30, 20, 0, pending), receipt(60, 20, 50, b)}, true},
		"early B decoded after retirement":              {[]generationHeartbeatReceipt{receipt(30, 20, 50, b), receipt(40, 20, 50, pending), receipt(60, 20, 50, b)}, false},
		"early B before any live artifact":              {[]generationHeartbeatReceipt{receipt(10, 0, 0, b)}, false},
		"old A after retirement":                        {[]generationHeartbeatReceipt{receipt(60, 20, 50, a)}, false},
		"self reported future phase":                    {[]generationHeartbeatReceipt{receipt(60, 20, 101, b)}, false},
		"retirement precedes live":                      {[]generationHeartbeatReceipt{receipt(60, 50, 20, b)}, false},
	} {
		t.Run(name, func(t *testing.T) {
			valid := true
			for _, r := range tc.receipts {
				if validateGenerationHeartbeatReceipt(r) != nil {
					valid = false
				}
			}
			if valid != tc.valid {
				t.Fatalf("transcript accepted=%v want=%v: %+v", valid, tc.valid, tc.receipts)
			}
		})
	}
}

type daemonGenerationEvidence struct {
	Phase                                    string
	Generation                               *uint64
	KernelGeneration                         uint64
	LSM                                      bool
	Hook                                     string
	PID, UID                                 uint32
	CgroupID                                 uint64
	Filename, Decision                       string
	Audit, KernelDenied, Enforced, Attempted bool
}

// Same pure oracle is exercised with negative evidence on the host and real
// captured evidence in the VM. Counters or a claimed current ID cannot pass it.
func validateGenerationDaemonEvidence(e daemonGenerationEvidence, scoped uint64) error {
	if e.Generation == nil || e.PID == 0 || e.UID != 65534 || e.CgroupID != scoped {
		return errors.New("uncaptured, unattributed or cross-scope evidence")
	}
	if e.LSM && *e.Generation != e.KernelGeneration {
		return errors.New("current ID relabel replaced captured kernel generation")
	}
	if e.Phase != "decision" || !e.LSM || e.Hook != "exec" {
		return nil
	}
	if *e.Generation != 1 && *e.Generation != 2 {
		return errors.New("unexpected extra publication")
	}
	name := filepath.Base(e.Filename)
	denied := name == "first-denied" || name == "global-audit" || (name == "allowed" && *e.Generation == 2) || (name == "reload-denied" && *e.Generation == 1)
	if denied {
		if e.Decision != "DENY" || !e.KernelDenied || !e.Enforced || e.Attempted || e.Audit {
			return errors.New("kernel denial disagrees with exact snapshot/outcome")
		}
	} else if name == "allowed" || name == "reload-denied" || name == "rule-audit" {
		if e.Decision != "DENY" || !e.Audit || e.KernelDenied || e.Enforced || e.Attempted {
			return errors.New("old/new audited evaluator disagrees with exact snapshot")
		}
	}
	return nil
}

func TestGenerationDaemonGateLatePhaseRecordReconciliation(t *testing.T) {
	// The handler can read live.json before its atomic rename, even though
	// the checkpoint's monotonic sample already precedes this request.
	a := policyserver.HeartbeatRequest{PolicyID: "generation", PolicyVersion: 1, PolicyHash: "hash-A"}
	r := generationHeartbeatReceipt{ReceivedNS: 30, ObservedNS: 40, Heartbeat: a}
	if err := validateGenerationHeartbeatReceipt(r); err != nil {
		t.Fatal("snapshot cannot yet disqualify A", err)
	}
	r.LiveNS, r.RetiredNS, r.ObservedNS = 20, 50, 60
	if err := validateGenerationHeartbeatReceipt(r); err == nil {
		t.Fatal("late atomic live record exempted stale A forever")
	}
	// Later phases must not retroactively reject an actually pre-live A.
	r.ReceivedNS = 10
	if err := validateGenerationHeartbeatReceipt(r); err != nil {
		t.Fatal("later phase rejected pre-live A", err)
	}
}

func TestGenerationDaemonGateCapturedVerdictOracle(t *testing.T) {
	one, two := uint64(1), uint64(2)
	good := daemonGenerationEvidence{Phase: "decision", Generation: &one, KernelGeneration: 1, LSM: true, Hook: "exec", PID: 123, UID: 65534, CgroupID: 555, Filename: "/fixture/allowed", Decision: "DENY", Audit: true}
	for name, mutate := range map[string]func(*daemonGenerationEvidence){
		"pass":              func(*daemonGenerationEvidence) {},
		"missing capture":   func(e *daemonGenerationEvidence) { e.Generation = nil },
		"wrong scope":       func(e *daemonGenerationEvidence) { e.CgroupID++ },
		"wrong uid":         func(e *daemonGenerationEvidence) { e.UID = 0 },
		"unknown pid":       func(e *daemonGenerationEvidence) { e.PID = 0 },
		"current relabel":   func(e *daemonGenerationEvidence) { e.Generation = &two },
		"false allow":       func(e *daemonGenerationEvidence) { e.Decision = "ALLOW" },
		"mistaken kill":     func(e *daemonGenerationEvidence) { e.Attempted = true; e.Enforced = true },
		"missed prevention": func(e *daemonGenerationEvidence) { e.Generation = &two; e.KernelGeneration = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			e := good
			mutate(&e)
			if err := validateGenerationDaemonEvidence(e, 555); (err == nil) != (name == "pass") {
				t.Fatalf("accepted invalid association=%v evidence=%+v err=%v", name, e, err)
			}
		})
	}
	denied := good
	denied.Generation = &two
	denied.KernelGeneration = 2
	denied.Audit = false
	denied.KernelDenied = true
	denied.Enforced = true
	if err := validateGenerationDaemonEvidence(denied, 555); err != nil {
		t.Fatal(err)
	}
	denied.Enforced = false
	if err := validateGenerationDaemonEvidence(denied, 555); err == nil {
		t.Fatal("unproven prevention accepted")
	}
}

func TestGenerationDaemonGatePassOracle(t *testing.T) {
	const parent = "--- PASS: TestDaemonGenerationOutcomes (1.23s)\n"
	const reload = "    --- PASS: TestDaemonGenerationOutcomes/opposing-captured-reload-LKG-and-idle-shutdown (0.50s)\n"
	const recovery = "    --- PASS: TestDaemonGenerationOutcomes/fleet-live-durable-and-drain-pending-no-false-ack (0.50s)\n"
	const shutdown = "    --- PASS: TestDaemonGenerationOutcomes/SIGTERM-cancels-held-generation-worker (0.20s)\n"
	good := parent + reload + recovery + shutdown + "PASS\n"
	for name, log := range map[string]string{
		"pass":             good,
		"empty":            "",
		"missing child":    parent + reload + "PASS\n",
		"missing shutdown": parent + reload + recovery + "PASS\n",
		"missing parent":   reload + recovery + shutdown + "PASS\n",
		"no tests":         "testing: warning: no tests to run\nPASS\n",
		"skip":             good + "    --- SKIP: TestDaemonGenerationOutcomes/required (0.00s)\n",
		"fail":             good + "    --- FAIL: TestDaemonGenerationOutcomes/required (0.00s)\n",
		"panic":            good + "panic: unexpected fault\n",
		"duplicate":        good + parent,
		"no final PASS":    parent + reload + recovery,
		"near match":       strings.Replace(good, "Outcomes (", "OutcomesOther (", 1),
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
		for _, path := range []string{"internal/generationvm/**", "internal/platform/**", "tests/integration/generation_daemon_test.go", "tests/integration/outcomes_test.go", "tests/integration/helpers_test.go", "tests/integration/run-generation-daemon.sh"} {
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
