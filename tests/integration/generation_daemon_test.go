//go:build linux && integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/policyserver"
	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Preparation is host-safe: compile actual policies, never start a daemon or
// attach hooks. The guest receives these exact hashed modules and executables.
func TestPrepareGenerationDaemonArtifacts(t *testing.T) {
	if os.Getenv("WARMOR_OUTCOME_PREPARE") != "1" {
		t.Skip("explicit runner preparation only")
	}
	dir := artifactDir(t)
	if !compiler.CargoAvailable() {
		t.Fatal("generation daemon gate requires real Cargo/wasm32 compilation")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"allowed", "first-denied", "reload-denied", "rule-audit", "global-audit", "file-victim"} {
		copyExecutable(t, self, filepath.Join(dir, name))
	}
	for _, version := range []string{"A", "B"} {
		allowedMode, changedMode := "    mode: audit\n", ""
		if version == "B" {
			allowedMode, changedMode = "", "    mode: audit\n"
		}
		source := fmt.Sprintf(`name: generation-daemon-%s
version: 1
default_action: deny
rules:
  - name: old-allowed-new-denied
    event: process
    conditions:
      all:
        - path: {eq: %q}
    action: deny
%s  - name: persistent-audit-probe
    event: process
    conditions:
      all:
        - path: {eq: %q}
    action: deny
    mode: audit
  - name: old-denied-new-allowed
    event: process
    conditions:
      all:
        - path: {eq: %q}
    action: deny
%s  - name: allow-fixture-file-io
    event: file
    conditions:
      all:
        - path: {glob: "*"}
    action: allow
`, version, filepath.Join(guestFixtureDir, "allowed"), allowedMode,
			filepath.Join(guestFixtureDir, "rule-audit"), filepath.Join(guestFixtureDir, "reload-denied"), changedMode)
		mustWrite(t, filepath.Join(dir, "generation-"+version+".yaml"), []byte(source), 0644)
		policy, err := compiler.Parse([]byte(source))
		if err != nil {
			t.Fatal(err)
		}
		built, err := compiler.Build(policy, compiler.BuildOptions{OutputPath: filepath.Join(dir, "generation-"+version+".wasm")})
		if err != nil {
			t.Fatal(err)
		}
		compiler.Cleanup(built)
		rt, err := wasm.NewRuntime(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := rt.LoadPolicy(context.Background(), filepath.Join(dir, "generation-"+version+".wasm")); err != nil {
			_ = rt.Close(context.Background())
			t.Fatal(err)
		}
		pool, err := wasm.NewPool(context.Background(), rt, 1)
		if err != nil {
			_ = rt.Close(context.Background())
			t.Fatal(err)
		}
		eval := wasm.NewPolicyEvaluator(pool, "generation-prepare")
		if !eval.StaticRulesProcess().Eligible || !eval.StaticRulesNetwork().Eligible {
			t.Fatal("compiled opposing policies must have complete exec AND connect domains")
		}
		want := api.ActionDeny
		result, err := eval.Evaluate(context.Background(), &api.Event{Filename: filepath.Join(guestFixtureDir, "allowed")})
		if err != nil || result.Action != want || result.Audit != (version == "A") {
			t.Fatalf("compiled %s policy is not opposing: %+v %v", version, result, err)
		}
		auditResult, err := eval.Evaluate(context.Background(), &api.Event{Filename: filepath.Join(guestFixtureDir, "rule-audit")})
		wantAction, wantAudit := api.ActionDeny, true
		if err != nil || auditResult.Action != wantAction || auditResult.Audit != wantAudit {
			t.Fatalf("compiled audit probe lost semantics: %+v %v", auditResult, err)
		}
		if err := eval.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := rt.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(t, filepath.Join(dir, "invalid-generation.wasm"), []byte("compiler-rejected invalid WASM candidate"), 0644)
}

type generationControl struct {
	HoldID      uint64
	HoldPath    string
	FailDurable bool
	FailDrain   bool
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

func atomicFixtureWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	mustWrite(t, path+".next", data, 0644)
	if err := os.Rename(path+".next", path); err != nil {
		t.Fatal(err)
	}
}

func controlGeneration(t *testing.T, dir string, c generationControl) {
	t.Helper()
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	atomicFixtureWrite(t, filepath.Join(dir, "control.json"), data)
}

func generationStatus(t *testing.T, dir, stage string, id uint64) {
	t.Helper()
	waitFor(t, fmt.Sprintf("%s generation %d", stage, id), func() bool {
		_, err := os.Stat(filepath.Join(dir, fmt.Sprintf("%s-%d.json", stage, id)))
		return err == nil
	})
}

func readGenerationEvidence(t *testing.T, dir string) []daemonGenerationEvidence {
	t.Helper()
	if data, err := os.ReadFile(filepath.Join(dir, "instrumentation-error.txt")); err == nil {
		t.Fatalf("profile evidence failed: %s", data)
	}
	data, err := os.ReadFile(filepath.Join(dir, "evidence.ndjson"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []daemonGenerationEvidence
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		var e daemonGenerationEvidence
		if json.Unmarshal(line, &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

func requireGenerationEvidence(t *testing.T, dir string, match func(daemonGenerationEvidence) bool) {
	t.Helper()
	waitFor(t, "captured generation/verdict/scope evidence", func() bool {
		for _, e := range readGenerationEvidence(t, dir) {
			if match(e) {
				return true
			}
		}
		return false
	})
}

func requireGenerationDaemonVM(t *testing.T) {
	t.Helper()
	if os.Getenv("WARMOR_GENERATION_DAEMON_VM") != "1" || os.Getenv("WARMOR_OUTCOME_VM") != "1" {
		t.Fatal("generation daemon gate must be explicitly run in disposable vimto; no skip")
	}
	requireOutcomeVM(t) // actual init, private ports, uid, LSM before any fixture
	version, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatal(err)
	}
	minor := os.Getenv("WARMOR_EXPECT_KERNEL_MINOR")
	if (minor != "6.1" && minor != "6.18") || !strings.HasPrefix(string(version), minor+".") {
		t.Fatalf("wrong kernel: got=%q expected=%q", version, minor)
	}
	verifyPreparedHashes(t)
}

func generationControlDir(t *testing.T, name string) string {
	t.Helper()
	dir := "/var/tmp/warmor-generation-" + name
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	controlGeneration(t, dir, generationControl{})
	t.Cleanup(func() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Error(err)
			return
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Error(err)
				continue
			}
			mustWrite(t, filepath.Join(artifactDir(t), name+"-"+entry.Name()), data, 0644)
		}
	})
	return dir
}

func heldGenerationHelper(t *testing.T, f *outcomeFixture, binary, marker string) (int, func()) {
	t.Helper()
	cmd := f.helper(t, binary, marker, "", 0)
	cmd.Env = append(cmd.Env, "WARMOR_OUTCOME_HOLD=1")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = input.Write([]byte{'x'})
			_ = input.Close()
			if err := waitCommand(cmd, outcomeTimeout); err != nil {
				t.Errorf("held helper did not survive old/new routing: %v stderr=%s", err, &stderr)
			}
		})
	}
	t.Cleanup(release)
	waitReady(t, output)
	f.checkMarker(t, marker, true)
	return cmd.Process.Pid, release
}

func checkGenerationVerdicts(t *testing.T, dir string, scoped uint64) {
	t.Helper()
	for _, e := range readGenerationEvidence(t, dir) {
		if e.Generation == nil {
			t.Fatalf("uncaptured evidence: %+v", e)
		}
		if e.CgroupID != scoped {
			t.Fatalf("cross-scope evidence: %+v expected cgroup=%d", e, scoped)
		}
		if e.LSM && *e.Generation != e.KernelGeneration {
			t.Fatalf("current relabel replaced captured kernel generation: %+v", e)
		}
		if e.Phase != "decision" || !e.LSM || e.Hook != "exec" {
			continue
		}
		if *e.Generation != 1 && *e.Generation != 2 {
			t.Fatalf("unexpected extra publication: %+v", e)
		}
		name := filepath.Base(e.Filename)
		if name == "first-denied" || name == "global-audit" || (name == "allowed" && *e.Generation == 2) || (name == "reload-denied" && *e.Generation == 1) {
			if e.Decision != "DENY" || !e.KernelDenied || !e.Enforced || e.Attempted {
				t.Fatalf("kernel denial not associated with exact snapshot: %+v", e)
			}
		} else if name == "allowed" || name == "reload-denied" {
			if e.Decision != "DENY" || !e.Audit || e.KernelDenied || e.Enforced || e.Attempted {
				t.Fatalf("old/new opposing evaluator mismatch: %+v", e)
			}
		}
	}
}

func continuousGenerationDeny(t *testing.T, f *outcomeFixture) func() {
	t.Helper()
	stop, done := make(chan struct{}), make(chan struct{})
	var attempts atomic.Int32
	var failure string // published by done
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			cmd := f.helper(t, "global-audit", fmt.Sprintf("generation-never-allowed-%d", i), "", 0)
			err := cmd.Start()
			if err == nil {
				_ = waitCommand(cmd, outcomeTimeout)
				failure = "invariant deny anchor executed during reload"
				return
			}
			if !isEPERM(err) {
				failure = fmt.Sprintf("deny anchor got non-EPERM: %v", err)
				return
			}
			attempts.Add(1)
			time.Sleep(10 * time.Millisecond)
		}
	}()
	var once sync.Once
	finish := func() {
		once.Do(func() {
			close(stop)
			<-done
			if failure != "" {
				t.Error(failure)
			}
			if attempts.Load() < 2 {
				t.Error("concurrent deny loop did not exercise reload")
			}
		})
	}
	t.Cleanup(finish)
	waitFor(t, "first concurrent invariant denial", func() bool {
		select {
		case <-done:
			t.Fatal(failure)
		default:
		}
		return attempts.Load() > 0
	})
	return finish
}

// Control-artifact installation rejects the same real compiler-invalid module
// tested below. It is not a privileged operation and is safe to run on the host.
func TestGenerationDaemonBadCandidateCompilerOracle(t *testing.T) {
	if _, err := compiler.Parse([]byte("name: broken\nversion: 1\ndefault_action: maybe\nrules: []\n")); err == nil {
		t.Fatal("malformed compiler update accepted")
	}
	rt, err := wasm.NewRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := rt.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	if err := rt.LoadPolicyBytes(context.Background(), []byte("compiler-rejected invalid WASM candidate")); err == nil {
		t.Fatal("invalid artifact accepted")
	}
}

func TestDaemonGenerationOutcomes(t *testing.T) {
	requireGenerationDaemonVM(t)
	t.Cleanup(func() {
		if !t.Failed() {
			mustWrite(t, filepath.Join(artifactDir(t), "generation-daemon-success.txt"), []byte("whole-daemon generation outcomes passed in vimto\n"), 0644)
		}
	}) // registered before fixture cleanup: success only after cleanup also passes
	f := newFixture(t)
	info, err := os.Stat(f.cgroup)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("cgroup inode unavailable")
	}
	scope := stat.Ino
	// Sibling outside the configured cgroup must stay unaffected by either map.
	outside := filepath.Join(f.cgroup + "-outside")
	if err := os.Mkdir(outside, 0755); err != nil {
		t.Fatal(err)
	}
	fd, err := os.Open(outside)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = fd.Close()
		if err := os.Remove(outside); err != nil {
			t.Error(err)
		}
	})
	other := *f
	other.fd = fd
	other.runAllowed(t, "first-denied", "outside-baseline", 0)
	f.runAllowed(t, "allowed", "generation-baseline-A", 0)
	f.runAllowed(t, "reload-denied", "generation-baseline-B", 0)
	t.Run("opposing-captured-reload-LKG-and-idle-shutdown", func(t *testing.T) {
		control := generationControlDir(t, "reload")
		active := f.activePolicy(t, "generation-active", filepath.Join(f.dir, "generation-A.wasm"))
		d := f.startDaemon(t, "generation-reload", active, "--experimental-atomic-generations", "--default-deny", "--eval-timeout", "2s", "--generation-vm-control", control)
		t.Cleanup(func() { controlGeneration(t, control, generationControl{}) }) // failure cleanup must unblock before releasing helpers
		f.requireFirstDenied(t, "reload-denied", "generation-A-first-denied")
		controlGeneration(t, control, generationControl{HoldID: 1, HoldPath: filepath.Join(f.work, "allowed")})
		oldPID, releaseOld := heldGenerationHelper(t, f, "allowed", "generation-old-held")
		generationStatus(t, control, "event", 1)
		stopDeny := continuousGenerationDeny(t, f)
		f.requireFirstDenied(t, "first-denied", "generation-old-queued-denial")
		oldAuditPID, releaseOldAudit := heldGenerationHelper(t, f, "rule-audit", "generation-old-audit-held")
		requireGenerationEvidence(t, control, func(e daemonGenerationEvidence) bool {
			return e.Phase == "capture" && e.LSM && e.PID == uint32(oldAuditPID) && e.Generation != nil && *e.Generation == 1
		})
		b, err := os.ReadFile(filepath.Join(f.dir, "generation-B.wasm"))
		if err != nil {
			t.Fatal(err)
		}
		atomicFixtureWrite(t, active, b) // real standalone watcher activates immutable bytes
		generationStatus(t, control, "live", 2)
		generationStatus(t, control, "before-drain", 2)
		if _, err := os.Stat(filepath.Join(control, "retired-1.json")); !os.IsNotExist(err) {
			t.Fatal("old evaluator retired while held event still active")
		}
		// First new operations must see complete B even while A's userspace
		// worker and old ring samples have not drained. No sleep/retry-to-deny.
		f.requireFirstDenied(t, "allowed", "generation-B-first-denied")
		newPID, releaseNew := heldGenerationHelper(t, f, "reload-denied", "generation-new-held")
		_, releaseNewAudit := heldGenerationHelper(t, f, "rule-audit", "generation-new-audit-held")
		other.runAllowed(t, "first-denied", "outside-during-switch", 0)
		requireGenerationEvidence(t, control, func(e daemonGenerationEvidence) bool {
			return e.Phase == "capture" && e.LSM && e.PID == uint32(newPID) && e.Generation != nil && *e.Generation == 2
		})
		controlGeneration(t, control, generationControl{})
		generationStatus(t, control, "retired", 1)
		requireGenerationEvidence(t, control, func(e daemonGenerationEvidence) bool {
			return e.Phase == "decision" && e.LSM && e.PID == uint32(oldPID) && e.Generation != nil && *e.Generation == 1 && e.Decision == "DENY" && e.Audit && !e.Attempted
		})
		requireGenerationEvidence(t, control, func(e daemonGenerationEvidence) bool {
			return e.Phase == "decision" && e.LSM && e.PID == uint32(newPID) && e.Generation != nil && *e.Generation == 2 && e.Decision == "DENY" && e.Audit && !e.Attempted
		})
		requireGenerationEvidence(t, control, func(e daemonGenerationEvidence) bool {
			return e.Phase == "decision" && e.LSM && filepath.Base(e.Filename) == "first-denied" && e.Generation != nil && *e.Generation == 1 && e.KernelDenied && e.Decision == "DENY"
		})
		requireGenerationEvidence(t, control, func(e daemonGenerationEvidence) bool {
			return e.Phase == "decision" && e.LSM && filepath.Base(e.Filename) == "allowed" && e.Generation != nil && *e.Generation == 2 && e.KernelDenied && e.Decision == "DENY"
		})
		for _, pid := range []uint32{uint32(oldPID), uint32(newPID)} {
			d.requireEvent(t, func(e streaming.SecurityEvent) bool {
				return e.PID == pid && e.CgroupID == scope && e.Decision == "deny" && e.AuditOnly && !e.Enforced && !e.EnforcementAttempted
			})
		}
		// Both generations must also drain same-verdict audit work, including
		// old samples queued while the event worker was held.
		for _, expected := range []struct {
			id       uint64
			decision string
			audit    bool
		}{{1, "DENY", true}, {2, "DENY", true}} {
			requireGenerationEvidence(t, control, func(e daemonGenerationEvidence) bool {
				return e.Phase == "decision" && e.LSM && e.Generation != nil && *e.Generation == expected.id && filepath.Base(e.Filename) == "rule-audit" && e.Decision == expected.decision && e.Audit == expected.audit && !e.KernelDenied && !e.Enforced && !e.Attempted
			})
		}
		releaseOld()
		releaseNew()
		releaseOldAudit()
		releaseNewAudit()
		stopDeny()
		// Invalid compiler output must not become a new generation or create
		// a clear/rebuild window. Actual enforcer load rejects it; B is LKG.
		d.rejectReload(t, active)
		f.requireFirstDenied(t, "allowed", "generation-LKG-denied")
		f.runAllowed(t, "reload-denied", "generation-LKG-allowed", 0)
		// Idle rings: no further operation is needed to wake Stop/Close.
		d.stop(t) // actual SIGTERM exit 0, never harness SIGKILL as success
		checkGenerationVerdicts(t, control, scope)
	})
	t.Run("fleet-live-durable-and-drain-pending-no-false-ack", func(t *testing.T) {
		control := generationControlDir(t, "fleet")
		srv := policyserver.NewServer(policyserver.ServerConfig{Insecure: true})
		if err := srv.Store().CreatePolicy(&policyserver.Policy{ID: "generation"}, filepath.Join(f.dir, "generation-A.wasm")); err != nil {
			t.Fatal(err)
		}
		ts := httptest.NewServer(srv.Handler())
		defer ts.Close()
		active := f.activePolicy(t, "generation-fleet-active", filepath.Join(f.dir, "generation-A.wasm"))
		d := f.startDaemon(t, "generation-fleet", active, "--experimental-atomic-generations", "--default-deny", "--eval-timeout", "2s", "--generation-vm-control", control, "--server", ts.URL, "--agent-id", "generation-vm", "--poll-interval", "100ms")
		t.Cleanup(func() { controlGeneration(t, control, generationControl{}) })
		// Initial desired A is reactivated by fleet once; the live B below
		// must remain generation 3 across every failed recovery attempt.
		waitFor(t, "fleet A acknowledged", func() bool {
			a, ok := srv.Store().GetAgent("generation-vm")
			return ok && a.PolicyVersion == 1 && a.PolicyID == "generation" && a.PolicyHash != "" && a.ActivationError == ""
		})
		generationStatus(t, control, "retired", 1)
		controlGeneration(t, control, generationControl{FailDurable: true, FailDrain: true})
		if err := srv.Store().AddVersion("generation", filepath.Join(f.dir, "generation-B.wasm"), nil, true); err != nil {
			t.Fatal(err)
		}
		generationStatus(t, control, "live", 3)
		generationStatus(t, control, "durable-sync", 3)
		assertPending := func(message string) {
			t.Helper()
			waitFor(t, "unknown/error fleet acknowledgement: "+message, func() bool {
				a, ok := srv.Store().GetAgent("generation-vm")
				return ok && a.PolicyID == "" && a.PolicyHash == "" && a.PolicyVersion == 0 && strings.Contains(a.ActivationError, message)
			})
		}
		assertPending("durable-sync")
		f.requireFirstDenied(t, "allowed", "fleet-pending-durable-denied")
		f.runAllowed(t, "reload-denied", "fleet-pending-durable-allowed", 0)
		// Failed disk barrier rolled back disk only, never live B.
		aBytes, err := os.ReadFile(filepath.Join(f.dir, "generation-A.wasm"))
		if err != nil {
			t.Fatal(err)
		}
		waitFor(t, "durable fault restores old boot revision", func() bool { onDisk, err := os.ReadFile(active); return err == nil && bytes.Equal(onDisk, aBytes) })
		controlGeneration(t, control, generationControl{FailDrain: true})
		generationStatus(t, control, "before-drain", 3)
		assertPending("pending drain")
		f.requireFirstDenied(t, "allowed", "fleet-pending-drain-denied")
		f.runAllowed(t, "reload-denied", "fleet-pending-drain-allowed", 0)
		if _, err := os.Stat(filepath.Join(control, "retired-2.json")); !os.IsNotExist(err) {
			t.Fatal("pending drain retired previous evaluator")
		}
		controlGeneration(t, control, generationControl{})
		generationStatus(t, control, "retired", 2)
		bBytes, err := os.ReadFile(filepath.Join(f.dir, "generation-B.wasm"))
		if err != nil {
			t.Fatal(err)
		}
		bHash := fmt.Sprintf("%x", sha256.Sum256(bBytes))
		waitFor(t, "fleet B acknowledged only after same-generation recovery", func() bool {
			a, ok := srv.Store().GetAgent("generation-vm")
			return ok && a.PolicyID == "generation" && a.PolicyVersion == 2 && a.PolicyHash == bHash && a.ActivationError == ""
		})
		if _, err := os.Stat(filepath.Join(control, "live-4.json")); !os.IsNotExist(err) {
			t.Fatal("pending retry republished a third candidate")
		}
		f.requireFirstDenied(t, "allowed", "fleet-recovered-denied")
		f.runAllowed(t, "reload-denied", "fleet-recovered-allowed", 0)
		other.runAllowed(t, "first-denied", "outside-after-recovery", 0)
		mustWrite(t, filepath.Join(f.dir, "generation-fleet.metrics"), []byte(d.scrape()), 0644)
		d.stop(t)
		for _, e := range readGenerationEvidence(t, control) {
			if e.Generation == nil || e.CgroupID != scope || (e.LSM && *e.Generation != e.KernelGeneration) {
				t.Fatalf("fleet recovery lost captured generation/scope: %+v", e)
			}
		}
	})
	t.Run("SIGTERM-cancels-held-generation-worker", func(t *testing.T) {
		control := generationControlDir(t, "shutdown")
		d := f.startDaemon(t, "generation-worker-stop", filepath.Join(f.dir, "generation-A.wasm"), "--experimental-atomic-generations", "--default-deny", "--eval-timeout", "2s", "--generation-vm-control", control)
		controlGeneration(t, control, generationControl{HoldID: 1, HoldPath: filepath.Join(f.work, "allowed")})
		_, release := heldGenerationHelper(t, f, "allowed", "generation-stop-held")
		t.Cleanup(func() { controlGeneration(t, control, generationControl{}) })
		generationStatus(t, control, "event", 1)
		// Event-loop work is deliberately pending and sensors have no further
		// wakeup-producing operations. Cancellation, not a synthetic event,
		// must release the lease and close both generations safely.
		d.stop(t)
		release()
	})
}
