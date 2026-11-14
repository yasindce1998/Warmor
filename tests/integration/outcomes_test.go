//go:build linux && integration

package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

const outcomeTimeout = 20 * time.Second

// Guest-local, traversable by uid 65534 even when the host checkout lives in
// a private home directory. Never chmod the shared host checkout or its parents.
const guestFixtureDir = "/var/tmp/warmor-outcome-fixtures"

func artifactDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("WARMOR_OUTCOME_ARTIFACTS")
	if !filepath.IsAbs(dir) {
		t.Fatal("WARMOR_OUTCOME_ARTIFACTS must name the absolute prepared artifact directory; use run-outcomes.sh")
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Fatalf("artifact directory is missing: %v", err)
	}
	return dir
}

func mustWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func copyExecutable(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, dst, data, 0755)
}

// Preparation compiles real compiler-generated policies on the host. It never
// starts the daemon or loads BPF. vimto does not need Rust in the guest.
func TestPrepareOutcomeArtifacts(t *testing.T) {
	if os.Getenv("WARMOR_OUTCOME_PREPARE") != "1" {
		t.Skip("host preparation is explicitly selected by run-outcomes.sh")
	}
	dir := artifactDir(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"allowed", "first-denied", "reload-denied", "rule-audit", "global-audit", "file-victim"} {
		copyExecutable(t, self, filepath.Join(dir, name))
	}
	if !compiler.CargoAvailable() {
		t.Fatal("requires cargo, rustup, and the wasm32-unknown-unknown target")
	}
	static := fmt.Sprintf(`name: outcome-static
version: 1
default_action: deny
rules:
  - name: allow-controlled-exec
    event: process
    conditions:
      all:
        - path: {eq: %q}
    action: allow
  - name: audit-controlled-exec
    event: process
    conditions:
      all:
        - path: {eq: %q}
    action: deny
    mode: audit
  - name: allow-fixture-file-IO
    event: file
    conditions:
      all:
        - path: {glob: "*"}
    action: allow
`, filepath.Join(guestFixtureDir, "allowed"), filepath.Join(guestFixtureDir, "rule-audit"))
	filePolicy := fmt.Sprintf(`name: outcome-file
version: 1
default_action: allow
rules:
  - name: terminate-nonroot-file-reader
    event: file
    conditions:
      all:
        - path: {eq: %q}
        - uid: {eq: 65534}
    action: deny
`, filepath.Join(guestFixtureDir, "watched-file"))
	for name, source := range map[string]string{"static": static, "file": filePolicy} {
		mustWrite(t, filepath.Join(dir, name+".yaml"), []byte(source), 0644)
		policy, err := compiler.Parse([]byte(source))
		if err != nil {
			t.Fatal(err)
		}
		built, err := compiler.Build(policy, compiler.BuildOptions{OutputPath: filepath.Join(dir, name+".wasm")})
		if err != nil {
			t.Fatal(err)
		}
		compiler.Cleanup(built)
		// Verify the generated WASM, not just YAML eligibility. These are the
		// artifacts the daemon will actually consume in the VM.
		rt, err := wasm.NewRuntime(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := rt.LoadPolicy(context.Background(), filepath.Join(dir, name+".wasm")); err != nil {
			rt.Close(context.Background())
			t.Fatal(err)
		}
		validatePreparedPolicy(t, name, rt)
		rt.Close(context.Background())
		t.Logf("compiled and runtime-validated %s.wasm", name)
	}
	mustWrite(t, filepath.Join(dir, "watched-file"), []byte("readable without daemon\n"), 0644)
}

func validatePreparedPolicy(t *testing.T, name string, rt *wasm.Runtime) {
	t.Helper()
	ctx := context.Background()
	pool, err := wasm.NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatal(err)
	}
	evaluator := wasm.NewPolicyEvaluator(pool, "outcome-prepare")
	defer evaluator.Close(ctx)
	check := func(kind api.EventType, path string, uid uint32, action api.Action, audit bool) {
		t.Helper()
		event := &api.Event{Type: kind, UID: uid, PID: 123, Filename: path}
		if kind == api.EventTypeFile {
			event.File = &api.FileEvent{Path: path}
		} else {
			event.Process = &api.ProcessEvent{Filename: path}
		}
		result, err := evaluator.Evaluate(ctx, event)
		if err != nil {
			t.Fatal(err)
		}
		if result.Action != action || result.Audit != audit {
			t.Fatalf("prepared %s policy: path=%s uid=%d got action=%s audit=%v; want action=%s audit=%v",
				name, path, uid, result.Action, result.Audit, action, audit)
		}
	}
	if name == "static" {
		if domain := evaluator.StaticRulesProcess(); !domain.Eligible || len(domain.Rules) != 2 {
			t.Fatalf("prepared static policy must expose eligible exec domain with 2 entries: %+v", domain)
		}
		check(api.EventTypeProcess, filepath.Join(guestFixtureDir, "allowed"), 65534, api.ActionAllow, false)
		check(api.EventTypeProcess, filepath.Join(guestFixtureDir, "first-denied"), 65534, api.ActionDeny, false)
		check(api.EventTypeProcess, filepath.Join(guestFixtureDir, "rule-audit"), 65534, api.ActionDeny, true)
		check(api.EventTypeFile, filepath.Join(guestFixtureDir, "markers", "allowed"), 65534, api.ActionAllow, false)
	} else {
		check(api.EventTypeFile, filepath.Join(guestFixtureDir, "watched-file"), 65534, api.ActionDeny, false)
		check(api.EventTypeFile, filepath.Join(guestFixtureDir, "watched-file"), 0, api.ActionAllow, false)
		check(api.EventTypeProcess, filepath.Join(guestFixtureDir, "file-victim"), 65534, api.ActionAllow, false)
	}
}

func requireOutcomeVM(t *testing.T) {
	t.Helper()
	if os.Getenv("WARMOR_OUTCOME_VM") != "1" {
		t.Skip("whole-daemon enforcement is VM-only; use tests/integration/run-outcomes.sh")
	}
	initExe, err := os.Readlink("/proc/1/exe")
	if err != nil {
		t.Fatal(err)
	}
	var ports []string
	paths, err := filepath.Glob("/sys/class/virtio-ports/*/name")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		ports = append(ports, string(data))
	}
	if err := verifyVM(os.Getenv("WARMOR_OUTCOME_VM"), initExe, ports); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		t.Fatal("VM test must run as root (the repository .vimto.toml selects root)")
	}
	lsm, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil || !strings.Contains(","+strings.TrimSpace(string(lsm))+",", ",bpf,") {
		t.Fatalf("BPF LSM is required, not a skip or observe fallback: lsm=%q err=%v", lsm, err)
	}
	kernel, err := os.ReadFile("/proc/version")
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(artifactDir(t), "guest-info.txt"), []byte(fmt.Sprintf("init=%s\nlsm=%s\nkernel=%s", initExe, lsm, kernel)), 0644)
}

type outcomeFixture struct {
	dir    string
	work   string
	cgroup string
	fd     *os.File
}

func newFixture(t *testing.T) *outcomeFixture {
	t.Helper()
	f := &outcomeFixture{dir: artifactDir(t), work: guestFixtureDir, cgroup: filepath.Join("/sys/fs/cgroup", fmt.Sprintf("warmor-outcomes-%d", os.Getpid()))}
	if err := os.Mkdir(f.work, 0755); err != nil {
		t.Fatalf("create VM-local fixture directory: %v", err)
	}
	for _, name := range []string{"allowed", "first-denied", "reload-denied", "rule-audit", "global-audit", "file-victim"} {
		copyExecutable(t, filepath.Join(f.dir, name), filepath.Join(f.work, name))
	}
	mustWrite(t, filepath.Join(f.work, "watched-file"), []byte("readable without daemon\n"), 0644)
	if err := os.Mkdir(f.cgroup, 0755); err != nil {
		t.Fatalf("create private cgroup v2: %v", err)
	}
	fd, err := os.Open(f.cgroup)
	if err != nil {
		t.Fatal(err)
	}
	f.fd = fd
	t.Cleanup(func() {
		fd.Close()
		markers, _ := os.ReadDir(filepath.Join(f.work, "markers"))
		for _, marker := range markers {
			data, err := os.ReadFile(filepath.Join(f.work, "markers", marker.Name()))
			if err != nil {
				t.Errorf("read marker: %v", err)
				continue
			}
			mustWrite(t, filepath.Join(f.dir, "marker-"+marker.Name()), data, 0644)
		}
		if err := os.Remove(f.cgroup); err != nil {
			t.Errorf("remove owned cgroup: %v", err)
		}
	})
	// uid 65534 must be able to write evidence without changing artifact ownership.
	if err := os.Mkdir(filepath.Join(f.work, "markers"), 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(f.work, "markers"), 0777); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *outcomeFixture) helper(t *testing.T, binary, marker, file string, delay time.Duration) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(filepath.Join(f.work, binary))
	cmd.Env = helperEnv(filepath.Join(f.work, "markers", marker), file, delay)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: 65534, Gid: 65534, NoSetGroups: false},
		// Place the child before its first exec. Moving a shell afterwards can
		// miss the first event or accidentally move the test/daemon itself.
		UseCgroupFD: true, CgroupFD: int(f.fd.Fd()),
	}
	return cmd
}

func (f *outcomeFixture) checkMarker(t *testing.T, marker string, want bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.work, "markers", marker))
	if !want {
		if !os.IsNotExist(err) {
			t.Fatalf("denied operation created a side effect: marker=%s data=%q err=%v", marker, data, err)
		}
		return
	}
	if err != nil || string(data) != "uid=65534\n" {
		t.Fatalf("successful nonroot operation missing side effect: marker=%s data=%q err=%v", marker, data, err)
	}
}

func (f *outcomeFixture) runAllowed(t *testing.T, binary, marker string, delay time.Duration) int {
	t.Helper()
	cmd := f.helper(t, binary, marker, "", delay)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("allowed %s failed to start: %v", binary, err)
	}
	pid := cmd.Process.Pid
	if err := waitCommand(cmd, outcomeTimeout); err != nil {
		t.Fatalf("allowed %s did not exit successfully: %v; output=%s", binary, err, &output)
	}
	f.checkMarker(t, marker, true)
	return pid
}

func (f *outcomeFixture) runAudited(t *testing.T, d *daemonProcess, binary, marker string) {
	t.Helper()
	cmd := f.helper(t, binary, marker, "", 0)
	cmd.Env = append(cmd.Env, "WARMOR_OUTCOME_HOLD=1")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("audit-only executable was refused: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	waitReady(t, output)
	f.checkMarker(t, marker, true)
	// Keep the child alive through actual policy evaluation (and event
	// delivery), rather than allowing a fast exit to outrun a mistaken kill.
	d.requireEvent(t, func(e streaming.SecurityEvent) bool {
		return e.PID == uint32(cmd.Process.Pid) && e.UID == 65534 && e.Decision == "deny" && e.AuditOnly && !e.Enforced
	})
	if _, err := input.Write([]byte{'x'}); err != nil {
		t.Fatalf("audit-only child did not survive evaluation: %v", err)
	}
	_ = input.Close()
	if err := waitCommand(cmd, outcomeTimeout); err != nil {
		t.Fatalf("audit-only child must exit normally after policy evaluation, got %v stderr=%s", err, &stderr)
	}
}

func waitReady(t *testing.T, output io.Reader) {
	t.Helper()
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(output).ReadString('\n')
		ready <- line
	}()
	select {
	case line := <-ready:
		if line != "READY uid=65534\n" {
			t.Fatalf("child never reached live nonroot readiness: %q", line)
		}
	case <-time.After(outcomeTimeout):
		t.Fatal("nonroot child readiness timed out; harness cleanup is not outcome proof")
	}
}

func waitCommand(cmd *exec.Cmd, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		// Never return the cleanup SIGKILL as the daemon's termination proof.
		return fmt.Errorf("timed out after %s (harness killed the child for cleanup)", timeout)
	}
}

func TestTimeoutCleanupIsNotTerminationProof(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "while :; do :; done")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	err := waitCommand(cmd, 10*time.Millisecond)
	if err == nil || wasSIGKILL(err) || !strings.Contains(err.Error(), "harness killed") {
		t.Fatalf("cleanup must report a timeout, never a daemon SIGKILL outcome: %v", err)
	}
}

type daemonProcess struct {
	cmd     *exec.Cmd
	done    chan error
	metrics string
	events  string
	log     string
}

func (f *outcomeFixture) startDaemon(t *testing.T, name, policy string, flags ...string) *daemonProcess {
	t.Helper()
	// Reserve an available VM-local port. A startup race fails closed below.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	d := &daemonProcess{
		metrics: fmt.Sprintf("http://127.0.0.1:%d/metrics", port),
		events:  filepath.Join(f.dir, name+".ndjson"), log: filepath.Join(f.dir, name+".log"),
		done: make(chan error, 1),
	}
	log, err := os.Create(d.log)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--policy", policy, "--require-lsm", "--lsm-enforce", "--cgroup-filter", f.cgroup,
		"--metrics-port", fmt.Sprint(port), "--event-sink", "file:" + d.events, "--stats-interval", "1h"}
	d.cmd = exec.Command(filepath.Join(f.dir, "warmor-daemon"), append(args, flags...)...)
	d.cmd.Stdout, d.cmd.Stderr = log, log
	if err := d.cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	go func() { d.done <- d.cmd.Wait() }()
	t.Cleanup(func() {
		_ = d.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-d.done:
			if err != nil {
				t.Errorf("daemon did not shut down cleanly: %v (log %s)", err, d.log)
			}
		case <-time.After(outcomeTimeout):
			_ = d.cmd.Process.Kill()
			<-d.done
			t.Errorf("daemon shutdown timed out (log %s)", d.log)
		}
		log.Close()
		if t.Failed() {
			data, _ := os.ReadFile(d.log)
			t.Logf("daemon log (%s):\n%s", d.log, data)
		}
	})
	waitFor(t, "daemon event loop and HTTP endpoint", func() bool {
		data, _ := os.ReadFile(d.log)
		return strings.Contains(string(data), "warmor is running") && strings.Contains(d.scrape(), "warmor_ebpf_loader_status 1")
	})
	return d
}

func (d *daemonProcess) scrape() string {
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get(d.metrics)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	return string(data)
}

func waitFor(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(outcomeTimeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s (see retained daemon logs/artifacts)", description)
}

func (d *daemonProcess) requireEvent(t *testing.T, match func(streaming.SecurityEvent) bool) {
	t.Helper()
	waitFor(t, "attributed policy event (not an outcome substitute)", func() bool {
		data, _ := os.ReadFile(d.events)
		for _, line := range bytes.Split(data, []byte{'\n'}) {
			var event streaming.SecurityEvent
			if json.Unmarshal(line, &event) == nil && match(event) {
				return true
			}
		}
		return false
	})
}

func (f *outcomeFixture) requireFirstDenied(t *testing.T, binary, marker string) {
	t.Helper()
	// One attempt only, with an executable not previously attempted against
	// this daemon. A repeat-until-denied probe would hide first-event misses.
	cmd := f.helper(t, binary, marker, "", 0)
	err := cmd.Start()
	if err == nil {
		_ = waitCommand(cmd, outcomeTimeout)
		t.Fatal("first eligible default-deny exec started; later kill/cached denial is not prevention")
	}
	if !isEPERM(err) {
		t.Fatalf("first exec error=%v; require exact EPERM, not EACCES, missing binary, exit code, or timeout", err)
	}
	f.checkMarker(t, marker, false)
}

func (d *daemonProcess) rejectReload(t *testing.T, active string) {
	t.Helper()
	// Current API can reject an invalid candidate before activation. This
	// does NOT claim map-write fault injection or atomic activation coverage.
	mustWrite(t, active, []byte("invalid WASM candidate"), 0644)
	if err := d.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "daemon to acknowledge rejected reload", func() bool {
		data, _ := os.ReadFile(d.log)
		return strings.Contains(string(data), "Failed to reload policy")
	})
}

func (f *outcomeFixture) activePolicy(t *testing.T, name, source string) string {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(f.dir, name+".wasm")
	mustWrite(t, active, data, 0644)
	return active
}

func TestDaemonOutcomes(t *testing.T) {
	requireOutcomeVM(t) // Must precede any daemon start or BPF operation.
	t.Cleanup(func() {
		if !t.Failed() {
			mustWrite(t, filepath.Join(artifactDir(t), "outcome-success.txt"), []byte("whole-daemon outcomes passed in vimto\n"), 0644)
		}
	})
	f := newFixture(t)
	staticPolicy := filepath.Join(f.dir, "static.wasm")
	filePolicy := filepath.Join(f.dir, "file.wasm")
	// Without any daemon, demonstrate DAC, mounts and uid do not account for
	// later failures. All paths are real ELF executables, not missing utilities.
	t.Run("baseline-without-daemon", func(t *testing.T) {
		for _, name := range []string{"allowed", "first-denied", "reload-denied", "rule-audit", "global-audit"} {
			f.runAllowed(t, name, "baseline-"+name, 0)
		}
		cmd := f.helper(t, "file-victim", "baseline-file", filepath.Join(f.work, "watched-file"), 0)
		cmd.Stdin = strings.NewReader("x")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("baseline file open failed: %v, output=%s", err, output)
		}
		f.checkMarker(t, "baseline-file", true)
	})
	if t.Failed() {
		t.Fatal("baseline failed; outcome probes would be ambiguous")
	}
	t.Run("allow-first-deny-and-rejected-reload-LKG", func(t *testing.T) {
		active := f.activePolicy(t, "active", staticPolicy)
		d := f.startDaemon(t, "default-deny", active, "--default-deny")
		waitFor(t, "exec allowlist active", func() bool {
			return strings.Contains(d.scrape(), "warmor_kernel_default_deny_active{event_type=\"exec\"} 1")
		})
		f.runAllowed(t, "allowed", "allowed-before-reload", 100*time.Millisecond)
		f.requireFirstDenied(t, "first-denied", "denied-first")
		// Per-rule audit is tested while global/kernel enforcement is active.
		f.runAudited(t, d, "rule-audit", "rule-audit")
		d.rejectReload(t, active)
		f.runAllowed(t, "allowed", "allowed-after-reload", 100*time.Millisecond)
		f.requireFirstDenied(t, "reload-denied", "denied-after-reload")
		mustWrite(t, filepath.Join(f.dir, "default-deny.metrics"), []byte(d.scrape()), 0644)
	})
	t.Run("global-audit-never-blocks-or-kills", func(t *testing.T) {
		d := f.startDaemon(t, "global-audit", staticPolicy, "--default-deny", "--audit")
		f.runAudited(t, d, "global-audit", "global-audit")
		mustWrite(t, filepath.Join(f.dir, "audit.metrics"), []byte(d.scrape()), 0644)
	})
	t.Run("nonroot-process-actually-terminated", func(t *testing.T) {
		active := f.activePolicy(t, "active-file", filePolicy)
		d := f.startDaemon(t, "termination", active)
		// A previously unseen file event must still be evaluated by LKG,
		// not merely hit a kernel decision cached before the rejected reload.
		d.rejectReload(t, active)
		// A live nonroot child starts normally, signals readiness, and waits.
		// Only then does the parent release its denied file-open operation.
		// This cannot pass due to a refused exec or an already-dead child.
		cmd := f.helper(t, "file-victim", "async-file-side-effect", filepath.Join(f.work, "watched-file"), 10*time.Second)
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
			t.Fatalf("victim did not start: %v", err)
		}
		t.Cleanup(func() {
			_ = input.Close()
			if cmd.ProcessState == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		})
		waitReady(t, output)
		if _, err := input.Write([]byte{'x'}); err != nil {
			_ = input.Close()
			_ = waitCommand(cmd, time.Second)
			t.Fatal(err)
		}
		_ = input.Close()
		if err := waitCommand(cmd, 5*time.Second); !wasSIGKILL(err) {
			t.Fatalf("require actual daemon SIGKILL of live uid 65534 child; got %v, stderr=%s", err, &stderr)
		}
		d.requireEvent(t, func(e streaming.SecurityEvent) bool {
			return e.PID == uint32(cmd.Process.Pid) && e.UID == 65534 && e.EventType == "file" &&
				e.Filename == filepath.Join(f.work, "watched-file") && e.Decision == "deny" && e.Enforced && !e.AuditOnly
		})
		// Deliberately no "no side effect" assertion here: userspace SIGKILL
		// is asynchronous containment, not synchronous file-open prevention.
		mustWrite(t, filepath.Join(f.dir, "termination.metrics"), []byte(d.scrape()), 0644)
	})
}
