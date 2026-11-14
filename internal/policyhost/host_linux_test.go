//go:build linux

package policyhost

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/policyhost/protocol"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
	"github.com/yasindce1998/warmor/pkg/api"
	"golang.org/x/sys/unix"
)

// Build the actual standalone command once; never self-exec a Go test binary,
// install security hooks, signal a sensor PID, or use a mock sleeper worker.
var buildOnce sync.Once
var hostPath, hostDigest string
var buildErr error

func config(t *testing.T) Config {
	t.Helper()
	buildOnce.Do(func() {
		// /tmp/opencode is private to the harness; a normal test run uses Go's
		// standard temporary directory. Ownership validation is still applied.
		base := ""
		if st, err := os.Stat("/tmp/opencode"); err == nil && st.IsDir() {
			base = "/tmp/opencode"
		}
		dir, err := os.MkdirTemp(base, "warmor-policy-host-test-")
		if err != nil {
			buildErr = err
			return
		}
		hostPath = filepath.Join(dir, "warmor-policy-host")
		cmd := exec.Command("go", "build", "-o", hostPath, "../../cmd/warmor-policy-host")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = errors.New(string(out))
			return
		}
		data, err := os.ReadFile(hostPath)
		if err != nil {
			buildErr = err
			return
		}
		h := sha256.Sum256(data)
		hostDigest = hex.EncodeToString(h[:])
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return Config{Executable: hostPath, ExecutableSHA256: hostDigest, Limits: protocol.Limits{AddressSpaceBytes: 4 << 30, CPUSeconds: 10, MemoryPages: 256, MaxRequests: 100}, InitializationTimeout: 5 * time.Second, LoadTimeout: 3 * time.Second, EvaluationTimeout: 200 * time.Millisecond, MaxHosts: 2}
}

func TestMain(m *testing.M) {
	code := m.Run()
	if hostPath != "" {
		_ = os.Remove(hostPath)
		_ = os.Remove(filepath.Dir(hostPath))
	}
	os.Exit(code)
}

func staged(t *testing.T, data []byte) *StagedPolicy {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Stage(data, ed25519.Sign(priv, data), pub)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func supervisor(t *testing.T, c Config) *Supervisor {
	t.Helper()
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func startHost(t *testing.T, s *Supervisor, data []byte) *Host {
	t.Helper()
	h, err := s.Start(context.Background(), staged(t, data))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}
func reaped(t *testing.T, h *Host) {
	t.Helper()
	select {
	case <-h.done:
	default:
		t.Fatal("child not reaped before operation returned")
	}
	if h.cmd.ProcessState == nil {
		t.Fatal("missing child process state")
	}
	status, ok := h.cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || (!h.cmd.ProcessState.Exited() && !status.Signaled()) {
		t.Fatal("missing child wait status")
	}
	// Wait may only happen once; ECHILD proves this owned child is reaped.
	var st syscall.WaitStatus
	if _, err := syscall.Wait4(h.cmd.Process.Pid, &st, syscall.WNOHANG, nil); !errors.Is(err, syscall.ECHILD) {
		t.Fatalf("child wait = %v", err)
	}
}

func TestBootstrapExcludesNonCLOEXECDescriptorAboveNOFILE(t *testing.T) {
	c := config(t) // build before introducing the deliberately inheritable fd
	s := supervisor(t, c)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	// F_DUPFD allocates a new owned descriptor, never overwrites fd 100 (which
	// might belong to another test/runtime). Unlike F_DUPFD_CLOEXEC this is
	// intentionally inheritable, and exceeds the worker's RLIMIT_NOFILE=32.
	fd, err := unix.FcntlInt(w.Fd(), unix.F_DUPFD, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC != 0 {
		t.Fatal("regression fixture is not inheritable", err)
	}
	h := startHost(t, s, wasmtest.ConstPolicy(0, nil))
	defer h.Close()
	// The worker is deliberately non-dumpable; prove closure through pipe
	// lifetime rather than weakening dumpability to inspect /proc/PID/fd.
	// Sanitization must not close/change any descriptor in the supervisor.
	if _, err := unix.Write(fd, []byte{7}); err != nil {
		t.Fatal("bootstrap altered parent's descriptor", err)
	}
	var b [1]byte
	if _, err := r.Read(b[:]); err != nil || b[0] != 7 {
		t.Fatal("parent pipe corrupted", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	fd = -1
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// EOF must occur while the worker is alive, not merely after Close kills
	// it. Poll avoids a blocked read goroutine if this regression returns.
	poll := []unix.PollFd{{Fd: int32(r.Fd()), Events: unix.POLLIN | unix.POLLHUP}}
	if _, err := unix.Poll(poll, 1000); err != nil || poll[0].Revents&unix.POLLHUP == 0 {
		t.Fatal("inherited pipe lacks EOF before worker exit", err)
	}
	if n, err := r.Read(b[:]); n != 0 || err != io.EOF {
		t.Fatalf("pipe EOF: n=%d err=%v", n, err)
	}
	if result, err := h.Evaluate(context.Background(), &api.Event{}); err != nil || result.Action != api.ActionAllow {
		t.Fatalf("fresh worker runtime unusable: %+v %v", result, err)
	}
}

func TestRealHostResultsAuditLimitsAndNoRuntimeInParent(t *testing.T) {
	c := config(t)
	s := supervisor(t, c)
	for _, tc := range []struct {
		module []byte
		event  *api.Event
		action api.Action
		audit  bool
	}{
		{wasmtest.ConstPolicy(0, nil), &api.Event{}, api.ActionAllow, false},
		{wasmtest.ConstPolicy(3, nil), &api.Event{}, api.ActionDeny, true},
		{wasmtest.UIDPolicy(nil), &api.Event{UID: 0}, api.ActionDeny, false},
		{wasmtest.UIDPolicy(nil), &api.Event{UID: 42}, api.ActionAllow, false},
		{wasmtest.GrowPolicy(256), &api.Event{}, api.ActionDeny, false},
		{wasmtest.AgeKnownPolicy(nil), &api.Event{}, api.ActionDeny, false},
	} {
		h := startHost(t, s, tc.module)
		result, err := h.Evaluate(context.Background(), tc.event)
		if err != nil || result.Action != tc.action || result.Audit != tc.audit {
			t.Fatalf("result=%+v err=%v", result, err)
		}
		// Read actual kernel-enforced limits of our owned process.
		b, err := os.ReadFile("/proc/" + strconv.Itoa(h.cmd.Process.Pid) + "/limits")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "4294967296") {
			t.Fatal("RLIMIT_AS not established")
		}
		h.Close()
		reaped(t, h)
	}
	cmd := exec.Command("go", "list", "-deps", ".")
	deps, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"github.com/tetratelabs/wazero", "github.com/yasindce1998/warmor/internal/wasm\n"} {
		if bytes.Contains(deps, []byte(forbidden)) {
			t.Fatalf("parent depends on runtime %q", forbidden)
		}
	}
}

func TestLoopDeadlineKillsAndReapsWithoutRestart(t *testing.T) {
	s := supervisor(t, config(t))
	h := startHost(t, s, wasmtest.LoopPolicy())
	before := runtime.NumGoroutine()
	started := time.Now()
	r, err := h.Evaluate(context.Background(), &api.Event{})
	if r != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("result=%+v err=%v", r, err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("evaluation deadline did not bound child")
	}
	reaped(t, h)
	if len(s.slots) != 0 {
		t.Fatal("dead child retained capacity")
	}
	if r, err := h.Evaluate(context.Background(), &api.Event{}); r != nil || !errors.Is(err, ErrClosed) {
		t.Fatalf("retired host reused: %+v %v", r, err)
	}
	if runtime.NumGoroutine() > before+1 {
		t.Fatal("evaluation leaked goroutines")
	}
}

func TestCancellationCloseAndCapacity(t *testing.T) {
	c := config(t)
	c.MaxHosts = 1
	s := supervisor(t, c)
	h := startHost(t, s, wasmtest.LoopPolicy())
	if _, err := s.Start(context.Background(), staged(t, wasmtest.ConstPolicy(0, nil))); !errors.Is(err, ErrBusy) {
		t.Fatalf("capacity: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { _, err := h.Evaluate(ctx, &api.Event{}); finished <- err }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation = %v", err)
	}
	reaped(t, h)
	h = startHost(t, s, wasmtest.LoopPolicy())
	go func() { _, err := h.Evaluate(context.Background(), &api.Event{}); finished <- err }()
	time.Sleep(20 * time.Millisecond)
	h.Close()
	if err := <-finished; err == nil {
		t.Fatal("close produced a decision")
	}
	reaped(t, h)
}

func TestCPURlimitKillsOwnedWorker(t *testing.T) {
	c := config(t)
	c.EvaluationTimeout = 5 * time.Second
	c.Limits.CPUSeconds = 1
	h := startHost(t, supervisor(t, c), wasmtest.LoopPolicy())
	_, err := h.Evaluate(context.Background(), &api.Event{})
	if !errors.Is(err, ErrHost) {
		t.Fatalf("CPU limit = %v", err)
	}
	reaped(t, h)
	status, ok := h.cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("unexpected child wait status type %T", h.cmd.ProcessState.Sys())
	}
	if !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("CPU limit status %v", status)
	}
	if h.cmd.ProcessState.UserTime()+h.cmd.ProcessState.SystemTime() < 500*time.Millisecond {
		t.Fatal("not a substantive CPU workload")
	}
}

func uleb(v uint32) []byte {
	var b []byte
	for {
		x := byte(v & 127)
		v >>= 7
		if v == 0 {
			return append(b, x)
		}
		b = append(b, x|128)
	}
}
func section(id byte, b []byte) []byte {
	return append(append([]byte{id}, uleb(uint32(len(b)))...), b...)
}

// Valid framing and real local/add/conditional/multiply instructions force
// decoder, validator and SSA/control-flow compiler work; no NOP padding or
// guest sleep/loop stand-in. It stays under child-side admission limits.
func compileHeavy() []byte {
	const functions = 384
	m := append([]byte{0, 97, 115, 109, 1, 0, 0, 0}, section(1, []byte{1, 0x60, 0, 0})...)
	m = append(m, section(3, append(uleb(functions), make([]byte, functions)...))...)
	body := append([]byte{1, 1, 0x7f}, bytes.Repeat([]byte{0x20, 0, 0x41, 1, 0x6a, 0x21, 0, 0x20, 0, 0x04, 0x40, 0x20, 0, 0x41, 2, 0x6c, 0x21, 0, 0x0b}, 1024)...)
	body = append(body, 0x0b)
	code := uleb(functions)
	for range functions {
		code = append(code, uleb(uint32(len(body)))...)
		code = append(code, body...)
	}
	return append(m, section(10, code)...)
}

func TestCompileDeadlineReapsAndPreservesIndependentGoodHost(t *testing.T) {
	c := config(t)
	c.LoadTimeout = 100 * time.Millisecond
	s := supervisor(t, c)
	// Good host has a separate lifetime and remains usable over failed loads.
	good := startHost(t, s, wasmtest.ConstPolicy(0, nil))
	p := staged(t, compileHeavy())
	before := runtime.NumGoroutine()
	for range 3 {
		started := time.Now()
		h, err := s.Start(context.Background(), p)
		var failure *Failure
		if h != nil || !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &failure) || failure.Phase != "load" {
			t.Fatalf("compiler deadline h=%v err=%v", h, err)
		}
		if time.Since(started) > c.InitializationTimeout+time.Second {
			t.Fatal("compile deadline not enforced")
		}
		// Capacity is released only after cmd.Wait completes, not on timeout.
		if len(s.slots) != 1 {
			t.Fatal("compiler child not reaped before return")
		}
		if r, err := good.Evaluate(context.Background(), &api.Event{}); err != nil || r.Action != api.ActionAllow {
			t.Fatalf("last known good disrupted: %+v %v", r, err)
		}
	}
	if runtime.NumGoroutine() > before+1 {
		t.Fatal("compile retries leaked goroutines")
	}
}

func TestSignatureStagingAndExecutableTrust(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data := wasmtest.ConstPolicy(0, nil)
	sig := ed25519.Sign(priv, data)
	p, err := Stage(data, sig, pub)
	if err != nil {
		t.Fatal(err)
	}
	data[0] = 1
	if p.data[0] != 0 {
		t.Fatal("staging aliases caller")
	}
	if _, err := Stage(data, sig, pub); err == nil {
		t.Fatal("bad signature accepted")
	}
	if _, err := Stage(data, sig, nil); err == nil {
		t.Fatal("missing key accepted")
	}
	c := config(t)
	for _, mutate := range []func(*Config){func(c *Config) { c.Executable = "warmor-policy-host" }, func(c *Config) { c.ExecutableSHA256 = strings.Repeat("0", 64) }, func(c *Config) { c.Limits.CPUSeconds = 0 }, func(c *Config) { c.MaxHosts = 0 }, func(c *Config) { c.InitializationTimeout = 0 }} {
		x := c
		mutate(&x)
		if _, err := New(x); err == nil {
			t.Fatal("unsafe config accepted")
		}
	}
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink(hostPath, link); err != nil {
		t.Fatal(err)
	}
	c.Executable = link
	if _, err := New(c); err == nil {
		t.Fatal("symlink executable accepted")
	}
	policy := filepath.Join(dir, "policy.wasm")
	if err := os.WriteFile(policy, p.data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy+".sig", sig, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := StageFile(policy, pub); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(policy, filepath.Join(dir, "policy-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := StageFile(filepath.Join(dir, "policy-link"), pub); err == nil {
		t.Fatal("symlink staging accepted")
	}
}

func TestMalformedGuestAndUnknownActionFailClosed(t *testing.T) {
	s := supervisor(t, config(t))
	if h, err := s.Start(context.Background(), staged(t, []byte("not wasm"))); err == nil || h != nil {
		t.Fatal("malformed policy ready")
	}
	h := startHost(t, s, wasmtest.ConstPolicy(999, nil))
	if r, err := h.Evaluate(context.Background(), &api.Event{}); err == nil || r != nil {
		t.Fatal("unknown action became decision")
	}
	reaped(t, h)
}

func TestMaxRequestsAndConcurrentEvaluationHaveNoInternalQueue(t *testing.T) {
	c := config(t)
	c.Limits.MaxRequests = 1
	s := supervisor(t, c)
	h := startHost(t, s, wasmtest.ConstPolicy(0, nil))
	if r, err := h.Evaluate(context.Background(), &api.Event{}); err != nil || r.Action != api.ActionAllow {
		t.Fatalf("last result %+v %v", r, err)
	}
	reaped(t, h)
	if _, err := h.Evaluate(context.Background(), &api.Event{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("request budget: %v", err)
	}
	h = startHost(t, s, wasmtest.ConstPolicy(0, nil))
	// Hold the actual serialization gate deterministically: no timing race
	// or unbounded number of waiting goroutines needed to test backpressure.
	h.gate <- struct{}{}
	if _, err := h.Evaluate(context.Background(), &api.Event{}); !errors.Is(err, ErrBusy) {
		t.Fatalf("busy host queued work: %v", err)
	}
	<-h.gate
}

func TestCrashAndRejectedInputDoNotAllow(t *testing.T) {
	s := supervisor(t, config(t))
	h := startHost(t, s, wasmtest.ConstPolicy(0, nil))
	if r, err := h.Evaluate(context.Background(), nil); err == nil || r != nil {
		t.Fatal("nil input allowed")
	}
	if r, err := h.Evaluate(context.Background(), &api.Event{Comm: strings.Repeat("secret", protocol.MaxEvent)}); err == nil || r != nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("oversized input allowed or leaked")
	}
	if r, err := h.Evaluate(context.Background(), &api.Event{}); err != nil || r.Action != api.ActionAllow {
		t.Fatalf("local rejection retired host: %+v %v", r, err)
	}
	// Only signal the exact process created by this supervisor.
	if err := h.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if r, err := h.Evaluate(context.Background(), &api.Event{}); err == nil || r != nil {
		t.Fatal("crashed child allowed")
	}
	h.Close()
	reaped(t, h)
}

func wasmName(s string) []byte { return append(uleb(uint32(len(s))), s...) }

// Build a real env.get_field_str consumer. The imported callback must read
// the immutable event inside the worker, not RPC back to a privileged parent.
func callbackPolicy(lengthQuery bool) []byte {
	m := []byte{0, 97, 115, 109, 1, 0, 0, 0}
	m = append(m, section(1, []byte{2, 0x60, 3, 0x7f, 0x7f, 0x7f, 1, 0x7f, 0x60, 1, 0x7f, 1, 0x7f})...)
	imp := append([]byte{1}, wasmName("env")...)
	imp = append(imp, wasmName("get_field_str")...)
	imp = append(imp, 0, 0)
	m = append(m, section(2, imp)...)
	m = append(m, section(3, []byte{2, 1, 1})...)
	m = append(m, section(5, []byte{1, 0, 1})...)
	exports := []byte{3}
	for _, entry := range []struct {
		name        string
		kind, index byte
	}{{"memory", 2, 0}, {"malloc", 0, 1}, {"evaluate_event", 0, 2}} {
		exports = append(exports, wasmName(entry.name)...)
		exports = append(exports, entry.kind, entry.index)
	}
	m = append(m, section(7, exports)...)
	malloc := []byte{0, 0x41, 0x80, 8, 0x0b} // 1024
	// field 15 (argv), buf 2048, cap 0 (query) or 1 (copy).
	cap := byte(1)
	if lengthQuery {
		cap = 0
	}
	eval := []byte{0, 0x41, 15, 0x41, 0x80, 16, 0x41, cap, 0x10, 0}
	if !lengthQuery {
		eval = append(eval, 0x1a, 0x41, 0x80, 16, 0x2d, 0, 0)
	} // drop count; load byte
	// Return DENY exactly when the expected value matches, otherwise ALLOW.
	if lengthQuery {
		eval = append(eval, 0x41, 3)
	} else {
		eval = append(eval, 0x41, 0xff, 1)
	}
	eval = append(eval, 0x46, 0x0b)
	code := []byte{2}
	code = append(code, uleb(uint32(len(malloc)))...)
	code = append(code, malloc...)
	code = append(code, uleb(uint32(len(eval)))...)
	code = append(code, eval...)
	return append(m, section(10, code)...)
}

func TestCallbacksRunInChildAndPreserveUnknownBytes(t *testing.T) {
	s := supervisor(t, config(t))
	for _, query := range []bool{true, false} {
		h := startHost(t, s, callbackPolicy(query))
		e := &api.Event{Process: &api.ProcessEvent{Args: []string{"\xff", "x"}}}
		r, err := h.Evaluate(context.Background(), e)
		if err != nil || r.Action != api.ActionDeny {
			t.Fatalf("callback query=%v result=%+v err=%v", query, r, err)
		}
		h.Close()
	}
	fixture, err := os.ReadFile("../wasm/testdata/allow_policy.wasm")
	if err != nil {
		t.Fatal(err)
	}
	h := startHost(t, s, fixture) // checked-in JSON ABI guest, not just binary tests
	if r, err := h.Evaluate(context.Background(), &api.Event{Filename: "/bin/tool"}); err != nil || r.Action != api.ActionAllow {
		t.Fatalf("JSON ABI %+v %v", r, err)
	}
}
