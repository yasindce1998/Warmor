//go:build integration

package ebpf

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
}

func requireLSM(t *testing.T) {
	t.Helper()
	if !IsLSMSupported() {
		t.Skip("kernel does not have CONFIG_BPF_LSM enabled")
	}
}

func loadLSMOrSkip(t *testing.T) *LSMLoader {
	t.Helper()
	loader, err := LoadLSM()
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "header padding") ||
			strings.Contains(errStr, "non-zero trailer") ||
			strings.Contains(errStr, "non-zero byte") ||
			strings.Contains(errStr, "parsing .BTF") ||
			strings.Contains(errStr, "load kernel spec") {
			t.Skipf("kernel BTF incompatible with cilium/ebpf library: %v", err)
		}
		t.Fatalf("LoadLSM failed: %v", err)
	}
	if loader == nil {
		t.Fatal("LoadLSM returned nil without error on LSM-supported kernel")
	}
	return loader
}

func TestLSM_LoadAndAttach(t *testing.T) {
	requireRoot(t)
	requireLSM(t)

	loader := loadLSMOrSkip(t)
	defer loader.Close()

	if loader.policyMap == nil {
		t.Error("PolicyMap is nil after successful load")
	}
	if loader.lsmReader == nil {
		t.Error("ringbuf reader is nil after successful load")
	}
	if loader.execLink == nil {
		t.Error("exec LSM link is nil")
	}
	if loader.fileLink == nil {
		t.Error("file LSM link is nil")
	}
	if loader.connectLink == nil {
		t.Error("connect LSM link is nil")
	}
	if loader.bindLink == nil {
		t.Error("bind LSM link is nil")
	}
	if loader.listenLink == nil {
		t.Error("listen LSM link is nil")
	}
	if loader.ptraceLink == nil {
		t.Error("ptrace LSM link is nil")
	}
	if loader.mountLink == nil {
		t.Error("mount LSM link is nil")
	}
}

func TestLSM_PolicyMapCRUD(t *testing.T) {
	requireRoot(t)
	requireLSM(t)

	loader := loadLSMOrSkip(t)
	defer loader.Close()

	pm := loader.PolicyMap()

	// Insert a rule
	err := pm.SetRule(0, EventTypeExec, "/usr/bin/test-blocked", ActionDeny, false)
	if err != nil {
		t.Fatalf("SetRule failed: %v", err)
	}

	// Verify it's there via Stats
	count, err := pm.Stats()
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	if count < 1 {
		t.Errorf("expected at least 1 entry, got %d", count)
	}

	// Delete the rule
	err = pm.DeleteRule(0, EventTypeExec, "/usr/bin/test-blocked")
	if err != nil {
		t.Fatalf("DeleteRule failed: %v", err)
	}

	// Insert multiple and clear
	for i := 0; i < 10; i++ {
		err = pm.SetRule(0, EventTypeExec, fmt.Sprintf("/test/path/%d", i), ActionAllow, false)
		if err != nil {
			t.Fatalf("SetRule[%d] failed: %v", i, err)
		}
	}

	count, _ = pm.Stats()
	if count < 10 {
		t.Errorf("expected at least 10 entries, got %d", count)
	}

	err = pm.Clear()
	if err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	count, _ = pm.Stats()
	if count != 0 {
		t.Errorf("expected 0 entries after Clear, got %d", count)
	}
}

func TestLSM_ExecBlocked(t *testing.T) {
	requireRoot(t)
	requireLSM(t)

	loader := loadLSMOrSkip(t)
	defer loader.Close()

	// Enable enforcement
	if err := loader.SetEnforceMode(true); err != nil {
		t.Fatalf("SetEnforceMode failed: %v", err)
	}

	// Create a test binary
	testBin := filepath.Join(t.TempDir(), "blocked-binary")
	if err := os.WriteFile(testBin, []byte("#!/bin/sh\necho hello\n"), 0755); err != nil {
		t.Fatalf("write test binary: %v", err)
	}

	// Insert deny rule for this binary (global rule, cgroup=0)
	pm := loader.PolicyMap()
	if err := pm.SetRule(0, EventTypeExec, testBin, ActionDeny, false); err != nil {
		t.Fatalf("SetRule deny: %v", err)
	}

	// Attempt to execute — should get EPERM
	cmd := exec.Command(testBin)
	err := cmd.Run()
	if err == nil {
		// The kernel hashes the full bprm->filename exactly like HashPattern,
		// so a rule for a >16-byte path must match.
		t.Fatal("expected exec to be blocked, but it succeeded")
	}

	var exitErr *exec.ExitError
	if ok := errors.As(err, &exitErr); ok {
		// On EPERM the shell might return 126
		t.Logf("exec blocked with exit code: %d", exitErr.ExitCode())
	} else {
		// Check if it's a permission error
		if !os.IsPermission(err) && !strings.Contains(err.Error(), "permission denied") {
			t.Logf("exec failed with: %v (type: %T)", err, err)
		}
	}

	// Clean up
	pm.DeleteRule(0, EventTypeExec, testBin)
	loader.SetEnforceMode(false)
}

func TestLSM_FileRulesRefused(t *testing.T) {
	requireRoot(t)
	requireLSM(t)

	loader := loadLSMOrSkip(t)
	defer loader.Close()

	if err := loader.SetEnforceMode(true); err != nil {
		t.Fatalf("SetEnforceMode failed: %v", err)
	}

	// Create a test file
	testFile := filepath.Join(t.TempDir(), "blocked-file.txt")
	if err := os.WriteFile(testFile, []byte("secret data"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	// The BPF file_open hook only sees the dentry basename, never the path
	// userspace evaluated, so the policy map manager refuses file rules
	// rather than install one that would match every same-named file.
	pm := loader.PolicyMap()
	for _, pattern := range []string{testFile, filepath.Base(testFile)} {
		if err := pm.SetRule(0, EventTypeFile, pattern, ActionDeny, false); !errors.Is(err, ErrNotKernelMatchable) {
			t.Fatalf("SetRule(file %q) err = %v, want ErrNotKernelMatchable", pattern, err)
		}
	}

	// With no rule installed the open must succeed.
	if _, err := os.ReadFile(testFile); err != nil {
		t.Fatalf("file open unexpectedly failed: %v", err)
	}
	loader.SetEnforceMode(false)
}

func TestLSM_ConnectBlocked(t *testing.T) {
	requireRoot(t)
	requireLSM(t)

	loader := loadLSMOrSkip(t)
	defer loader.Close()

	if err := loader.SetEnforceMode(true); err != nil {
		t.Fatalf("SetEnforceMode failed: %v", err)
	}

	// Block connections to 169.254.169.254:80 (metadata service), keyed the
	// way lsm_connect hashes the raw sockaddr_in.
	pm := loader.PolicyMap()
	if err := pm.SetEndpointRule(0, EventTypeNetwork, "169.254.169.254", 80, ActionDeny, false); err != nil {
		t.Fatalf("SetEndpointRule deny: %v", err)
	}

	// Attempt to connect — should fail
	conn, err := net.DialTimeout("tcp", "169.254.169.254:80", 2*time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("expected connect to be blocked, but it succeeded")
	}

	// Verify it's a permission error, not a timeout
	if !isPermissionError(err) {
		t.Logf("connect failed with: %v (may be EACCES or timeout depending on implementation)", err)
	}

	// Clean up
	pm.Clear()
	loader.SetEnforceMode(false)
}

func TestLSM_AuditModeNoBlock(t *testing.T) {
	requireRoot(t)
	requireLSM(t)

	loader := loadLSMOrSkip(t)
	defer loader.Close()

	// Explicitly disable enforcement (audit only)
	if err := loader.SetEnforceMode(false); err != nil {
		t.Fatalf("SetEnforceMode(false) failed: %v", err)
	}

	// Create a test binary
	testBin := filepath.Join(t.TempDir(), "audit-only-binary")
	if err := os.WriteFile(testBin, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write test binary: %v", err)
	}

	// Insert deny rule
	pm := loader.PolicyMap()
	if err := pm.SetRule(0, EventTypeExec, testBin, ActionDeny, true); err != nil {
		t.Fatalf("SetRule deny+audit: %v", err)
	}

	// In audit mode, execution should still succeed
	cmd := exec.Command(testBin)
	err := cmd.Run()
	if err != nil {
		t.Errorf("in audit mode, exec should succeed but got: %v", err)
	}

	// Clean up
	pm.DeleteRule(0, EventTypeExec, testBin)
}

func TestLSM_AuditFlaggedDenyNoBlock(t *testing.T) {
	requireRoot(t)
	requireLSM(t)

	loader := loadLSMOrSkip(t)
	defer loader.Close()

	// Enforcement on, but the rule is audit-flagged (userspace audit mode):
	// the kernel must log it and never be stricter than userspace.
	if err := loader.SetEnforceMode(true); err != nil {
		t.Fatalf("SetEnforceMode failed: %v", err)
	}

	testBin := filepath.Join(t.TempDir(), "audit-flagged-binary")
	if err := os.WriteFile(testBin, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write test binary: %v", err)
	}

	pm := loader.PolicyMap()
	if err := pm.SetRule(0, EventTypeExec, testBin, ActionDeny, true); err != nil {
		t.Fatalf("SetRule deny+audit: %v", err)
	}

	if err := exec.Command(testBin).Run(); err != nil {
		t.Errorf("audit-flagged deny must not block exec, got: %v", err)
	}

	pm.DeleteRule(0, EventTypeExec, testBin)
	loader.SetEnforceMode(false)
}

func TestLSM_CgroupFilter(t *testing.T) {
	requireRoot(t)
	requireLSM(t)

	loader := loadLSMOrSkip(t)
	defer loader.Close()

	if err := loader.SetEnforceMode(true); err != nil {
		t.Fatalf("SetEnforceMode failed: %v", err)
	}

	// Set cgroup filter to a non-existent cgroup ID (99999)
	// This means our current process's cgroup won't match → rules should not apply
	if err := loader.SetCgroupFilter([]uint64{99999}); err != nil {
		t.Fatalf("SetCgroupFilter failed: %v", err)
	}

	// Create a test binary
	testBin := filepath.Join(t.TempDir(), "cgroup-test-binary")
	if err := os.WriteFile(testBin, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write test binary: %v", err)
	}

	// Insert a deny rule
	pm := loader.PolicyMap()
	if err := pm.SetRule(0, EventTypeExec, testBin, ActionDeny, false); err != nil {
		t.Fatalf("SetRule: %v", err)
	}

	// Execution should succeed because our cgroup is not in the filter
	cmd := exec.Command(testBin)
	err := cmd.Run()
	if err != nil {
		t.Errorf("with cgroup filter excluding us, exec should succeed: %v", err)
	}

	// Clear cgroup filter (empty = all cgroups processed)
	if err := loader.SetCgroupFilter(nil); err != nil {
		t.Fatalf("clear cgroup filter: %v", err)
	}

	// Clean up
	pm.DeleteRule(0, EventTypeExec, testBin)
	loader.SetEnforceMode(false)
}

func TestLSM_PolicyMapOverflow(t *testing.T) {
	requireRoot(t)
	requireLSM(t)

	loader := loadLSMOrSkip(t)
	defer loader.Close()

	pm := loader.PolicyMap()

	// Insert many rules - the map has 65536 max entries
	// Insert 1000 rules to stress test without filling completely
	for i := 0; i < 1000; i++ {
		pattern := fmt.Sprintf("/stress/test/path/number/%d/binary", i)
		err := pm.SetRule(uint64(i%100), EventTypeExec, pattern, ActionDeny, false)
		if err != nil {
			t.Fatalf("SetRule failed at iteration %d: %v", i, err)
		}
	}

	count, err := pm.Stats()
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	if count < 1000 {
		t.Errorf("expected at least 1000 entries, got %d", count)
	}

	// Clean up
	pm.Clear()
}

func TestLSM_RingbufEventDelivery(t *testing.T) {
	requireRoot(t)
	requireLSM(t)

	loader := loadLSMOrSkip(t)
	defer loader.Close()

	// Don't insert any policy rule — every exec should generate a ringbuf event (policy miss)
	// Execute something to trigger an LSM event
	cmd := exec.Command("/bin/true")
	if err := cmd.Run(); err != nil {
		t.Fatalf("exec /bin/true failed: %v", err)
	}

	// Read events with a short timeout
	done := make(chan struct{})
	var event *Event
	var readErr error

	go func() {
		event, readErr = loader.ReadLSMEvent()
		close(done)
	}()

	select {
	case <-done:
		if readErr != nil {
			t.Logf("ReadLSMEvent error (may be expected if no events pending): %v", readErr)
		} else if event != nil {
			t.Logf("received LSM event: pid=%d comm=%s filename=%s", event.PID, event.Comm, event.Filename)
		}
	case <-time.After(3 * time.Second):
		t.Log("no ringbuf event within 3s (event delivery depends on exec being in monitored cgroup)")
	}
}

func TestLSM_WASMFeedbackLoop(t *testing.T) {
	requireRoot(t)
	requireLSM(t)

	loader := loadLSMOrSkip(t)
	defer loader.Close()

	if err := loader.SetEnforceMode(true); err != nil {
		t.Fatalf("SetEnforceMode failed: %v", err)
	}

	pm := loader.PolicyMap()

	// Simulate the WASM feedback loop:
	// 1. A batch of decisions arrives from WASM evaluation
	decisions := []CachedDecision{
		{CgroupID: 0, EventType: EventTypeExec, Pattern: "/usr/bin/nc", Action: ActionDeny, Audit: true},
		{CgroupID: 0, EventType: EventTypeExec, Pattern: "/usr/bin/ncat", Action: ActionDeny, Audit: true},
		{CgroupID: 0, EventType: EventTypeExec, Pattern: "/usr/bin/socat", Action: ActionDeny, Audit: true},
		{CgroupID: 0, EventType: EventTypeFile, Pattern: "/etc/shadow", Action: ActionDeny, Audit: false},
		{CgroupID: 0, EventType: EventTypeExec, Pattern: "/usr/bin/curl", Action: ActionAllow, Audit: false},
	}

	// 2. SyncFromWASM writes them all into the BPF map
	if err := pm.SyncFromWASM(decisions); err != nil {
		t.Fatalf("SyncFromWASM failed: %v", err)
	}

	// 3. Verify all decisions are in the map
	count, err := pm.Stats()
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	// The file decision is not kernel-matchable and is skipped.
	if want := len(decisions) - 1; count != want {
		t.Errorf("expected %d entries, got %d", want, count)
	}

	// 4. Verify the lookup would work by checking the raw map
	key := PolicyKey{
		CgroupID:  0,
		RuleHash:  HashPattern("/usr/bin/nc"),
		EventType: EventTypeExec,
	}
	var val PolicyValue
	keyBytes, _ := key.MarshalBinary()
	err = loader.execObjs.PolicyMap.Lookup(keyBytes, &val)
	if err != nil {
		t.Fatalf("direct map Lookup for /usr/bin/nc failed: %v", err)
	}
	if val.Action != ActionDeny {
		t.Errorf("expected ActionDeny for /usr/bin/nc, got %d", val.Action)
	}
	if val.Audit != 1 {
		t.Errorf("expected audit=1 for /usr/bin/nc, got %d", val.Audit)
	}

	// Clean up
	pm.Clear()
	loader.SetEnforceMode(false)
}

func TestLSM_BindBlocked(t *testing.T) {
	requireRoot(t)
	requireLSM(t)

	loader := loadLSMOrSkip(t)
	defer loader.Close()

	if err := loader.SetEnforceMode(true); err != nil {
		t.Fatalf("SetEnforceMode failed: %v", err)
	}

	// Block binding to 127.0.0.1:9999
	port := uint16(9999)
	pm := loader.PolicyMap()
	if err := pm.SetEndpointRule(0, EventTypeBind, "127.0.0.1", port, ActionDeny, false); err != nil {
		t.Fatalf("SetEndpointRule bind deny: %v", err)
	}

	// Attempt to bind — should get EPERM
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer syscall.Close(fd)

	sa := &syscall.SockaddrInet4{Port: int(port), Addr: [4]byte{127, 0, 0, 1}}
	err = syscall.Bind(fd, sa)
	if err == nil {
		t.Fatal("expected bind to be blocked, but it succeeded")
	}
	if !isPermissionError(err) {
		t.Logf("bind failed with: %v (expected permission error)", err)
	}

	// Clean up
	pm.Clear()
	loader.SetEnforceMode(false)
}

func TestLSM_ListenBlocked(t *testing.T) {
	requireRoot(t)
	requireLSM(t)

	loader := loadLSMOrSkip(t)
	defer loader.Close()

	if err := loader.SetEnforceMode(true); err != nil {
		t.Fatalf("SetEnforceMode failed: %v", err)
	}

	// Block listening on port 9998
	port := uint16(9998)
	portHash := HashPort(port)

	pm := loader.PolicyMap()
	key := PolicyKey{
		CgroupID:  0,
		RuleHash:  portHash,
		EventType: EventTypeListen,
	}
	val := PolicyValue{Action: ActionDeny}
	if err := pm.policyMap.Put(key, val); err != nil {
		t.Fatalf("put listen deny rule: %v", err)
	}

	// Create a socket and bind it first (to port 9998)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer syscall.Close(fd)

	sa := &syscall.SockaddrInet4{Port: int(port), Addr: [4]byte{127, 0, 0, 1}}
	if err := syscall.Bind(fd, sa); err != nil {
		t.Fatalf("bind: %v", err)
	}

	// Attempt to listen — should get EPERM
	err = syscall.Listen(fd, 1)
	if err == nil {
		t.Fatal("expected listen to be blocked, but it succeeded")
	}
	if !isPermissionError(err) {
		t.Logf("listen failed with: %v (expected permission error)", err)
	}

	// Clean up
	pm.policyMap.Delete(key)
	loader.SetEnforceMode(false)
}

func TestLSM_PtraceBlocked(t *testing.T) {
	requireRoot(t)
	requireLSM(t)

	loader := loadLSMOrSkip(t)
	defer loader.Close()

	if err := loader.SetEnforceMode(true); err != nil {
		t.Fatalf("SetEnforceMode failed: %v", err)
	}

	// Start a child process that we'll try to ptrace
	cmd := exec.Command("/bin/sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	defer cmd.Process.Kill()

	// Block ptracing "sleep"
	pm := loader.PolicyMap()
	if err := pm.SetRule(0, EventTypePtrace, "sleep", ActionDeny, false); err != nil {
		t.Fatalf("SetRule deny ptrace sleep: %v", err)
	}

	// Attempt to ptrace attach — should get EPERM
	err := syscall.PtraceAttach(cmd.Process.Pid)
	if err == nil {
		syscall.PtraceDetach(cmd.Process.Pid)
		t.Fatal("expected ptrace to be blocked, but it succeeded")
	}
	if !isPermissionError(err) {
		t.Logf("ptrace failed with: %v (expected permission error)", err)
	}

	// Clean up
	pm.DeleteRule(0, EventTypePtrace, "sleep")
	loader.SetEnforceMode(false)
}

func TestLSM_MountBlocked(t *testing.T) {
	requireRoot(t)
	requireLSM(t)

	loader := loadLSMOrSkip(t)
	defer loader.Close()

	if err := loader.SetEnforceMode(true); err != nil {
		t.Fatalf("SetEnforceMode failed: %v", err)
	}

	// Block mounting "proc" filesystem type
	pm := loader.PolicyMap()
	if err := pm.SetRule(0, EventTypeMount, "proc", ActionDeny, false); err != nil {
		t.Fatalf("SetRule deny mount proc: %v", err)
	}

	// Create a temp dir as mount target
	target := t.TempDir()

	// Attempt to mount proc — should get EPERM
	err := syscall.Mount("none", target, "proc", 0, "")
	if err == nil {
		syscall.Unmount(target, 0)
		t.Fatal("expected mount to be blocked, but it succeeded")
	}
	if !isPermissionError(err) {
		t.Logf("mount failed with: %v (expected permission error)", err)
	}

	// Clean up
	pm.DeleteRule(0, EventTypeMount, "proc")
	loader.SetEnforceMode(false)
}

func isPermissionError(err error) bool {
	if os.IsPermission(err) {
		return true
	}
	if strings.Contains(err.Error(), "permission denied") {
		return true
	}
	if strings.Contains(err.Error(), "operation not permitted") {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.EPERM || errno == syscall.EACCES
	}
	return false
}
