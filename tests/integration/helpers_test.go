//go:build linux

package integration

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/privatefile"
)

// createOutcomeRecordings is called only with the freshly created guest-local
// fixture directory by the VM harness. Never repair ownership on the shared
// checkout: private recording opens intentionally reject those ancestors.
func createOutcomeRecordings(work string) (string, error) {
	dir := filepath.Join(work, "recordings")
	if err := os.Mkdir(dir, 0700); err != nil {
		return "", fmt.Errorf("create guest-local recordings directory: %w", err)
	}
	return dir, nil
}

// exportOutcomeRecording runs after the daemon has exited, including when its
// subtest failed. The shared evidence directory is not a live recording sink.
// Missing recordings and failed exports must remain visible as test failures.
func exportOutcomeRecording(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read guest recording %s: %w", src, err)
	}
	file, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create recording evidence %s: %w", dst, err)
	}
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return fmt.Errorf("write recording evidence %s: %w", dst, err)
	}
	return nil
}

func TestOutcomeRecordingEvidence(t *testing.T) {
	work, artifacts := t.TempDir(), t.TempDir()
	dir, err := createOutcomeRecordings(work)
	if err != nil {
		t.Fatal(err)
	}
	if dir != filepath.Join(work, "recordings") {
		t.Fatalf("recordings outside guest fixture: %s", dir)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("recordings directory must be private: %v %v", info, err)
	}
	src, dst := filepath.Join(dir, "partial.ndjson"), filepath.Join(artifacts, "partial.ndjson")
	data := []byte("{\"partial\":true}\n")
	if err := os.WriteFile(src, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := exportOutcomeRecording(src, dst); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{src, dst} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != string(data) {
			t.Fatalf("recording lost at %s: %q %v", path, got, err)
		}
	}
	info, err = os.Stat(dst)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("exported recording must be private: %v %v", info, err)
	}
	if err := exportOutcomeRecording(src, dst); !errors.Is(err, os.ErrExist) {
		t.Fatalf("export overwrote existing evidence: %v", err)
	}
	if err := exportOutcomeRecording(filepath.Join(dir, "missing"), filepath.Join(artifacts, "missing.ndjson")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing recording error lost: %v", err)
	}
	if err := exportOutcomeRecording(src, filepath.Join(artifacts, "missing-parent", "events.ndjson")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("evidence destination error lost: %v", err)
	}
}

func TestOutcomeRecordingDirectoryRejectsExistingSymlink(t *testing.T) {
	work, target := t.TempDir(), t.TempDir()
	if err := os.Symlink(target, filepath.Join(work, "recordings")); err != nil {
		t.Fatal(err)
	}
	if _, err := createOutcomeRecordings(work); !errors.Is(err, os.ErrExist) {
		t.Fatalf("recordings must be newly created, not follow a preexisting entry: %v", err)
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatalf("symlink target modified: %v %v", entries, err)
	}
}

func TestOutcomeRecordingUsesPrivateFileContract(t *testing.T) {
	work := t.TempDir()
	dir, err := createOutcomeRecordings(work)
	if err != nil {
		t.Fatal(err)
	}
	file, err := privatefile.OpenAppend(filepath.Join(dir, "host.ndjson"), false, false)
	if err != nil {
		t.Fatalf("guest recording must satisfy real private sink ownership checks: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

// A copy of this test binary is the controlled executable. No shell, optional
// system utility, DNS server, network timeout or deny counter is an oracle.
func TestMain(m *testing.M) {
	if os.Getenv("WARMOR_OUTCOME_HELPER") == "1" {
		os.Exit(runHelper())
	}
	os.Exit(m.Run())
}

func runHelper() int {
	marker := os.Getenv("WARMOR_OUTCOME_MARKER")
	if os.Getuid() != 65534 || os.Geteuid() != 65534 {
		fmt.Fprintln(os.Stderr, "helper must actually run as uid/euid 65534")
		return 90
	}
	if os.Getenv("WARMOR_OUTCOME_CACHE_PROBE") == "1" {
		fmt.Println("READY uid=65534")
		for {
			var trigger [1]byte
			if n, err := os.Stdin.Read(trigger[:]); err != nil || n != 1 {
				return 0
			}
			if _, err := os.ReadFile(os.Getenv("WARMOR_OUTCOME_FILE")); err != nil {
				return 92
			}
		}
	}
	if os.Getenv("WARMOR_OUTCOME_FILE") != "" {
		fmt.Println("READY uid=65534")
		var trigger [1]byte
		if n, err := os.Stdin.Read(trigger[:]); err != nil || n != 1 {
			return 91
		}
		if _, err := os.ReadFile(os.Getenv("WARMOR_OUTCOME_FILE")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 92
		}
	}
	if err := os.WriteFile(marker, []byte("uid=65534\n"), 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 93
	}
	if os.Getenv("WARMOR_OUTCOME_HOLD") == "1" {
		fmt.Println("READY uid=65534")
		var release [1]byte
		if n, err := os.Stdin.Read(release[:]); err != nil || n != 1 {
			return 95
		}
	}
	delay, err := time.ParseDuration(os.Getenv("WARMOR_OUTCOME_DELAY"))
	if err != nil {
		return 94
	}
	time.Sleep(delay)
	return 0
}

func isEPERM(err error) bool {
	return errors.Is(err, syscall.EPERM)
}

func wasSIGKILL(err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGKILL
}

// Requiring vimto's actual PID 1 and its private control/stdio devices prevents
// an exported environment variable (or running in kind/a container) from
// accidentally authorizing enforcement on a shared host kernel.
func verifyVM(optIn, initExe string, ports []string) error {
	if optIn != "1" || filepath.Base(initExe) != "vimto" {
		return fmt.Errorf("outcome enforcement is permitted only inside the vimto VM")
	}
	seen := map[string]bool{}
	for _, port := range ports {
		seen[strings.TrimSpace(port)] = true
	}
	if !seen["ctrl"] || !seen["stdio"] {
		return fmt.Errorf("vimto private virtio control/stdio ports missing")
	}
	return nil
}

func TestVMGuard(t *testing.T) {
	for _, tc := range []struct {
		name, optIn, init string
		ports             []string
		valid             bool
	}{
		{"host", "", "/usr/lib/systemd/systemd", nil, false},
		{"opt-in alone", "1", "/usr/lib/systemd/systemd", nil, false},
		{"container", "1", "/usr/bin/tini", []string{"ctrl", "stdio"}, false},
		{"missing ports", "1", "/home/user/bin/vimto", nil, false},
		{"vimto", "1", "/home/user/bin/vimto", []string{"ctrl\n", "stdio\n"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyVM(tc.optIn, tc.init, tc.ports); (err == nil) != tc.valid {
				t.Fatalf("verifyVM() = %v, valid=%v", err, tc.valid)
			}
		})
	}
}

func TestEPERMOracle(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, false}, {syscall.EPERM, true},
		{&os.PathError{Op: "fork/exec", Path: "/probe", Err: syscall.EPERM}, true},
		{syscall.EACCES, false}, {syscall.ENOENT, false},
		{syscall.ECONNREFUSED, false}, {syscall.ETIMEDOUT, false},
		{errors.New("operation not permitted"), false},
	} {
		if got := isEPERM(tc.err); got != tc.want {
			t.Fatalf("isEPERM(%v)=%v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestSIGKILLOracle(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action string
		want   bool
	}{
		{"success", "exit 0", false}, {"ordinary failure", "exit 1", false},
		{"shell 137 is not a signal", "exit 137", false},
		{"different signal", "kill -TERM $$", false}, {"actual kill", "kill -KILL $$", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := wasSIGKILL(exec.Command("/bin/sh", "-c", tc.action).Run()); got != tc.want {
				t.Fatalf("wasSIGKILL()=%v, want %v", got, tc.want)
			}
		})
	}
	if wasSIGKILL(syscall.EPERM) {
		t.Fatal("refused start is not process termination")
	}
}
