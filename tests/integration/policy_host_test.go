//go:build linux && integration

package integration

import (
	"crypto/sha256"
	"debug/buildinfo"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	policycrypto "github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
)

func prepareSignedHostFixtures(t *testing.T) {
	t.Helper()
	dir := artifactDir(t)
	verifySameBuild(t)
	key, err := policycrypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.MarshalPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, "fixture-public.pem"), pub, 0644)
	for name, module := range map[string][]byte{
		"compile-heavy":    wasmtest.CompileHeavy(),
		"init-loop":        wasmtest.InitializationLoopPolicy(),
		"signed-malformed": []byte("signed but not a WASM module"),
	} {
		mustWrite(t, filepath.Join(dir, name+".wasm"), module, 0644)
	}
	// Private key never leaves this preparation process. No committed fixture
	// key, private artifact file, secret environment, or production signer.
	for _, name := range []string{"static", "file", "compile-heavy", "init-loop", "signed-malformed"} {
		path := filepath.Join(dir, name+".wasm")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		mustWrite(t, path+".sig", key.SignPolicyFile(data), 0644)
	}
	// These two compiler sources and their deterministic/exhaustive declarations
	// are reviewed above in validatePreparedPolicy. Attest ONLY these bytes, not
	// arbitrary signed guests, the heavy compiler workload, or init-loop module.
	var digests []string
	for _, name := range []string{"static", "file"} {
		data, err := os.ReadFile(filepath.Join(dir, name+".wasm"))
		if err != nil {
			t.Fatal(err)
		}
		digests = append(digests, fmt.Sprintf("%x", sha256.Sum256(data)))
	}
	mustWrite(t, filepath.Join(dir, "reviewed-declaration-digests.txt"), []byte(strings.Join(digests, ",")+"\n"), 0644)
}

func verifySameBuild(t *testing.T) {
	t.Helper()
	var revision string
	var toolchain, architecture string
	for _, name := range []string{"warmor-daemon", "warmor-policy-host"} {
		info, err := buildinfo.ReadFile(filepath.Join(artifactDir(t), name))
		if err != nil {
			t.Fatal(err)
		}
		settings := map[string]string{}
		for _, setting := range info.Settings {
			settings[setting.Key] = setting.Value
		}
		if settings["vcs.revision"] == "" || settings["GOOS"] != "linux" {
			t.Fatalf("%s lacks exact Linux VCS provenance: %+v", name, settings)
		}
		if settings["-tags"] != "policyhost_phaseproof" {
			t.Fatalf("%s missing explicit paired test-only phase-proof build tag", name)
		}
		if revision != "" && revision != settings["vcs.revision"] {
			t.Fatal("daemon and host built from different commits")
		}
		if toolchain != "" && (toolchain != info.GoVersion || architecture != settings["GOARCH"]) {
			t.Fatal("daemon and host built with different toolchains or architectures")
		}
		revision = settings["vcs.revision"]
		toolchain, architecture = info.GoVersion, settings["GOARCH"]
	}
	source, err := os.ReadFile(filepath.Join(artifactDir(t), "source-sha.txt"))
	if err != nil || strings.TrimSpace(string(source)) != revision {
		t.Fatalf("binary VCS revision differs from runner source: %v", err)
	}
}

func (f *outcomeFixture) installPolicyHost(t *testing.T) {
	t.Helper()
	requireOutcomeVM(t) // Defense in depth before creating any trusted install path.
	verifySameBuild(t)
	// Must only be called after requireOutcomeVM. No shared-checkout ancestor
	// chmod/chown and no symlink-prone /bin, /var/run or ConfigMap projection.
	const install = "/run/warmor-outcomes"
	if err := os.Mkdir(install, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(install, "warmor-policy-host")
	copyExecutable(t, filepath.Join(f.dir, "warmor-policy-host"), path)
	pin, err := os.ReadFile(filepath.Join(f.dir, "POLICY_HOST_SHA256"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(data)) != strings.TrimSpace(string(pin)) {
		t.Fatal("installed policy host differs from same-build pinned artifact")
	}
	for _, p := range []string{"/run", install, path} {
		st, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
			t.Fatalf("guest helper path must be physical, root owned and not writable: %s", p)
		}
	}
	declarations, err := os.ReadFile(filepath.Join(f.dir, "reviewed-declaration-digests.txt"))
	if err != nil {
		t.Fatal(err)
	}
	f.hostFlags = []string{"--experimental-supervised-policy-host", "--policy-host", path,
		"--policy-host-sha256", strings.TrimSpace(string(pin)),
		"--verify-key", filepath.Join(f.dir, "fixture-public.pem"),
		"--policy-declaration-digests", strings.TrimSpace(string(declarations)),
		// Enough for normal compiler output, bounded below compile-heavy work.
		"--policy-host-load-timeout", "500ms", "--eval-timeout", "500ms"}
	if os.Getenv("WARMOR_OUTCOME_ATOMIC_GENERATIONS") == "1" {
		f.hostFlags = append(f.hostFlags, "--experimental-atomic-generations")
	}
	mustWrite(t, filepath.Join(f.dir, "installed-host.txt"), []byte(fmt.Sprintf("path=%s\nsha256=%s\natomic=%s\n", path, strings.TrimSpace(string(pin)), os.Getenv("WARMOR_OUTCOME_ATOMIC_GENERATIONS"))), 0644)
}

func (d *daemonProcess) hostPIDs(t *testing.T) []int {
	t.Helper()
	var pids []int
	// os/exec may fork on any Go runtime thread, not only the thread-group leader.
	tasks, err := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/children", d.cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range tasks {
		children, err := os.ReadFile(task)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range strings.Fields(string(children)) {
			pid, err := strconv.Atoi(field)
			if err != nil {
				t.Fatal(err)
			}
			cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
			if os.IsNotExist(err) {
				continue
			}
			// A just-exited child can be visible as a zombie until cmd.Wait
			// completes. Keep counting it: disappearance, not empty cmdline,
			// is the reaping oracle.
			if err != nil || (len(cmdline) != 0 && string(cmdline) != "warmor-policy-host\x00--serve\x00" && string(cmdline) != "warmor-policy-host\x00") {
				t.Fatalf("unexpected daemon child %d: %q %v", pid, cmdline, err)
			}
			pids = append(pids, pid)
		}
	}
	return pids
}

func (f *outcomeFixture) hostLoadFailures(t *testing.T) {
	active := f.activePolicy(t, "host-LKG", filepath.Join(f.dir, "static.wasm"))
	listener, env := listenHostLoadPhase(t, f)
	d := f.startDaemonEnv(t, "host-LKG", active, env, "--default-deny")
	old := d.hosts[0]
	for _, candidate := range []string{"compile-heavy", "init-loop", "signed-malformed"} {
		t.Run(candidate, func(t *testing.T) {
			before, _ := os.ReadFile(d.log)
			f.activePolicy(t, "host-LKG", filepath.Join(f.dir, candidate+".wasm"))
			// One publication authority: let the watcher load the signed pair.
			// A simultaneous SIGHUP would queue a second activation and obscure
			// which candidate failed. Real compile/init children remain visible.
			if candidate != "signed-malformed" {
				phase := acceptHostLoadPhase(t, listener, hostFixtureDigest(t, filepath.Join(f.dir, candidate+".wasm")), old)
				owned := false
				for _, pid := range d.hostPIDs(t) {
					owned = owned || uint64(pid) == phase.held.Sequence
				}
				if !owned {
					t.Fatal("held-load receipt PID is not an owned daemon child")
				}
				// Completing work and confirming the still-held child happens
				// BEFORE release, never racing a 500ms deadline. Dispatch stalled
				// for the entire load cannot satisfy the fresh phase confirmation.
				f.requireAllowDuringLoad(t, d, phase, candidate)
				phase.release(t)
			} else {
				// Malformed framing rejects immediately: only eventual LKG is
				// claimed for this candidate, not concurrent load progress.
				f.runAllowed(t, "allowed", candidate+"-LKG-allow", 0)
			}
			f.requireFirstDenied(t, candidate+"-denied", candidate+"-LKG-deny")
			waitFor(t, "signed child load rejection", func() bool {
				data, _ := os.ReadFile(d.log)
				tail := string(data[len(before):])
				return strings.Contains(tail, "policy-host load:")
			})
			log, _ := os.ReadFile(d.log)
			if candidate != "signed-malformed" && !strings.Contains(string(log[len(before):]), "context deadline exceeded") {
				t.Fatal("real compile/init workload must reach the parent deadline, not an early ABI/admission failure")
			}
			// Restore the watcher's original content identity before its next
			// retry tick. Restoration is not activation and cannot replace LKG.
			f.activePolicy(t, "host-LKG", filepath.Join(f.dir, "static.wasm"))
			waitFor(t, "failed candidate reaped with LKG host retained", func() bool {
				pids := d.hostPIDs(t)
				return len(pids) == 1 && pids[0] == old
			})
			f.runAllowed(t, "allowed", candidate+"-after-allow", 0)
		})
	}
}

func (f *outcomeFixture) deadHostCache(t *testing.T) {
	d := f.startDaemon(t, "host-cache", filepath.Join(f.dir, "static.wasm"), "--audit")
	cmd := f.helper(t, "file-victim", "unused-cache-marker", filepath.Join(f.work, "watched-file"), 0)
	cmd.Env = append(cmd.Env, "WARMOR_OUTCOME_CACHE_PROBE=1")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = input.Close()
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	waitReady(t, output)
	match := func(e streaming.SecurityEvent) bool {
		return e.PID == uint32(cmd.Process.Pid) && e.UID == 65534 && e.EventType == "file" && e.Filename == filepath.Join(f.work, "watched-file")
	}
	for range 2 {
		if _, err := input.Write([]byte{'x'}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	d.requireEvent(t, func(e streaming.SecurityEvent) bool { return match(e) && e.Decision == "allow" && e.Cached })
	if err := syscall.Kill(d.hosts[0], syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "active host reaped", func() bool { return len(d.hostPIDs(t)) == 0 })
	if _, err := input.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	d.requireEvent(t, func(e streaming.SecurityEvent) bool {
		return match(e) && e.Decision == "deny" && !e.Cached && e.AuditOnly && !e.Enforced && strings.Contains(e.Reason, "Evaluation error:")
	})
	if len(d.hostPIDs(t)) != 0 {
		t.Fatal("dead host silently respawned")
	}
	_ = input.Close()
	if err := waitCommand(cmd, outcomeTimeout); err != nil {
		t.Fatal(err)
	}
}

func (f *outcomeFixture) cancelHostLoad(t *testing.T) {
	active := f.activePolicy(t, "cancel-active", filepath.Join(f.dir, "static.wasm"))
	d := f.startDaemon(t, "host-cancel", active, "--default-deny", "--policy-host-load-timeout", "9s")
	f.activePolicy(t, "cancel-active", filepath.Join(f.dir, "init-loop.wasm"))
	// Let the file watcher own the load. SIGHUP reload is synchronous in the
	// signal loop, so it cannot observe SIGTERM until its own bounded return.
	waitFor(t, "watcher candidate child", func() bool {
		pids := d.hostPIDs(t)
		if len(pids) != 2 {
			return false
		}
		d.hosts = pids
		return true
	})
	if err := d.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	// Leave Wait ownership with startDaemon cleanup, but require progress much
	// sooner than the 9s load budget. The marker is written by the real Stop.
	started := time.Now()
	waitFor(t, "SIGTERM cancellation and resource Close", func() bool {
		log, _ := os.ReadFile(d.log)
		return strings.Contains(string(log), "Resources cleaned up")
	})
	if time.Since(started) > 4*time.Second {
		t.Fatal("SIGTERM waited for candidate load deadline instead of canceling it")
	}
}
