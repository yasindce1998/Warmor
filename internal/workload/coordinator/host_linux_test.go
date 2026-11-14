//go:build linux

package coordinator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func statFixture(pid int, start string) string {
	fields := make([]string, 20)
	for n := range fields {
		fields[n] = "0"
	}
	fields[0] = "S"
	fields[19] = start
	return fmt.Sprintf("%d (name with ) spaces) %s\n", pid, strings.Join(fields, " "))
}

func fixtureHost(t *testing.T) (*HostVerifier, string, string) {
	t.Helper()
	base := t.TempDir()
	proc := filepath.Join(base, "proc")
	cg := filepath.Join(base, "cgroup")
	for _, dir := range []string{filepath.Join(proc, "123/ns"), filepath.Join(proc, "sys/kernel/random"), filepath.Join(cg, "kubepods/container")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeFixture(t, filepath.Join(proc, "123/stat"), statFixture(123, "100"))
	writeFixture(t, filepath.Join(proc, "123/cgroup"), "0::/kubepods/container\n")
	writeFixture(t, filepath.Join(cg, "kubepods/container/cgroup.procs"), "123\n")
	writeFixture(t, filepath.Join(proc, "sys/kernel/random/boot_id"), "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n")
	for n, kind := range []string{"pid", "cgroup", "mnt"} {
		if err := os.Symlink(fmt.Sprintf("%s:[%d]", kind, n+10), filepath.Join(proc, "123/ns", kind)); err != nil {
			t.Fatal(err)
		}
	}
	pr, err := os.OpenRoot(proc)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := os.OpenRoot(cg)
	if err != nil {
		closeFixture(t, pr)
		t.Fatal(err)
	}
	// Fixtures intentionally bypass ONLY filesystem-superblock preflight and
	// cgroup filesystem inspection. Production constructors never expose this.
	v := &HostVerifier{proc: pr, cgroups: cr, boot: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", session: "fixture-session", max: 8, maxGap: time.Minute, active: make(map[uint64]pinnedBinding),
		inspect: func(f *os.File) (uint64, uint64, error) {
			var st unix.Stat_t
			err := unix.Fstat(int(f.Fd()), &st)
			return uint64(st.Dev), st.Ino, err
		}}
	t.Cleanup(func() { closeFixture(t, v) })
	return v, proc, cg
}

func writeFixture(t *testing.T, name, data string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestHostEvidenceLifetimeRemovalAndPIDReuse(t *testing.T) {
	v, proc, _ := fixtureHost(t)
	claims := []ProcessClaim{{ContainerID: "exact-id", PID: 123, ExclusiveCgroupOwnership: true}}
	first, err := v.Verify(context.Background(), claims)
	if err != nil || len(first) != 1 {
		t.Fatalf("verify %+v %v", first, err)
	}
	second, err := v.Verify(context.Background(), claims)
	if err != nil || len(second) != 1 || first[0] != second[0] {
		t.Fatal("stable evidence changed")
	}
	writeFixture(t, filepath.Join(proc, "123/stat"), statFixture(123, "101"))
	third, err := v.Verify(context.Background(), claims)
	if err != nil || len(third) != 1 || third[0].Lifetime == first[0].Lifetime {
		t.Fatal("PID reuse retained lifetime")
	}
	if _, err := v.Verify(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	fourth, err := v.Verify(context.Background(), claims)
	if err != nil || len(fourth) != 1 || fourth[0].Lifetime == third[0].Lifetime {
		t.Fatal("removed/recreated claim inherited lifetime")
	}
	if _, err := v.Verify(context.Background(), []ProcessClaim{{ContainerID: "new-container", PID: 123, ExclusiveCgroupOwnership: true}}); err != nil {
		t.Fatal(err)
	}
	if v.active[fourth[0].CgroupID].binding.Lifetime == fourth[0].Lifetime {
		t.Fatal("container reassignment inherited lifetime")
	}
	beforeGap := v.active[fourth[0].CgroupID].binding.Lifetime
	v.observedUntil = time.Now().Add(-time.Second)
	if _, err := v.Verify(context.Background(), []ProcessClaim{{ContainerID: "new-container", PID: 123, ExclusiveCgroupOwnership: true}}); err != nil {
		t.Fatal(err)
	}
	if v.active[fourth[0].CgroupID].binding.Lifetime == beforeGap {
		t.Fatal("expired observation gap inherited lifetime")
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), claims); err == nil {
		t.Fatal("verify after close")
	}
}

func TestHostEvidenceRejectsUnprovableClaimsAndEscapes(t *testing.T) {
	for _, mode := range []string{"missing", "start", "root", "escape", "outside-symlink", "hybrid", "namespace", "boot", "duplicates", "budget", "canceled", "migration", "not-member", "procs-budget", "ownership-unproven"} {
		t.Run(mode, func(t *testing.T) {
			v, proc, cg := fixtureHost(t)
			claims := []ProcessClaim{{ContainerID: "exact-id", PID: 123, ExclusiveCgroupOwnership: true}}
			if b, err := v.Verify(context.Background(), claims); err != nil || len(b) != 1 {
				t.Fatal("fixture not verified", err)
			}
			ctx := context.Background()
			switch mode {
			case "ownership-unproven":
				claims[0].ExclusiveCgroupOwnership = false
			case "missing":
				if err := os.Remove(filepath.Join(proc, "123/stat")); err != nil {
					t.Fatal(err)
				}
			case "start":
				writeFixture(t, filepath.Join(proc, "123/stat"), statFixture(123, "0"))
			case "root":
				writeFixture(t, filepath.Join(proc, "123/cgroup"), "0::/\n")
			case "escape":
				writeFixture(t, filepath.Join(proc, "123/cgroup"), "0::/../../outside\n")
			case "outside-symlink":
				outside := t.TempDir()
				if err := os.Symlink(outside, filepath.Join(cg, "escape")); err != nil {
					t.Fatal(err)
				}
				writeFixture(t, filepath.Join(proc, "123/cgroup"), "0::/escape\n")
			case "hybrid":
				writeFixture(t, filepath.Join(proc, "123/cgroup"), "1:cpu:/a\n0::/kubepods/container\n")
			case "namespace":
				if err := os.Remove(filepath.Join(proc, "123/ns/mnt")); err != nil {
					t.Fatal(err)
				}
			case "boot":
				writeFixture(t, filepath.Join(proc, "sys/kernel/random/boot_id"), "different")
			case "duplicates":
				claims = append(claims, claims[0])
			case "budget":
				v.max = 1
				claims = append(claims, ProcessClaim{ContainerID: "other", PID: 999})
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "not-member":
				writeFixture(t, filepath.Join(cg, "kubepods/container/cgroup.procs"), "999\n")
			case "procs-budget":
				writeFixture(t, filepath.Join(cg, "kubepods/container/cgroup.procs"), strings.Repeat("123\n", (1<<20)/4+1))
			case "migration":
				original := v.inspect
				v.inspect = func(f *os.File) (uint64, uint64, error) {
					writeFixture(t, filepath.Join(proc, "123/stat"), statFixture(123, "999"))
					return original(f)
				}
			}
			b, _ := v.Verify(ctx, claims)
			if len(b) != 0 || len(v.active) != 0 {
				t.Fatal("unprovable claim retained binding")
			}
		})
	}
}

func TestHostConstructorRefusesOrdinaryDirectories(t *testing.T) {
	base := t.TempDir()
	cfg := HostConfig{ProcRoot: base, CgroupRoot: base, HostPIDNamespace: "pid:[1]", HostCgroupNamespace: "cgroup:[2]", TrustHostMounts: true, MaxBindings: 8, MaxObservationGap: 30 * time.Second}
	if v, err := NewHostVerifier(cfg); err == nil {
		closeFixture(t, v)
		t.Fatal("ordinary directory accepted as host mounts")
	}
	cfg.TrustHostMounts = false
	if _, err := NewHostVerifier(cfg); err == nil {
		t.Fatal("implicit mount trust accepted")
	}
}

func TestHostParsers(t *testing.T) {
	if got, err := processStart(statFixture(123, "42"), 123); err != nil || got != "42" {
		t.Fatal(got, err)
	}
	for _, s := range []string{"", statFixture(124, "42"), "123 (x) S", strings.Replace(statFixture(123, "42"), ") S", ") Z", 1)} {
		if _, err := processStart(s, 123); err == nil {
			t.Fatal("invalid stat accepted")
		}
	}
	for _, s := range []string{"0::/", "0::/a/../b\n", "0::/a/\n", "0::/a\n0::/b\n", "0::/a\x00b\n"} {
		if _, err := unifiedMembership(s); err == nil {
			t.Fatalf("invalid cgroup accepted %q", s)
		}
	}
	if safeID("../../a") || safeID("") || !safeID("full-id_123.abc") {
		t.Fatal("ID validation")
	}
	if !fullCgroupMount("21 1 0:10 / /host/cgroup rw - cgroup2 cgroup rw\n", "/host/cgroup") ||
		fullCgroupMount("21 1 0:10 /delegated /host/cgroup rw - cgroup2 cgroup rw\n", "/host/cgroup") {
		t.Fatal("delegated cgroup mount accepted")
	}
}

func TestHostVerifierConflictingInodeAndChangedNamespace(t *testing.T) {
	v, proc, _ := fixtureHost(t)
	if err := os.MkdirAll(filepath.Join(proc, "124/ns"), 0700); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(proc, "124/stat"), statFixture(124, "101"))
	writeFixture(t, filepath.Join(proc, "124/cgroup"), "0::/kubepods/container\n")
	writeFixture(t, filepath.Join(v.cgroups.Name(), "kubepods/container/cgroup.procs"), "123\n124\n")
	for n, kind := range []string{"pid", "cgroup", "mnt"} {
		if err := os.Symlink(fmt.Sprintf("%s:[%d]", kind, n+10), filepath.Join(proc, "124/ns", kind)); err != nil {
			t.Fatal(err)
		}
	}
	b, err := v.Verify(context.Background(), []ProcessClaim{{ContainerID: "one", PID: 123, ExclusiveCgroupOwnership: true}, {ContainerID: "two", PID: 124, ExclusiveCgroupOwnership: true}})
	if err != nil || len(b) != 0 {
		t.Fatal("shared cgroup claim accepted", err)
	}
	v.hostPIDNamespace = "pid:[999]"
	if _, err := v.Verify(context.Background(), nil); err == nil {
		t.Fatal("missing authorized host namespace accepted")
	}
}

func TestHostExclusiveOwnershipIsSeparateFromPIDMembership(t *testing.T) {
	v, _, cg := fixtureHost(t)
	// Other PIDs can be normal children of this container. Requiring all
	// members to be init PIDs would neither prove ownership nor be correct.
	writeFixture(t, filepath.Join(cg, "kubepods/container/cgroup.procs"), "123\n456\n")
	claim := ProcessClaim{ContainerID: "exact-id", PID: 123}
	bindings, err := v.Verify(context.Background(), []ProcessClaim{claim})
	if err != nil || len(bindings) != 0 {
		t.Fatal("membership without exclusive ownership was accepted", err)
	}
	claim.ExclusiveCgroupOwnership = true // Separate trusted fixture runtime contract.
	bindings, err = v.Verify(context.Background(), []ProcessClaim{claim})
	if err != nil || len(bindings) != 1 {
		t.Fatal("explicit ownership contract rejected ordinary child process", err)
	}
}
