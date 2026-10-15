//go:build linux

package container

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// statLine builds a /proc/<pid>/stat line with the given comm and
// starttime (field 22).
func statLine(pid int, comm string, startTicks uint64) string {
	f := make([]string, 0, 50)
	f = append(f, fmt.Sprint(pid), "("+comm+")", "S")
	for i := 4; i < 22; i++ {
		f = append(f, "0")
	}
	f = append(f, fmt.Sprint(startTicks))
	for i := 23; i <= 52; i++ {
		f = append(f, "0")
	}
	return strings.Join(f, " ") + "\n"
}

func TestParseStartTicks(t *testing.T) {
	for _, comm := range []string{"bash", "a b", "x) (y", "))"} {
		got, ok := parseStartTicks([]byte(statLine(42, comm, 123456)))
		if !ok || got != 123456 {
			t.Errorf("comm %q: got %d, %v", comm, got, ok)
		}
	}
	for _, bad := range []string{"", "42 (bash) S 1 2", "42 bash S"} {
		if _, ok := parseStartTicks([]byte(bad)); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestProcessStartTime_Self(t *testing.T) {
	wall, sinceBoot, ok := bootClockNow()
	if !ok {
		t.Skip("CLOCK_BOOTTIME unavailable")
	}
	start, ok := processStartTime("/proc", os.Getpid(), wall, sinceBoot)
	if !ok {
		t.Fatal("could not read own start time")
	}
	if start.After(wall.Add(time.Second)) || wall.Sub(start) > time.Hour {
		t.Errorf("own start time %v implausible (now %v)", start, wall)
	}
}

type fakeProc struct {
	t    *testing.T
	root string
}

func (p fakeProc) add(pid int, startTicks uint64) {
	dir := filepath.Join(p.root, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		p.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(statLine(pid, "init", startTicks)), 0o644); err != nil {
		p.t.Fatal(err)
	}
}

func writeProcs(t *testing.T, dir string, pids ...int) {
	t.Helper()
	var b strings.Builder
	for _, p := range pids {
		fmt.Fprintln(&b, p)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCgroupResolver_ContainerStart(t *testing.T) {
	root := t.TempDir()
	proc := fakeProc{t, t.TempDir()}
	const cid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	scope := filepath.Join(root, "machine.slice", "libpod-"+cid+".scope")
	leaf := filepath.Join(scope, "container") // crun-style nested leaf
	host := filepath.Join(root, "system.slice", "sshd.service")
	empty := filepath.Join(root, "system.slice", "docker-"+strings.Repeat("e", 64)+".scope")
	for _, d := range []string{leaf, host, empty} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Boot was at wall time 1_000_000; "now" is 10_000s after boot.
	boot := time.Unix(1_000_000, 0)
	sinceBoot := 10_000 * time.Second
	now := boot.Add(sinceBoot)
	r := NewCgroupResolver(root)
	r.procRoot = proc.root
	r.now = func() time.Time { return now }
	r.bootClock = func() (time.Time, time.Duration, bool) { return now, sinceBoot, true }

	// The init (oldest, started 5000.00s after boot) runs in the leaf, a
	// later exec in the scope; a pid that has already exited is skipped.
	proc.add(100, 500_000)
	proc.add(200, 900_000)
	writeProcs(t, leaf, 200, 100, 999)
	writeProcs(t, scope, 300)
	proc.add(300, 950_000)
	proc.add(400, 1)
	writeProcs(t, host, 400)

	start, ok := r.ContainerStart(dirIno(t, leaf))
	if want := boot.Add(5000 * time.Second); !ok || !start.Equal(want) {
		t.Fatalf("leaf ContainerStart = %v, %v; want %v", start, ok, want)
	}
	// The scope resolves to the same container and start.
	if s, ok := r.ContainerStart(dirIno(t, scope)); !ok || !s.Equal(start) {
		t.Errorf("scope ContainerStart = %v, %v; want %v", s, ok, start)
	}
	if _, ok := r.ContainerStart(dirIno(t, host)); ok {
		t.Error("host cgroup has a container start")
	}
	if _, ok := r.ContainerStart(0); ok {
		t.Error("cgroup 0 has a container start")
	}

	// Cached: later processes don't change it.
	proc.add(100, 800_000)
	if s, _ := r.ContainerStart(dirIno(t, leaf)); !s.Equal(start) {
		t.Errorf("start changed after caching: %v", s)
	}

	// A container with no readable processes is unknown, and retried only
	// once the rescan interval has passed.
	if _, ok := r.ContainerStart(dirIno(t, empty)); ok {
		t.Fatal("empty container has a start")
	}
	proc.add(500, 700_000)
	writeProcs(t, empty, 500)
	if _, ok := r.ContainerStart(dirIno(t, empty)); ok {
		t.Error("retried before the rescan interval")
	}
	now = now.Add(3 * time.Second)
	sinceBoot += 3 * time.Second
	if s, ok := r.ContainerStart(dirIno(t, empty)); !ok || !s.Equal(boot.Add(7000*time.Second)) {
		t.Errorf("retry: %v, %v", s, ok)
	}
}

func TestCgroupResolver_ContainerStartNoBootClock(t *testing.T) {
	root := t.TempDir()
	ctr := filepath.Join(root, "system.slice", "docker-"+strings.Repeat("a", 64)+".scope")
	if err := os.MkdirAll(ctr, 0o755); err != nil {
		t.Fatal(err)
	}
	writeProcs(t, ctr, os.Getpid())
	r := NewCgroupResolver(root)
	r.bootClock = func() (time.Time, time.Duration, bool) { return time.Time{}, 0, false }
	if _, ok := r.ContainerStart(dirIno(t, ctr)); ok {
		t.Error("start reported without a boot clock")
	}
}

func TestProcessStartTime_FutureRejected(t *testing.T) {
	proc := fakeProc{t, t.TempDir()}
	proc.add(1, 2000) // 20s after boot
	wall := time.Unix(1_000_000, 0)
	if _, ok := processStartTime(proc.root, 1, wall, 10*time.Second); ok {
		t.Error("start after now accepted")
	}
	if s, ok := processStartTime(proc.root, 1, wall, 20*time.Second-5*time.Millisecond); !ok || !s.Equal(wall) {
		t.Errorf("one-tick rounding: %v, %v", s, ok)
	}
}
