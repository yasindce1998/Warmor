//go:build linux

package container

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func dirIno(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no Stat_t for %s", path)
	}
	return st.Ino
}

func TestCgroupResolver(t *testing.T) {
	root := t.TempDir()
	const cid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	host := filepath.Join(root, "system.slice", "sshd.service")
	ctr := filepath.Join(root, "kubepods.slice", "kubepods-pod1.slice", "cri-containerd-"+cid+".scope")
	conmon := filepath.Join(root, "machine.slice", "crio-conmon-"+cid+".scope")
	for _, d := range []string{host, ctr, conmon} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Unix(1000, 0)
	r := NewCgroupResolver(root)
	r.now = func() time.Time { return now }

	info, ok := r.Lookup(dirIno(t, ctr))
	if !ok || info.ID != cid || info.Runtime != RuntimeContainerd || info.CgroupID != dirIno(t, ctr) {
		t.Fatalf("container lookup = %+v, %v", info, ok)
	}
	if r.IsContainer(dirIno(t, host)) {
		t.Error("host service cgroup resolved as a container")
	}
	if r.IsContainer(dirIno(t, conmon)) {
		t.Error("crio-conmon scope resolved as a container")
	}
	if r.IsContainer(0) {
		t.Error("cgroup id 0 resolved as a container")
	}

	// A container created after the last scan is found once the rescan
	// interval has passed, not before.
	late := filepath.Join(root, "system.slice", "docker-"+cid[:12]+cid[12:]+".scope")
	if err := os.MkdirAll(late, 0o755); err != nil {
		t.Fatal(err)
	}
	if r.IsContainer(999999999) {
		t.Fatal("unknown id resolved")
	}
	if r.IsContainer(dirIno(t, late)) {
		t.Error("rescanned before minRescan elapsed")
	}
	now = now.Add(3 * time.Second)
	if !r.IsContainer(dirIno(t, late)) {
		t.Error("new container not found after rescan")
	}
}

func TestContainerFromCgroup_Podman(t *testing.T) {
	const cid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	info, err := ContainerFromCgroup("/sys/fs/cgroup/machine.slice/libpod-" + cid + ".scope")
	if err != nil || info.ID != cid || info.Runtime != RuntimePodman {
		t.Fatalf("podman = %+v, %v", info, err)
	}
	if _, err := ContainerFromCgroup("/sys/fs/cgroup/machine.slice/libpod-conmon-" + cid + ".scope"); err == nil {
		t.Error("libpod-conmon scope resolved as a container")
	}
}
