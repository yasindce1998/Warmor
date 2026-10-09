//go:build linux

package ebpf

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestResolveCgroupID_Self(t *testing.T) {
	// /proc/self/cgroup should always exist on Linux with cgroup v2
	selfCgroup := "/sys/fs/cgroup"
	if _, err := os.Stat(selfCgroup); os.IsNotExist(err) {
		t.Skip("cgroup v2 filesystem not mounted")
	}

	id, err := ResolveCgroupID(selfCgroup)
	if err != nil {
		t.Fatalf("ResolveCgroupID(%q) failed: %v", selfCgroup, err)
	}
	if id == 0 {
		t.Error("expected non-zero cgroup ID for root cgroup")
	}
}

func TestResolveCgroupID_NotExist(t *testing.T) {
	_, err := ResolveCgroupID("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for non-existent path")
	}
}

func TestResolveCgroupIDs(t *testing.T) {
	selfCgroup := "/sys/fs/cgroup"
	if _, err := os.Stat(selfCgroup); os.IsNotExist(err) {
		t.Skip("cgroup v2 filesystem not mounted")
	}

	ids, err := ResolveCgroupIDs([]string{selfCgroup})
	if err != nil {
		t.Fatalf("ResolveCgroupIDs failed: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected 1 ID, got %d", len(ids))
	}
	if ids[0] == 0 {
		t.Error("expected non-zero cgroup ID")
	}
}

func TestResolveCgroupIDs_MixedValid(t *testing.T) {
	_, err := ResolveCgroupIDs([]string{"/sys/fs/cgroup", "/nonexistent"})
	if err == nil {
		t.Fatal("expected error for mixed paths with non-existent entry")
	}
}

func TestDiscoverPodCgroups_NoKubepods(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := DiscoverPodCgroups(tmpDir)
	if err == nil {
		t.Fatal("expected error when kubepods directory doesn't exist")
	}
}

func TestDiscoverPodCgroups_EmptyKubepods(t *testing.T) {
	tmpDir := t.TempDir()
	kubepods := filepath.Join(tmpDir, "kubepods.slice")
	if err := os.MkdirAll(kubepods, 0755); err != nil {
		t.Fatal(err)
	}

	_, err := DiscoverPodCgroups(tmpDir)
	if err == nil {
		t.Fatal("expected error when no pod cgroups found")
	}
}

func TestGetPIDCgroupID_Self(t *testing.T) {
	if _, err := os.Stat("/sys/fs/cgroup"); os.IsNotExist(err) {
		t.Skip("cgroup v2 filesystem not mounted")
	}

	id, err := GetPIDCgroupID(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("GetPIDCgroupID(self) failed: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero cgroup ID for self")
	}
}

func TestGetPIDCgroupID_Invalid(t *testing.T) {
	_, err := GetPIDCgroupID(99999999)
	if err == nil {
		t.Fatal("expected error for invalid PID")
	}
}

func TestDiscoverPodCgroups_KubepodsSlice(t *testing.T) {
	tmpDir := t.TempDir()
	base := filepath.Join(tmpDir, "kubepods.slice")
	// Pod slices and the container scopes beneath them are returned; the QoS
	// slices (which merely contain "kubepods") are not pods and are skipped.
	qosDirs := []string{
		filepath.Join(base, "kubepods-besteffort.slice"),
		filepath.Join(base, "kubepods-burstable.slice"),
	}
	podDirs := []string{
		filepath.Join(base, "kubepods-pod9f8e7d6c_1234_4abc_8def_0123456789ab.slice"),
		filepath.Join(base, "kubepods-besteffort.slice", "kubepods-besteffort-pod1234.slice"),
		filepath.Join(base, "kubepods-burstable.slice", "kubepods-burstable-podabcd.slice"),
		filepath.Join(base, "kubepods-burstable.slice", "kubepods-burstable-podabcd.slice", "cri-containerd-0123.scope"),
		filepath.Join(base, "kubepods-burstable.slice", "kubepods-burstable-podabcd.slice", "crio-4567.scope"),
	}
	for _, d := range append(qosDirs, podDirs...) {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	// A regular file whose name contains "pod" must be ignored.
	if err := os.WriteFile(filepath.Join(base, "pod-notadir"), nil, 0644); err != nil {
		t.Fatal(err)
	}

	ids, err := DiscoverPodCgroups(tmpDir)
	if err != nil {
		t.Fatalf("DiscoverPodCgroups failed: %v", err)
	}

	want := make(map[uint64]bool)
	for _, d := range podDirs {
		id, err := ResolveCgroupID(d)
		if err != nil {
			t.Fatal(err)
		}
		want[id] = true
	}
	if len(ids) != len(want) {
		t.Fatalf("got %d IDs %v, want %d", len(ids), ids, len(want))
	}
	for _, id := range ids {
		if !want[id] {
			t.Errorf("unexpected cgroup ID %d", id)
		}
	}
}

func TestDiscoverPodCgroups_CgroupfsKubepods(t *testing.T) {
	// cgroupfs driver layout: kubepods/<qos>/pod<uid>/<container-id>, plus
	// guaranteed pods directly under kubepods/. Container dirs are bare hex
	// IDs that contain no "pod" substring but must still be included.
	tmpDir := t.TempDir()
	base := filepath.Join(tmpDir, "kubepods")
	pod := filepath.Join(base, "besteffort", "pod5678abcd-1234-4abc-8def-0123456789ab")
	podDirs := []string{
		pod,
		filepath.Join(pod, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		filepath.Join(pod, "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"),
		filepath.Join(base, "pod1111aaaa-2222-4333-8444-555566667777"),
	}
	for _, d := range podDirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	// The QoS dir and a non-pod sibling must not be returned.
	if err := os.MkdirAll(filepath.Join(base, "burstable", "system"), 0755); err != nil {
		t.Fatal(err)
	}

	ids, err := DiscoverPodCgroups(tmpDir)
	if err != nil {
		t.Fatalf("DiscoverPodCgroups failed: %v", err)
	}
	want := make(map[uint64]bool)
	for _, d := range podDirs {
		id, err := ResolveCgroupID(d)
		if err != nil {
			t.Fatal(err)
		}
		want[id] = true
	}
	if len(ids) != len(want) {
		t.Fatalf("got %d IDs %v, want %d", len(ids), ids, len(want))
	}
	for _, id := range ids {
		if !want[id] {
			t.Errorf("unexpected cgroup ID %d", id)
		}
	}
}

func TestIsPodCgroupDir(t *testing.T) {
	for name, want := range map[string]bool{
		"kubepods-pod9f8e7d6c_1234_4abc_8def_0123456789ab.slice":            true,
		"kubepods-besteffort-pod9f8e7d6c_1234_4abc_8def_0123456789ab.slice": true,
		"kubepods-burstable-podabcd.slice":                                  true,
		"pod9f8e7d6c-1234-4abc-8def-0123456789ab":                           true,
		"kubepods-besteffort.slice":                                         false,
		"kubepods-burstable.slice":                                          false,
		"kubepods.slice":                                                    false,
		"besteffort":                                                        false,
		"cri-containerd-0123.scope":                                         false,
		"0123456789abcdef":                                                  false,
		"podman.slice":                                                      false,
	} {
		if got := isPodCgroupDir(name); got != want {
			t.Errorf("isPodCgroupDir(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestDiscoverPodCgroups_PrefersSlice(t *testing.T) {
	tmpDir := t.TempDir()
	slicePod := filepath.Join(tmpDir, "kubepods.slice", "pod-a")
	plainPod := filepath.Join(tmpDir, "kubepods", "pod-b")
	for _, d := range []string{slicePod, plainPod} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	ids, err := DiscoverPodCgroups(tmpDir)
	if err != nil {
		t.Fatalf("DiscoverPodCgroups failed: %v", err)
	}
	wantID, _ := ResolveCgroupID(slicePod)
	if len(ids) != 1 || ids[0] != wantID {
		t.Errorf("ids = %v, want only kubepods.slice pod [%d]", ids, wantID)
	}
}

func TestDiscoverPodCgroups_KubepodsIsFile(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "kubepods.slice"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := DiscoverPodCgroups(tmpDir); err == nil {
		t.Fatal("expected error when kubepods.slice is a regular file")
	}
}

func TestDiscoverPodCgroups_NoMatchingDirs(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmpDir, "kubepods", "besteffort", "system"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := DiscoverPodCgroups(tmpDir); err == nil {
		t.Fatal("expected error when no pod-like directories exist")
	}
}

func TestResolveCgroupIDs_Empty(t *testing.T) {
	ids, err := ResolveCgroupIDs(nil)
	if err != nil {
		t.Fatalf("ResolveCgroupIDs(nil) failed: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expected empty result, got %v", ids)
	}
}

func TestResolveCgroupID_MatchesInode(t *testing.T) {
	dir := t.TempDir()
	id, err := ResolveCgroupID(dir)
	if err != nil {
		t.Fatalf("ResolveCgroupID failed: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no syscall.Stat_t available")
	}
	if id != st.Ino {
		t.Errorf("ResolveCgroupID = %d, want inode %d", id, st.Ino)
	}
}
