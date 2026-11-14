//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
	_, err := ResolveCgroupID(filepath.Join(t.TempDir(), "missing"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("resolver must preserve wrapped ENOENT: %v", err)
	}
}

func TestDiscoverPodCgroupsWrappedResolverChurn(t *testing.T) {
	root := t.TempDir()
	pod := filepath.Join(root, "kubepods", "podabcd")
	child := filepath.Join(pod, "container")
	if err := os.MkdirAll(child, 0755); err != nil {
		t.Fatal(err)
	}
	podID, err := ResolveCgroupID(pod)
	if err != nil {
		t.Fatal(err)
	}
	removed := false
	ids, err := discoverPodCgroups(root, func(path string) (uint64, error) {
		if path == child {
			// Walk has already stat'ed this directory. Delete it just before
			// the actual resolver's Statx, as happens during container churn.
			if err := os.Remove(child); err != nil {
				t.Fatal(err)
			}
			removed = true
		}
		id, err := ResolveCgroupID(path)
		if err != nil {
			return 0, fmt.Errorf("additional resolver context: %w", err)
		}
		return id, nil
	})
	if err != nil || !removed || len(ids) != 1 || ids[0] != podID {
		t.Fatalf("wrapped ENOENT during churn should skip only vanished child: ids=%v removed=%v err=%v", ids, removed, err)
	}
	// Non-churn resolver failures must still fail discovery, not be mistaken
	// for a harmless deletion and silently shrink coverage.
	_, err = discoverPodCgroups(root, func(string) (uint64, error) {
		return 0, fmt.Errorf("statx permission: %w", fs.ErrPermission)
	})
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("wrapped permission error was swallowed: %v", err)
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

	ids, err := DiscoverPodCgroups(tmpDir)
	if err != nil || len(ids) != 0 {
		t.Fatalf("empty hierarchy must be an empty scoped set: %v, %v", ids, err)
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

func TestDiscoverPodCgroups_KubeletRootLayouts(t *testing.T) {
	for _, tc := range []struct {
		name, base, qos, guaranteed, burstable string
	}{
		{"kind-systemd", "kubelet.slice/kubelet-kubepods.slice", "kubelet-kubepods-burstable.slice", "kubelet-kubepods-podabcd.slice", "kubelet-kubepods-burstable-podabcd_1234.slice"},
		{"kubelet-cgroupfs", "kubelet/kubepods", "burstable", "podabcd-1234", "poddef0-5678"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			base := filepath.Join(root, filepath.FromSlash(tc.base))
			pod := filepath.Join(base, tc.qos, tc.burstable)
			podDirs := []string{
				filepath.Join(base, tc.guaranteed),
				pod,
				filepath.Join(pod, "cri-containerd-abcd.scope"),
				filepath.Join(pod, "crio-def0.scope", "nested-child"),
				filepath.Join(pod, "crio-def0.scope"),
			}
			for _, path := range append(podDirs,
				filepath.Join(root, "system.slice", "poddead"), // outside the selected pod hierarchy
				filepath.Join(root, "kubelet.slice", "host-service.scope"),
				filepath.Join(base, tc.qos, "host-service.scope")) {
				if err := os.MkdirAll(path, 0755); err != nil {
					t.Fatal(err)
				}
			}
			ids, err := DiscoverPodCgroups(root)
			if err != nil {
				t.Fatal(err)
			}
			want := make(map[uint64]bool)
			for _, path := range podDirs {
				id, err := ResolveCgroupID(path)
				if err != nil {
					t.Fatal(err)
				}
				want[id] = true
			}
			if len(ids) != len(want) {
				t.Fatalf("nested hierarchy lost pod/descendant IDs: got %v, want %v", ids, want)
			}
			for _, id := range ids {
				if !want[id] {
					t.Fatalf("scope included parent/QoS/host ID %d", id)
				}
			}
		})
	}
}

func TestDiscoverPodCgroups_KubeletRootStillFailsWithoutPodHierarchy(t *testing.T) {
	for _, layout := range []string{"kubelet.slice", "kubelet", "kubelet.slice/kubelet-kubepods.slice", "kubelet/kubepods"} {
		t.Run(layout, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, filepath.FromSlash(layout))
			if strings.Contains(layout, "/") {
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, nil, 0644); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(path, 0755); err != nil {
				t.Fatal(err)
			}
			if ids, err := DiscoverPodCgroups(root); err == nil {
				t.Fatalf("missing/non-directory nested pod hierarchy must fail, got %v", ids)
			}
		})
	}
}

func TestIsPodCgroupDir(t *testing.T) {
	for name, want := range map[string]bool{
		"kubepods-pod9f8e7d6c_1234_4abc_8def_0123456789ab.slice":            true,
		"kubepods-besteffort-pod9f8e7d6c_1234_4abc_8def_0123456789ab.slice": true,
		"kubepods-burstable-podabcd.slice":                                  true,
		"kubelet-kubepods-podabcd.slice":                                    true,
		"kubelet-kubepods-besteffort-podabcd_1234.slice":                    true,
		"kubelet-kubepods-burstable-podabcd.slice":                          true,
		"pod9f8e7d6c-1234-4abc-8def-0123456789ab":                           true,
		"kubepods-besteffort.slice":                                         false,
		"kubepods-burstable.slice":                                          false,
		"kubepods.slice":                                                    false,
		"kubelet-kubepods.slice":                                            false,
		"kubelet-kubepods-besteffort.slice":                                 false,
		"kubelet-kubepods-burstable.slice":                                  false,
		"arbitrary-kubepods-podabcd.slice":                                  false,
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
	if ids, err := DiscoverPodCgroups(tmpDir); err != nil || len(ids) != 0 {
		t.Fatalf("no pods must be an empty scoped set: %v, %v", ids, err)
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
