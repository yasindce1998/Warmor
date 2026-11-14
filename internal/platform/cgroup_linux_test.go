//go:build linux

package platform

import (
	"errors"
	"github.com/yasindce1998/warmor/internal/ebpf"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCgroupDiscoveryPodChurn(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "kubepods.slice")
	if err := os.Mkdir(base, 0755); err != nil {
		t.Fatal(err)
	}
	p := &LinuxPlatform{config: LinuxConfig{CgroupRoot: root}, scope: cgroupScope{enabled: true}}
	var written []uint64
	write := func(ids []uint64) error { written = append([]uint64(nil), ids...); return nil }
	if err := p.reconcileCgroups(ebpf.DiscoverPodCgroups, write); err != nil {
		t.Fatal(err)
	}
	if p.scope.contains(123) || len(written) != 0 {
		t.Fatal("empty scope expanded to host")
	}
	pod := filepath.Join(base, "kubepods-podabcd.slice")
	child := filepath.Join(pod, "cri-containerd-123.scope")
	if err := os.MkdirAll(child, 0755); err != nil {
		t.Fatal(err)
	}
	if err := p.reconcileCgroups(ebpf.DiscoverPodCgroups, write); err != nil {
		t.Fatal(err)
	}
	id, _ := ebpf.ResolveCgroupID(child)
	if !p.scope.contains(id) || len(written) != 2 {
		t.Fatal("new child not covered", written)
	}
	if err := os.Remove(child); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pod); err != nil {
		t.Fatal(err)
	}
	if err := p.reconcileCgroups(ebpf.DiscoverPodCgroups, write); err != nil {
		t.Fatal(err)
	}
	if p.scope.contains(id) || len(written) != 0 {
		t.Fatal("deleted child remains", written)
	}
}
func TestCgroupFailuresRetainScopeAndWithdrawReadiness(t *testing.T) {
	p := &LinuxPlatform{ebpfLoader: &ebpf.Loader{}, stopChan: make(chan struct{}), config: LinuxConfig{CgroupFilter: []string{"auto"}, CgroupRoot: "/host/cgroup", CgroupReconcileInterval: time.Second}, scope: cgroupScope{enabled: true}}
	p.scope.accept([]uint64{42}, nil)
	for _, failure := range []string{"discovery", "writer", "capacity"} {
		discover := func(root string) ([]uint64, error) {
			if root != "/host/cgroup" {
				t.Fatal(root)
			}
			if failure == "discovery" {
				return nil, errors.New("unreadable")
			}
			if failure == "capacity" {
				return make([]uint64, ebpf.CgroupFilterCapacity+1), nil
			}
			return []uint64{43}, nil
		}
		writes := 0
		writer := func([]uint64) error { writes++; return errors.New("map failed") }
		if err := p.reconcileCgroups(discover, writer); err == nil {
			t.Fatal("expected failure")
		}
		if !p.scope.contains(42) || p.scope.contains(43) || p.scope.contains(1) {
			t.Fatal("scope changed")
		}
		if p.Ready() == nil {
			t.Fatal("failure reported ready")
		}
		if failure != "writer" && writes != 0 {
			t.Fatal("invalid discovery touched maps")
		}
	}
	if err := p.reconcileCgroups(func(string) ([]uint64, error) { return []uint64{43}, nil }, func([]uint64) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if p.Ready() != nil || p.scope.contains(42) || !p.scope.contains(43) {
		t.Fatal("retry did not heal")
	}
	p.scope.Lock()
	p.scope.lastSync = time.Now().Add(-time.Minute)
	p.scope.Unlock()
	if err := p.Ready(); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatal(err)
	}
	p.readerError(errors.New("reader disconnected"))
	if err := p.Ready(); err == nil || !strings.Contains(err.Error(), "reader") {
		t.Fatal(err)
	}
}
