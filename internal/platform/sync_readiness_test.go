//go:build linux

package platform

import (
	"testing"

	"github.com/yasindce1998/warmor/internal/ebpf"
)

// The mirrored kernel-sync posture is observability-only: it starts healthy
// and changing it must not withdraw platform readiness.
func TestKernelSyncPostureDoesNotFlipPlatformReadiness(t *testing.T) {
	p := &LinuxPlatform{
		ebpfLoader: &ebpf.Loader{},
		stopChan:   make(chan struct{}),
	}

	if !p.KernelSyncHealthy() {
		t.Fatal("default kernel sync posture must be healthy")
	}
	if err := p.Ready(); err != nil {
		t.Fatalf("baseline readiness: %v", err)
	}

	p.SetKernelSyncHealthy(false)
	if p.KernelSyncHealthy() {
		t.Fatal("degraded kernel sync posture not reported")
	}
	if err := p.Ready(); err != nil {
		t.Fatalf("degraded kernel sync posture flipped readiness: %v", err)
	}

	p.SetKernelSyncHealthy(true)
	if !p.KernelSyncHealthy() {
		t.Fatal("kernel sync posture did not recover")
	}
	if err := p.Ready(); err != nil {
		t.Fatalf("healthy kernel sync posture withdrew readiness: %v", err)
	}
}
