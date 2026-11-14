//go:build linux

package platform

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/ebpf"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Exercise the real monitor conversion/delivery loops with synthetic readers:
// no BPF attachment, pidfd open or signal is performed. Both scope filtering and
// the strict signaling identity must survive across all Linux capture paths.
func TestLinuxMonitorsPreserveKernelIdentityWithCgroupReadiness(t *testing.T) {
	type monitor func(*LinuxPlatform, context.Context, func() (*ebpf.Event, error))
	for _, tc := range []struct {
		name string
		kind ebpf.EventKind
		run  monitor
		lsm  bool
	}{
		{"exec", ebpf.EventKindProcess, (*LinuxPlatform).monitorProcessEventsFrom, false},
		{"file", ebpf.EventKindFile, (*LinuxPlatform).monitorFileEventsFrom, false},
		{"network", ebpf.EventKindNetwork, (*LinuxPlatform).monitorNetworkEventsFrom, false},
		{"lsm-exec", ebpf.EventKindProcess, (*LinuxPlatform).monitorLSMEventsFrom, true},
		{"lsm-file", ebpf.EventKindFile, (*LinuxPlatform).monitorLSMEventsFrom, true},
		{"lsm-network", ebpf.EventKindNetwork, (*LinuxPlatform).monitorLSMEventsFrom, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const stamp uint64 = 9876543210123
			out := make(chan *api.Event, 3)
			p := &LinuxPlatform{
				ebpfLoader: &ebpf.Loader{}, eventChan: out, stopChan: make(chan struct{}),
				config: LinuxConfig{CgroupFilter: []string{"auto"}, CgroupReconcileInterval: time.Second},
				scope:  cgroupScope{enabled: true},
			}
			p.scope.accept([]uint64{42}, nil)
			var captured, released atomic.Int32
			p.SetEventCapture(func(event *api.Event) bool {
				captured.Add(1)
				id := uint64(88) // tracepoints capture current at dispatch
				if event.LSMEvent {
					id = event.PolicyGeneration
				}
				event.GenerationContext = api.NewGenerationContext(id, func() { released.Add(1) })
				return true
			})
			if err := p.Ready(); err != nil {
				t.Fatal(err)
			}
			input := ebpf.Event{
				Kind: tc.kind, PID: 1234, UID: 10001, GID: 10002, CgroupID: 42,
				KernelTimestampNS: stamp, Timestamp: time.Unix(42, 123),
				PolicyGeneration: 77,
				Comm:             "identity-marker", Filename: "/marker", Args: []string{"marker", "argument"},
				PPID: 123, ParentComm: "parent", Family: 10, RemoteAddr: "::1", RemotePort: 443,
				KernelDenied: true, IntegrityViolation: true, Hook: "bprm_check_security",
				TargetCgroupID: 43, MountSource: "/source",
			}
			readerErr := errors.New("synthetic reader disconnected")
			reads := 0
			p.wg.Add(1)
			tc.run(p, context.Background(), func() (*ebpf.Event, error) {
				reads++
				event := input
				switch reads {
				case 1:
					event.CgroupID = 999 // outside exact scope: never delivered
				case 2:
				case 3:
					event.KernelTimestampNS = 0 // missing stays missing, not synthesized
				default:
					return nil, readerErr
				}
				return &event, nil
			})
			p.wg.Wait()
			if len(out) != 2 || captured.Load() != 2 {
				t.Fatalf("scope leaked or lost events: %d", len(out))
			}
			for _, wantStamp := range []uint64{stamp, 0} {
				event := <-out
				if event.KernelTimestampNS != wantStamp || event.CgroupID != input.CgroupID || event.PID != input.PID || event.UID != input.UID || event.GID != input.GID || event.Timestamp != input.Timestamp || event.LSMEvent != tc.lsm {
					t.Fatalf("monitor lost raw identity: %+v", event)
				}
				if tc.lsm && (!event.KernelDenied || !event.IntegrityViolation || event.Hook != input.Hook || event.TargetCgroupID != input.TargetCgroupID || event.MountSource != input.MountSource) {
					t.Fatalf("LSM outcome/identity evidence lost: %+v", event)
				}
				wantGeneration := uint64(88)
				if tc.lsm {
					wantGeneration = input.PolicyGeneration
				}
				if event.GenerationContext == nil || event.GenerationContext.ID != wantGeneration {
					t.Fatalf("scoped monitor lost captured generation: %+v", event)
				}
				event.GenerationContext.Complete()
			}
			if released.Load() != 2 {
				t.Fatal("scoped monitor delivery leaked generation leases")
			}
			if err := p.Ready(); !errors.Is(err, readerErr) {
				t.Fatalf("reader failure must withdraw readiness: %v", err)
			}
		})
	}
}
