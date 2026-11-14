//go:build linux

package platform

import (
	"context"
	"fmt"
	"github.com/yasindce1998/warmor/internal/ebpf"
	"github.com/yasindce1998/warmor/internal/metrics"
	"sync"
	"time"
)

type cgroupScope struct {
	sync.RWMutex
	enabled   bool // immutable after Load, before any reader starts
	ids       map[uint64]bool
	err       error
	readerErr error
	lastSync  time.Time
}

func (s *cgroupScope) contains(id uint64) bool {
	s.RLock()
	defer s.RUnlock()
	return !s.enabled || s.ids[id]
}
func (s *cgroupScope) accept(ids []uint64, err error) {
	metrics.RecordCgroupReconciliation(len(ids), err)
	s.Lock()
	defer s.Unlock()
	s.err = err
	if err != nil {
		return
	} // retain last good userspace scope
	s.ids = make(map[uint64]bool, len(ids))
	for _, id := range ids {
		s.ids[id] = true
	}
	s.lastSync = time.Now()
}
func (p *LinuxPlatform) autoCgroups() bool {
	return len(p.config.CgroupFilter) == 1 && p.config.CgroupFilter[0] == "auto"
}

// Injection permits unprivileged discovery/churn/error tests without BPF.
func (p *LinuxPlatform) reconcileCgroups(discover func(string) ([]uint64, error), writers ...func([]uint64) error) error {
	ids, err := discover(p.config.CgroupRoot)
	if err == nil && len(ids) > ebpf.CgroupFilterCapacity {
		err = fmt.Errorf("cgroup filter capacity exceeded: %d exact IDs, maximum %d", len(ids), ebpf.CgroupFilterCapacity)
	}
	if err == nil {
		for _, write := range writers {
			if err = write(ids); err != nil {
				break
			}
		}
	}
	p.scope.accept(ids, err)
	return err
}
func (p *LinuxPlatform) monitorCgroups(ctx context.Context) {
	defer p.wg.Done()
	tick := time.NewTicker(p.config.CgroupReconcileInterval)
	defer tick.Stop()
	writers := []func([]uint64) error{p.ebpfLoader.ReplaceCgroupFilter}
	if p.lsmLoader != nil {
		writers = append(writers, p.lsmLoader.ReplaceCgroupFilter)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		case <-tick.C:
			if err := p.reconcileCgroups(ebpf.DiscoverPodCgroups, writers...); err != nil {
				fmt.Printf("ERROR: cgroup reconciliation failed (not ready; retaining last accepted userspace scope): %v\n", err)
			}
		}
	}
}
func (p *LinuxPlatform) readerError(err error) {
	p.scope.Lock()
	defer p.scope.Unlock()
	p.scope.readerErr = fmt.Errorf("event reader stopped: %w", err)
}

// Ready reports local capture/scope health, not admission or CR generation ack.
func (p *LinuxPlatform) Ready() error {
	select {
	case <-p.stopChan:
		return fmt.Errorf("platform stopped")
	default:
	}
	if p.ebpfLoader == nil {
		return fmt.Errorf("platform not loaded")
	}
	if p.config.LSMEnforce && !p.lsmEnabled {
		return fmt.Errorf("requested LSM enforcement is inactive")
	}
	p.scope.RLock()
	defer p.scope.RUnlock()
	if p.scope.readerErr != nil {
		return p.scope.readerErr
	}
	if p.scope.err != nil {
		return fmt.Errorf("cgroup reconciliation: %w", p.scope.err)
	}
	if p.autoCgroups() && time.Since(p.scope.lastSync) > 3*p.config.CgroupReconcileInterval {
		return fmt.Errorf("cgroup discovery is stale")
	}
	return nil
}
