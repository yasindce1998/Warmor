package winutil

import (
	"sync"
	"time"
)

// exitGrace is how long an exited process stays resolvable. ETW delivers
// events asynchronously, so a file or network event from a process can
// arrive after its exit event.
const exitGrace = 30 * time.Second

// maxProcEntries bounds the table if exit events are lost.
const maxProcEntries = 65536

// ProcInfo is what the platform knows about a running process.
type ProcInfo struct {
	PID        uint32
	PPID       uint32
	NTImage    string // NT device path, as the kernel reports it
	Image      string // drive-letter path
	Comm       string // lowercased image file name
	CmdLine    string
	CreateTime time.Time

	exitedAt time.Time
}

// ProcTable maps PIDs to process information. It is fed by process start and
// exit events and read when enriching file and network events, which on
// Windows only carry a PID.
type ProcTable struct {
	mu        sync.RWMutex
	m         map[uint32]*ProcInfo
	now       func() time.Time
	lastSweep time.Time
}

// sweepInterval rate-limits the O(n) sweep run on process exits.
const sweepInterval = time.Second

// NewProcTable creates an empty process table.
func NewProcTable() *ProcTable {
	return &ProcTable{m: make(map[uint32]*ProcInfo), now: time.Now}
}

// Put records a process start, replacing any previous process with the same
// PID (Windows reuses PIDs aggressively).
func (t *ProcTable) Put(info ProcInfo) {
	info.exitedAt = time.Time{}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.m) >= maxProcEntries {
		t.sweepLocked(true)
	}
	t.m[info.PID] = &info
}

// Get returns the process for pid, including recently exited ones.
func (t *ProcTable) Get(pid uint32) (ProcInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p, ok := t.m[pid]
	if !ok {
		return ProcInfo{}, false
	}
	return *p, true
}

// Exit marks pid as exited. It stays resolvable for a grace period.
func (t *ProcTable) Exit(pid uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if p, ok := t.m[pid]; ok && p.exitedAt.IsZero() {
		p.exitedAt = now
	}
	if now.Sub(t.lastSweep) >= sweepInterval {
		t.lastSweep = now
		t.sweepLocked(false)
	}
}

// Len returns the number of tracked processes.
func (t *ProcTable) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.m)
}

// sweepLocked drops processes past their exit grace. With force it also
// drops all exited processes, and if that frees nothing, the oldest half of
// the table, so lost exit events cannot grow it without bound.
func (t *ProcTable) sweepLocked(force bool) {
	now := t.now()
	freed := false
	for pid, p := range t.m {
		if !p.exitedAt.IsZero() && (force || now.Sub(p.exitedAt) > exitGrace) {
			delete(t.m, pid)
			freed = true
		}
	}
	if force && !freed {
		// Drop everything created in the older half of the observed span.
		var oldest, newest time.Time
		for _, p := range t.m {
			if oldest.IsZero() || p.CreateTime.Before(oldest) {
				oldest = p.CreateTime
			}
			if p.CreateTime.After(newest) {
				newest = p.CreateTime
			}
		}
		mid := oldest.Add(newest.Sub(oldest) / 2)
		for pid, p := range t.m {
			if !p.CreateTime.After(mid) {
				delete(t.m, pid)
			}
		}
	}
}
