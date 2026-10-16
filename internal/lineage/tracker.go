package lineage

import (
	"container/list"
	"sync"
	"time"
)

// ProcessInfo stores metadata about a tracked process.
type ProcessInfo struct {
	PID       uint32
	PPID      uint32
	Comm      string
	Filename  string
	UID       uint32
	GID       uint32
	StartTime time.Time
}

// Tracker maintains an in-memory process tree built from exec events.
// It provides ancestry lookups for stateful policy evaluation.
type Tracker struct {
	mu        sync.RWMutex
	processes map[uint32]*ProcessInfo
	// order lists tracked PIDs from oldest to newest StartTime, so the
	// oldest is evicted in O(1); elems indexes it by PID.
	order    *list.List
	elems    map[uint32]*list.Element
	maxDepth int
	maxSize  int
}

// TrackerConfig configures the process lineage tracker.
type TrackerConfig struct {
	MaxDepth int // Maximum ancestry chain depth (default 16)
	MaxSize  int // Maximum number of processes to track (default 100000)
}

// NewTracker creates a process lineage tracker.
func NewTracker(cfg TrackerConfig) *Tracker {
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 16
	}
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 100000
	}
	return &Tracker{
		processes: make(map[uint32]*ProcessInfo, 4096),
		order:     list.New(),
		elems:     make(map[uint32]*list.Element, 4096),
		maxDepth:  cfg.MaxDepth,
		maxSize:   cfg.MaxSize,
	}
}

// RecordExec registers a new process execution.
func (t *Tracker) RecordExec(pid, ppid, uid, gid uint32, comm, filename string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if el, ok := t.elems[pid]; ok {
		// Re-exec of a tracked PID: it becomes the newest entry.
		t.order.MoveToBack(el)
	} else {
		if len(t.processes) >= t.maxSize {
			t.evictOldest()
		}
		t.elems[pid] = t.order.PushBack(pid)
	}

	t.processes[pid] = &ProcessInfo{
		PID:       pid,
		PPID:      ppid,
		Comm:      comm,
		Filename:  filename,
		UID:       uid,
		GID:       gid,
		StartTime: time.Now(),
	}
}

// RecordExit removes a process from tracking.
func (t *Tracker) RecordExit(pid uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.remove(pid)
}

func (t *Tracker) remove(pid uint32) {
	if el, ok := t.elems[pid]; ok {
		t.order.Remove(el)
		delete(t.elems, pid)
	}
	delete(t.processes, pid)
}

// GetAncestors returns the ancestry chain for a given PID, from parent up to root.
func (t *Tracker) GetAncestors(pid uint32) []ProcessInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var chain []ProcessInfo
	seen := make(map[uint32]bool)
	current := pid

	for i := 0; i < t.maxDepth; i++ {
		info, ok := t.processes[current]
		if !ok || info.PPID == 0 || info.PPID == current {
			break
		}
		if seen[info.PPID] {
			break // cycle detection
		}
		seen[current] = true

		parent, ok := t.processes[info.PPID]
		if !ok {
			break
		}
		chain = append(chain, *parent)
		current = info.PPID
	}
	return chain
}

// GetProcess returns info for a specific PID.
func (t *Tracker) GetProcess(pid uint32) (ProcessInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	info, ok := t.processes[pid]
	if !ok {
		return ProcessInfo{}, false
	}
	return *info, true
}

// HasAncestor checks if any ancestor of pid matches the given comm name.
func (t *Tracker) HasAncestor(pid uint32, comm string) bool {
	ancestors := t.GetAncestors(pid)
	for _, a := range ancestors {
		if a.Comm == comm {
			return true
		}
	}
	return false
}

// Size returns the number of tracked processes.
func (t *Tracker) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.processes)
}

// evictOldest drops the process with the oldest StartTime. Entries are
// appended (or moved to the back) whenever StartTime is set, so that is the
// front of order.
func (t *Tracker) evictOldest() {
	if el := t.order.Front(); el != nil {
		pid, _ := el.Value.(uint32)
		t.remove(pid)
	}
}
