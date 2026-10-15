package container

import (
	"io/fs"
	"path/filepath"
	"sync"
	"time"
)

// CgroupResolver maps kernel cgroup ids (what BPF reports) to containers.
//
// A cgroup v2 id is the inode number of its directory under the cgroup
// mount, and ids are never reused while the system is up, so a resolved id
// stays valid. Lookups that miss trigger a rescan of the hierarchy, rate
// limited so a stream of host-process events can't turn into a stream of
// directory walks.
type CgroupResolver struct {
	root      string
	procRoot  string
	minRescan time.Duration
	now       func() time.Time
	// bootClock returns the wall clock and the time since boot
	// (CLOCK_BOOTTIME) at the same instant; see processStartTime.
	bootClock  func() (wall time.Time, sinceBoot time.Duration, ok bool)
	mu         sync.Mutex
	byID       map[uint64]*cgroupEntry
	lastScan   time.Time
	scanErrors int
}

// cgroupEntry is what the resolver knows about one cgroup id.
type cgroupEntry struct {
	info *ContainerInfo // nil: known cgroup, not a container
	path string

	// start is the container's start time once determined; lastStartTry
	// rate-limits attempts while it is not.
	start        time.Time
	lastStartTry time.Time
}

// NewCgroupResolver resolves ids under root (normally /sys/fs/cgroup).
func NewCgroupResolver(root string) *CgroupResolver {
	return &CgroupResolver{
		root:      root,
		procRoot:  "/proc",
		minRescan: 2 * time.Second,
		now:       time.Now,
		bootClock: bootClockNow,
		byID:      make(map[uint64]*cgroupEntry),
	}
}

// Lookup returns the container a cgroup belongs to. ok is false for host
// cgroups and for ids not (yet) present in the hierarchy.
func (r *CgroupResolver) Lookup(cgroupID uint64) (info *ContainerInfo, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.lookupLocked(cgroupID)
	if e == nil || e.info == nil {
		return nil, false
	}
	return e.info, true
}

func (r *CgroupResolver) lookupLocked(cgroupID uint64) *cgroupEntry {
	if cgroupID == 0 {
		return nil
	}
	if e, known := r.byID[cgroupID]; known {
		return e
	}
	if now := r.now(); r.lastScan.IsZero() || now.Sub(r.lastScan) >= r.minRescan {
		r.lastScan = now
		r.rescanLocked()
		return r.byID[cgroupID]
	}
	return nil
}

// IsContainer reports whether cgroupID belongs to a container.
func (r *CgroupResolver) IsContainer(cgroupID uint64) bool {
	_, ok := r.Lookup(cgroupID)
	return ok
}

// maxStartPIDs bounds the processes examined to date one container, so a
// container with a huge process count cannot stall event handling.
const maxStartPIDs = 10000

// ContainerStart returns when the container that cgroupID belongs to
// started. ok is false for host cgroups and when the start cannot be
// determined.
//
// The start is the earliest start time (/proc/<pid>/stat field 22) of any
// process in the container's cgroup subtree: the container's init is
// started when the container is, and lives as long as it does. The value
// is cached per cgroup once found; an undetermined start is retried at most
// once per rescan interval.
//
// Cgroup directory timestamps are deliberately not used. cgroup v2 is
// kernfs, which reports no birth time (statx STATX_BTIME is unsupported),
// and its mtime/ctime are either the moment the VFS inode was instantiated
// (first access, or again after the inode was evicted) or the last chown,
// chmod or child create/remove, so they make containers look younger than
// they are. Neither is the time the daemon first saw the cgroup, which for
// containers that predate the daemon is arbitrarily late.
//
// Limits: pids are read from cgroup.procs in the daemon's PID namespace, so
// the daemon must share the host PID namespace (hostPID) or the start is
// unknown. A process migrated into the container's cgroup from outside
// (only possible from the host, with root) can make it look older. The
// resolution is a clock tick (10ms with the usual USER_HZ of 100).
func (r *CgroupResolver) ContainerStart(cgroupID uint64) (start time.Time, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.lookupLocked(cgroupID)
	if e == nil || e.info == nil {
		return time.Time{}, false
	}
	if !e.start.IsZero() {
		return e.start, true
	}
	now := r.now()
	if !e.lastStartTry.IsZero() && now.Sub(e.lastStartTry) < r.minRescan {
		return time.Time{}, false
	}
	e.lastStartTry = now
	s, ok := r.earliestProcessStart(r.containerDir(e.path, e.info.ID))
	if !ok {
		return time.Time{}, false
	}
	e.start = s
	return s, true
}

// containerDir returns the topmost directory at or above path that still
// belongs to container id: runtimes may run the container's processes in a
// child of the container's scope (e.g. crun's .../libpod-<id>.scope/container).
func (r *CgroupResolver) containerDir(path, id string) string {
	dir := path
	for {
		parent := filepath.Dir(dir)
		if parent == dir || len(parent) <= len(r.root) {
			return dir
		}
		ci, err := ContainerFromCgroup(parent)
		if err != nil || ci.ID != id {
			return dir
		}
		dir = parent
	}
}

// earliestProcessStart returns the earliest start time of the processes in
// the cgroup subtree at dir.
func (r *CgroupResolver) earliestProcessStart(dir string) (time.Time, bool) {
	wall, sinceBoot, ok := r.bootClock()
	if !ok {
		return time.Time{}, false
	}
	var earliest time.Time
	seen := 0
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() && path != dir {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		for _, pid := range readPIDs(filepath.Join(path, "cgroup.procs")) {
			if seen >= maxStartPIDs {
				return fs.SkipAll
			}
			seen++
			s, ok := processStartTime(r.procRoot, pid, wall, sinceBoot)
			if ok && (earliest.IsZero() || s.Before(earliest)) {
				earliest = s
			}
		}
		return nil
	})
	return earliest, !earliest.IsZero()
}

// rescanLocked rebuilds the id map from the hierarchy, dropping cgroups that
// no longer exist.
func (r *CgroupResolver) rescanLocked() {
	byID := make(map[uint64]*cgroupEntry, len(r.byID))
	err := filepath.WalkDir(r.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Cgroups vanish mid-walk all the time; skip, don't abort.
			if d != nil && d.IsDir() && path != r.root {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		id, ok := inodeOf(fi)
		if !ok {
			return nil
		}
		if prev, seen := r.byID[id]; seen {
			byID[id] = prev
			return nil
		}
		e := &cgroupEntry{path: path}
		if ci, err := ContainerFromCgroup(path); err == nil {
			ci.CgroupID = id
			e.info = ci
		}
		byID[id] = e
		return nil
	})
	if err != nil {
		r.scanErrors++
		return
	}
	r.byID = byID
}
