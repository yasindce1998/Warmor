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
	root       string
	minRescan  time.Duration
	now        func() time.Time
	mu         sync.Mutex
	byID       map[uint64]*ContainerInfo // nil value: known cgroup, not a container
	lastScan   time.Time
	scanErrors int
}

// NewCgroupResolver resolves ids under root (normally /sys/fs/cgroup).
func NewCgroupResolver(root string) *CgroupResolver {
	return &CgroupResolver{
		root:      root,
		minRescan: 2 * time.Second,
		now:       time.Now,
		byID:      make(map[uint64]*ContainerInfo),
	}
}

// Lookup returns the container a cgroup belongs to. ok is false for host
// cgroups and for ids not (yet) present in the hierarchy.
func (r *CgroupResolver) Lookup(cgroupID uint64) (info *ContainerInfo, ok bool) {
	if cgroupID == 0 {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if info, known := r.byID[cgroupID]; known {
		return info, info != nil
	}
	if now := r.now(); r.lastScan.IsZero() || now.Sub(r.lastScan) >= r.minRescan {
		r.lastScan = now
		r.rescanLocked()
		if info, known := r.byID[cgroupID]; known {
			return info, info != nil
		}
	}
	return nil, false
}

// IsContainer reports whether cgroupID belongs to a container.
func (r *CgroupResolver) IsContainer(cgroupID uint64) bool {
	_, ok := r.Lookup(cgroupID)
	return ok
}

// rescanLocked rebuilds the id map from the hierarchy, dropping cgroups that
// no longer exist.
func (r *CgroupResolver) rescanLocked() {
	byID := make(map[uint64]*ContainerInfo, len(r.byID))
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
		var info *ContainerInfo
		if ci, err := ContainerFromCgroup(path); err == nil {
			ci.CgroupID = id
			info = ci
		}
		byID[id] = info
		return nil
	})
	if err != nil {
		r.scanErrors++
		return
	}
	r.byID = byID
}
