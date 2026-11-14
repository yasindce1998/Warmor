package learner

import (
	"context"
	"fmt"
	"maps"
	"net"
	"strconv"
	"sync"

	"github.com/yasindce1998/warmor/internal/streaming"
)

// ContainerProfile captures observed behavior for a single container.
type ContainerProfile struct {
	CgroupID    uint64
	Execs       map[string]int // binary path -> count
	Files       map[string]int // file path -> count
	Networks    map[string]int // "proto:addr:port" -> count
	Binds       map[string]int // "proto:port" -> count
	Listens     map[string]int // "proto:port" -> count
	Mounts      map[string]int // mount type -> count
	Ptrace      map[string]int // target comm -> count
	Unsupported map[string]int
}

func newContainerProfile(cgroupID uint64) *ContainerProfile {
	return &ContainerProfile{
		CgroupID:    cgroupID,
		Execs:       make(map[string]int),
		Files:       make(map[string]int),
		Networks:    make(map[string]int),
		Binds:       make(map[string]int),
		Listens:     make(map[string]int),
		Mounts:      make(map[string]int),
		Ptrace:      make(map[string]int),
		Unsupported: make(map[string]int),
	}
}

// Recorder implements streaming.Sink to record all observed container behavior.
type Recorder struct {
	profiles map[uint64]*ContainerProfile
	mu       sync.RWMutex
	active   bool
	filter   map[uint64]bool // nil = record all
}

// NewRecorder creates a new behavior recorder. If cgroupIDs is non-empty,
// only those containers are recorded; otherwise all are recorded.
func NewRecorder(cgroupIDs []uint64) *Recorder {
	var filter map[uint64]bool
	if len(cgroupIDs) > 0 {
		filter = make(map[uint64]bool, len(cgroupIDs))
		for _, id := range cgroupIDs {
			filter[id] = true
		}
	}
	return &Recorder{
		profiles: make(map[uint64]*ContainerProfile),
		active:   true,
		filter:   filter,
	}
}

func (r *Recorder) Write(_ context.Context, event *streaming.SecurityEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.active {
		return nil
	}

	if event == nil {
		return fmt.Errorf("nil recorded event")
	}
	if event.SchemaVersion < 0 || event.SchemaVersion > streaming.EventSchemaVersion {
		return fmt.Errorf("unsupported event schema version %d", event.SchemaVersion)
	}
	if event.SchemaVersion >= 2 && event.PolicyInput == nil {
		return fmt.Errorf("schema version 2 requires policy_input for learning")
	}
	issues := event.InputIssues
	if event.SchemaVersion >= 2 && event.PolicyInput != nil {
		// Learn evaluator inputs, never a separately editable SIEM summary.
		event = streaming.FromAPIEvent(event.PolicyInput, nil)
		issues = append(append([]streaming.InputIssue(nil), issues...), event.InputIssues...)
	}
	if r.filter != nil && !r.filter[event.CgroupID] {
		return nil
	}
	for _, issue := range issues {
		if issue.State == "redacted" || issue.State == "truncated" {
			return fmt.Errorf("cannot learn from %s input %s", issue.State, issue.Field)
		}
		switch issue.Field {
		case "filename", "process.filename", "file.path", "network.operation", "network.protocol", "network.remote_addr":
			return fmt.Errorf("cannot learn from incomplete target input %s", issue.Field)
		}
	}

	p, ok := r.profiles[event.CgroupID]
	if !ok {
		p = newContainerProfile(event.CgroupID)
		r.profiles[event.CgroupID] = p
	}

	switch event.EventType {
	case "exec":
		key := event.Filename
		if key != "" {
			p.Execs[key]++
		}
	case "file":
		if event.Filename != "" {
			p.Files[event.Filename]++
		}
	case "network":
		key := fmt.Sprintf("%s:%s", event.Protocol, net.JoinHostPort(event.RemoteAddr, strconv.Itoa(int(event.RemotePort))))
		if event.PolicyInput != nil && event.PolicyInput.Network != nil {
			key = event.PolicyInput.Network.Operation + "|" + key
		}
		p.Networks[key]++
	case "bind":
		key := fmt.Sprintf("%s:%d", event.Protocol, event.LocalPort)
		if event.PolicyInput != nil && event.PolicyInput.Network != nil {
			key = event.PolicyInput.Network.Operation + "|" + key
		}
		p.Binds[key]++
	case "listen":
		key := fmt.Sprintf("%s:%d", event.Protocol, event.LocalPort)
		if event.PolicyInput != nil && event.PolicyInput.Network != nil {
			key = event.PolicyInput.Network.Operation + "|" + key
		}
		p.Listens[key]++
	case "mount":
		p.Mounts[event.MountType]++
	case "ptrace":
		p.Ptrace[event.PtraceComm]++
	default:
		p.Unsupported[event.EventType]++
	}

	return nil
}

func (r *Recorder) Flush(_ context.Context) error { return nil }

func (r *Recorder) Close() error {
	r.mu.Lock()
	r.active = false
	r.mu.Unlock()
	return nil
}

func (r *Recorder) Name() string { return "learner-recorder" }

// Profiles returns a snapshot of all recorded container profiles.
func (r *Recorder) Profiles() map[uint64]*ContainerProfile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[uint64]*ContainerProfile, len(r.profiles))
	for id, profile := range r.profiles {
		copy := *profile
		copy.Execs, copy.Files, copy.Networks = maps.Clone(profile.Execs), maps.Clone(profile.Files), maps.Clone(profile.Networks)
		copy.Binds, copy.Listens = maps.Clone(profile.Binds), maps.Clone(profile.Listens)
		copy.Mounts, copy.Ptrace, copy.Unsupported = maps.Clone(profile.Mounts), maps.Clone(profile.Ptrace), maps.Clone(profile.Unsupported)
		out[id] = &copy
	}
	return out
}
