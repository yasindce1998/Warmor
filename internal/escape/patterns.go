package escape

import (
	"path"
	"slices"
	"strings"
	"time"
)

// TechniqueID maps to MITRE ATT&CK technique identifiers.
type TechniqueID string

const (
	TechNsenter       TechniqueID = "T1611.001" // nsenter from container
	TechHostMount     TechniqueID = "T1611.002" // mount host filesystem
	TechPtraceCross   TechniqueID = "T1055.008" // ptrace across cgroup
	TechProcNS        TechniqueID = "T1611.003" // /proc/*/ns/* access
	TechUnshareSetns  TechniqueID = "T1611.004" // unshare + setns sequence
	TechDockerSocket  TechniqueID = "T1610"     // docker socket access
	TechSensitiveExec TechniqueID = "T1059.004" // exec of escape tools
)

// Severity levels for escape attempts.
type Severity int

const (
	SeverityHigh     Severity = 3
	SeverityCritical Severity = 4
)

// Pattern describes a container escape technique as one or more event conditions
// that must be matched within a time window.
type Pattern struct {
	ID          TechniqueID
	Name        string
	Description string
	Severity    Severity
	Window      time.Duration
	Steps       []StepMatcher
}

// StepMatcher is a single event condition within a multi-step escape pattern.
type StepMatcher struct {
	EventType string
	Match     func(ev *EventView) bool
}

// EventView provides a read-only view of event fields for pattern matching.
//
// EventType is the streaming event type: exec, file, network, connect_unix,
// bind, listen, ptrace or mount. For exec, Filename is the binary being
// executed and Comm is still the *calling* process's name (the LSM hook runs
// before the exec completes), so patterns match on the binary, never Comm.
type EventView struct {
	EventType          string
	Comm               string
	Filename           string
	CgroupID           uint64
	PID                uint32
	PPID               uint32
	UID                uint32
	MountType          string
	MountSource        string
	PtraceComm         string
	PtraceTargetCgroup uint64
	RemoteAddr         string
	LocalPort          uint16
}

// RuntimeSockets are the container runtime API sockets. Connecting to one
// from inside a container hands over control of the host. The daemon also
// loads them into the kernel's unix_watch map so these connects are reported.
var RuntimeSockets = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/var/run/containerd/containerd.sock",
	"/run/containerd/containerd.sock",
	"/var/run/crio/crio.sock",
	"/run/crio/crio.sock",
	"/run/podman/podman.sock",
	"/var/run/podman/podman.sock",
}

// DefaultPatterns returns the built-in escape patterns.
func DefaultPatterns() []*Pattern {
	return []*Pattern{
		nsenterPattern(),
		hostMountPattern(),
		ptraceCrossPattern(),
		procNSPattern(),
		unshareSetnsPattern(),
		dockerSocketPattern(),
		sensitiveExecPattern(),
	}
}

func execBase(ev *EventView) string {
	return path.Base(ev.Filename)
}

// isRuntimeInit reports whether the event comes from the container
// runtime's own setup, which legitimately mounts filesystems inside the new
// container's cgroup before handing over to the workload.
func isRuntimeInit(comm string) bool {
	return strings.HasPrefix(comm, "runc") || comm == "crun" || comm == "youki" ||
		comm == "conmon" || strings.HasPrefix(comm, "containerd-shim")
}

func nsenterPattern() *Pattern {
	return &Pattern{
		ID:          TechNsenter,
		Name:        "nsenter from container",
		Description: "Container process executes nsenter to enter another (host) namespace",
		Severity:    SeverityCritical,
		Steps: []StepMatcher{{
			EventType: "exec",
			Match:     func(ev *EventView) bool { return execBase(ev) == "nsenter" },
		}},
	}
}

// blockDevicePrefixes are disk device nodes. Mounting one from a container
// gives raw access to a host filesystem.
var blockDevicePrefixes = []string{"/dev/sd", "/dev/vd", "/dev/xvd", "/dev/hd", "/dev/nvme", "/dev/mmcblk", "/dev/mapper/", "/dev/dm-"}

func hostMountPattern() *Pattern {
	return &Pattern{
		ID:          TechHostMount,
		Name:        "host filesystem mount",
		Description: "Container mounts a host block device or a cgroup v1 hierarchy (release_agent escape)",
		Severity:    SeverityCritical,
		Steps: []StepMatcher{{
			EventType: "mount",
			Match: func(ev *EventView) bool {
				if isRuntimeInit(ev.Comm) {
					return false
				}
				if ev.MountType == "cgroup" {
					return true
				}
				for _, p := range blockDevicePrefixes {
					if strings.HasPrefix(ev.MountSource, p) {
						return true
					}
				}
				return false
			},
		}},
	}
}

func ptraceCrossPattern() *Pattern {
	return &Pattern{
		ID:          TechPtraceCross,
		Name:        "cross-cgroup ptrace",
		Description: "Container process attempts to ptrace a process in a different cgroup",
		Severity:    SeverityCritical,
		Steps: []StepMatcher{{
			EventType: "ptrace",
			Match: func(ev *EventView) bool {
				return ev.PtraceTargetCgroup != 0 && ev.PtraceTargetCgroup != ev.CgroupID
			},
		}},
	}
}

func procNSPattern() *Pattern {
	return &Pattern{
		ID:          TechProcNS,
		Name:        "/proc namespace access",
		Description: "Container opens /proc/<pid>/ns/*, the handles setns needs to join another namespace",
		Severity:    SeverityHigh,
		Steps: []StepMatcher{{
			EventType: "file",
			Match:     func(ev *EventView) bool { return containsNS(ev.Filename) },
		}},
	}
}

func unshareSetnsPattern() *Pattern {
	return &Pattern{
		ID:          TechUnshareSetns,
		Name:        "unshare + setns sequence",
		Description: "Container executes unshare followed by namespace handle access within 5s",
		Severity:    SeverityCritical,
		Window:      5 * time.Second,
		Steps: []StepMatcher{
			{
				EventType: "exec",
				Match:     func(ev *EventView) bool { return execBase(ev) == "unshare" },
			},
			{
				EventType: "file",
				Match:     func(ev *EventView) bool { return containsNS(ev.Filename) },
			},
		},
	}
}

func dockerSocketPattern() *Pattern {
	return &Pattern{
		ID:          TechDockerSocket,
		Name:        "container runtime socket access",
		Description: "Container connects to the Docker/containerd/CRI-O/podman API socket",
		Severity:    SeverityHigh,
		Steps: []StepMatcher{{
			EventType: "connect_unix",
			Match:     func(ev *EventView) bool { return slices.Contains(RuntimeSockets, ev.Filename) },
		}},
	}
}

// escapeTools are binaries with no business running inside an application
// container and a long history in breakout write-ups.
var escapeTools = []string{
	"runc", "ctr", "crictl", "kubectl", "docker", "nerdctl",
	"chroot", "capsh", "setcap", "debugfs",
}

func sensitiveExecPattern() *Pattern {
	return &Pattern{
		ID:          TechSensitiveExec,
		Name:        "sensitive binary execution",
		Description: "Container executes a container-runtime or capability tool",
		Severity:    SeverityHigh,
		Steps: []StepMatcher{{
			EventType: "exec",
			Match:     func(ev *EventView) bool { return slices.Contains(escapeTools, execBase(ev)) },
		}},
	}
}

// containsNS reports whether path is a namespace handle under /proc:
// /proc/<pid>/ns/<type>, /proc/self/ns/<type> or /proc/thread-self/ns/<type>.
func containsNS(path string) bool {
	rest, ok := strings.CutPrefix(path, "/proc/")
	if !ok {
		return false
	}
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return false
	}
	who := rest[:slash]
	if who != "self" && who != "thread-self" {
		for _, c := range who {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	typ, ok := strings.CutPrefix(rest[slash:], "/ns/")
	return ok && typ != "" && !strings.Contains(typ, "/")
}
