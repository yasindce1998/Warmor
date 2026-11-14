package workload

import (
	"fmt"
	"maps"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// Reason distinguishes unknown identity from verified Pods without matches.
// Unknown identities must never be evaluated as empty-label Pods.
type Reason string

const (
	Verified            Reason = "verified"
	UnknownCgroup       Reason = "unknown_cgroup"
	LifetimeMismatch    Reason = "lifetime_mismatch"
	IncompleteIdentity  Reason = "incomplete_identity"
	ConflictingIdentity Reason = "conflicting_identity"
)

// Binding is evidence supplied by a trusted host-cgroup producer. The producer
// must verify the exact runtime ID and host cgroup identity/lifetime; neither
// CRI lists nor directory-name parsing alone proves this. Lifetime is a nonempty
// opaque boot/incarnation token, not merely a cgroup ID.
type Binding struct {
	CgroupID    uint64
	Lifetime    string
	ContainerID string // full CRI ID, without runtime:// prefix
}

// Inputs describe one node and one authorized runtime endpoint. Runtime is the
// Kubernetes containerID scheme ("containerd", "cri-o"), not the containerd
// namespace. The caller enforces source freshness.
type Inputs struct {
	NodeName  string
	Runtime   string
	Pods      []corev1.Pod
	Inventory Inventory
	Bindings  []Binding
}

// Identity is an immutable corroborated join. Its zero value is unverified.
// Pod labels come only from the Kubernetes API, never runtime labels.
type Identity struct {
	runtime, containerID, sandboxID, containerName string
	podUID                                         types.UID
	namespace, podName, nodeName                   string
	podLabels                                      map[string]string
	imageRef                                       string
}

func (i Identity) Runtime() string           { return i.runtime }
func (i Identity) ContainerID() string       { return i.containerID }
func (i Identity) SandboxID() string         { return i.sandboxID }
func (i Identity) ContainerName() string     { return i.containerName }
func (i Identity) PodUID() types.UID         { return i.podUID }
func (i Identity) Namespace() string         { return i.namespace }
func (i Identity) PodName() string           { return i.podName }
func (i Identity) NodeName() string          { return i.nodeName }
func (i Identity) Labels() map[string]string { return maps.Clone(i.podLabels) }

// ImageRef is runtime-reported. CRI does not guarantee OCI digest formatting;
// this field must not be mistaken for an attested image/manifest digest.
func (i Identity) ImageRef() string { return i.imageRef }

type entry struct {
	lifetime string
	identity Identity
	reason   Reason
}

// Snapshot is immutable and safe for concurrent readers. Publish atomically
// with a coordinator-owned identity epoch. Late events still require verified
// event-time lifetime evidence from the binding producer.
type Snapshot struct {
	byCgroup map[uint64]entry
}

// NewSnapshot joins exact runtime IDs with sandbox metadata and the current
// Pod's running container status, name, attempt, UID, namespace, and node.
// Individual incomplete/conflicting joins become unknown, never old identities.
// Only invalid node/runtime configuration fails the entire construction.
// Inputs must not be mutated concurrently during construction.
func NewSnapshot(in Inputs) (*Snapshot, error) {
	if in.NodeName == "" || !validID(in.Runtime) {
		return nil, fmt.Errorf("workload snapshot requires a node name and runtime scheme")
	}
	containers := make(map[string][]*runtimeapi.Container)
	for _, c := range in.Inventory.Containers {
		if c != nil {
			containers[c.Id] = append(containers[c.Id], c)
		}
	}
	sandboxes := make(map[string][]*runtimeapi.PodSandbox)
	for _, s := range in.Inventory.Sandboxes {
		if s != nil {
			sandboxes[s.Id] = append(sandboxes[s.Id], s)
		}
	}
	pods := make(map[types.UID][]*corev1.Pod)
	podNames := make(map[types.NamespacedName]int)
	statuses := make(map[string][]podContainer)
	for n := range in.Pods {
		p := &in.Pods[n]
		pods[p.UID] = append(pods[p.UID], p)
		podNames[types.NamespacedName{Namespace: p.Namespace, Name: p.Name}]++
		indexStatuses(statuses, p, in.Runtime, p.Status.ContainerStatuses, regular)
		indexStatuses(statuses, p, in.Runtime, p.Status.InitContainerStatuses, initContainer)
		indexStatuses(statuses, p, in.Runtime, p.Status.EphemeralContainerStatuses, ephemeral)
	}
	snapshot := &Snapshot{byCgroup: make(map[uint64]entry, len(in.Bindings))}
	for _, b := range in.Bindings {
		if _, exists := snapshot.byCgroup[b.CgroupID]; exists {
			// Even identical duplicates are ambiguous. A third cannot repair it.
			snapshot.byCgroup[b.CgroupID] = entry{reason: ConflictingIdentity}
			continue
		}
		e := entry{lifetime: b.Lifetime, reason: IncompleteIdentity}
		if b.CgroupID != 0 && b.Lifetime != "" && validID(b.ContainerID) {
			e.identity, e.reason = join(in.NodeName, in.Runtime, b.ContainerID, containers, sandboxes, pods, podNames, statuses)
		}
		snapshot.byCgroup[b.CgroupID] = e
	}
	return snapshot, nil
}

// Lookup requires the exact cgroup/lifetime match. Failure does not mean known
// host. A nil snapshot is safely unknown. Never substitute the current token
// for an unverified delayed event's lifetime.
func (s *Snapshot) Lookup(cgroupID uint64, lifetime string) (Identity, Reason) {
	if s == nil || cgroupID == 0 {
		return Identity{}, UnknownCgroup
	}
	e, ok := s.byCgroup[cgroupID]
	if !ok {
		return Identity{}, UnknownCgroup
	}
	if e.reason != Verified {
		return Identity{}, e.reason
	}
	if lifetime == "" || lifetime != e.lifetime {
		return Identity{}, LifetimeMismatch
	}
	return e.identity, Verified
}

type containerKind uint8

const (
	regular containerKind = iota
	initContainer
	ephemeral
)

type podContainer struct {
	pod    *corev1.Pod
	status corev1.ContainerStatus
	kind   containerKind
}

func indexStatuses(index map[string][]podContainer, pod *corev1.Pod, runtime string, statuses []corev1.ContainerStatus, kind containerKind) {
	for _, status := range statuses {
		if status.State.Running == nil {
			continue
		}
		id, ok := strings.CutPrefix(status.ContainerID, runtime+"://")
		if ok && validID(id) {
			index[id] = append(index[id], podContainer{pod: pod, status: status, kind: kind})
		}
	}
}

func join(node, runtime, id string, containers map[string][]*runtimeapi.Container, sandboxes map[string][]*runtimeapi.PodSandbox, pods map[types.UID][]*corev1.Pod, podNames map[types.NamespacedName]int, statuses map[string][]podContainer) (Identity, Reason) {
	cs, ps := containers[id], statuses[id]
	if len(cs) > 1 || len(ps) > 1 {
		return Identity{}, ConflictingIdentity
	}
	if len(cs) != 1 || len(ps) != 1 {
		return Identity{}, IncompleteIdentity
	}
	c, pc := cs[0], ps[0]
	p := pc.pod
	ss := sandboxes[c.PodSandboxId]
	if len(ss) > 1 || len(pods[p.UID]) > 1 || podNames[types.NamespacedName{Namespace: p.Namespace, Name: p.Name}] > 1 {
		return Identity{}, ConflictingIdentity
	}
	if len(ss) != 1 || !validID(c.PodSandboxId) || c.State != runtimeapi.ContainerState_CONTAINER_RUNNING || c.Metadata == nil {
		return Identity{}, IncompleteIdentity
	}
	s := ss[0]
	if s.State != runtimeapi.PodSandboxState_SANDBOX_READY || s.Metadata == nil ||
		p.UID == "" || p.Name == "" || p.Namespace == "" || p.Spec.NodeName != node ||
		s.Metadata.Uid != string(p.UID) || s.Metadata.Name != p.Name || s.Metadata.Namespace != p.Namespace ||
		c.Metadata.Name == "" || c.Metadata.Name != pc.status.Name || !declaredContainer(p, pc.kind, pc.status.Name) ||
		pc.status.RestartCount < 0 || c.Metadata.Attempt != uint32(pc.status.RestartCount) ||
		!consistentLabels(s.Labels, p, "") || !consistentLabels(c.Labels, p, pc.status.Name) {
		return Identity{}, IncompleteIdentity
	}
	return Identity{
		runtime: runtime, containerID: c.Id, sandboxID: s.Id, containerName: c.Metadata.Name,
		podUID: p.UID, namespace: p.Namespace, podName: p.Name, nodeName: p.Spec.NodeName,
		podLabels: maps.Clone(p.Labels), imageRef: c.ImageRef,
	}, Verified
}

func declaredContainer(p *corev1.Pod, kind containerKind, name string) bool {
	switch kind {
	case regular:
		for _, c := range p.Spec.Containers {
			if c.Name == name {
				return true
			}
		}
	case initContainer:
		for _, c := range p.Spec.InitContainers {
			if c.Name == name {
				return true
			}
		}
	case ephemeral:
		for _, c := range p.Spec.EphemeralContainers {
			if c.Name == name {
				return true
			}
		}
	}
	return false
}

// Runtime labels corroborate identity if present, but are not selector data.
func consistentLabels(labels map[string]string, p *corev1.Pod, containerName string) bool {
	want := map[string]string{
		"io.kubernetes.pod.uid":       string(p.UID),
		"io.kubernetes.pod.name":      p.Name,
		"io.kubernetes.pod.namespace": p.Namespace,
	}
	if containerName != "" {
		want["io.kubernetes.container.name"] = containerName
	}
	for key, expected := range want {
		if got, exists := labels[key]; exists && got != expected {
			return false
		}
	}
	return true
}

// IDs are full opaque strings, never prefixes. This adapter supports nonempty
// URL-safe opaque IDs; unsupported forms remain unresolved.
func validID(id string) bool {
	if id == "" || len(id) > 256 {
		return false
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}
