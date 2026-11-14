package workload

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const fullID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const lifetime = "boot-a:cgroup-incarnation-7"

func fixture() Inputs {
	return Inputs{
		NodeName: "node-a", Runtime: "containerd",
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{UID: "pod-uid", Name: "app", Namespace: "team-a", Labels: map[string]string{"app": "api", "tier": "frontend"}, ResourceVersion: "opaque-version"},
			Spec:       corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "main"}}},
			Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
				Name: "main", ContainerID: "containerd://" + fullID, RestartCount: 2,
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}}},
		}},
		Inventory: Inventory{
			Containers: []*runtimeapi.Container{{
				Id: fullID, PodSandboxId: "sandbox-id", State: runtimeapi.ContainerState_CONTAINER_RUNNING,
				Metadata: &runtimeapi.ContainerMetadata{Name: "main", Attempt: 2},
				ImageRef: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Labels:   map[string]string{"io.kubernetes.pod.uid": "pod-uid", "app": "untrusted-runtime-label"},
			}},
			Sandboxes: []*runtimeapi.PodSandbox{{
				Id: "sandbox-id", State: runtimeapi.PodSandboxState_SANDBOX_READY,
				Metadata: &runtimeapi.PodSandboxMetadata{Uid: "pod-uid", Name: "app", Namespace: "team-a"},
			}},
		},
		Bindings: []Binding{{CgroupID: 42, Lifetime: lifetime, ContainerID: fullID}},
	}
}

func verifiedIdentity(t *testing.T, in Inputs) Identity {
	t.Helper()
	snapshot, err := NewSnapshot(in)
	if err != nil {
		t.Fatal(err)
	}
	identity, reason := snapshot.Lookup(42, lifetime)
	if reason != Verified {
		t.Fatalf("identity reason = %s", reason)
	}
	return identity
}

func TestSnapshotExactJoin(t *testing.T) {
	in := fixture()
	id := verifiedIdentity(t, in)
	if id.Runtime() != "containerd" || id.ContainerID() != fullID || id.SandboxID() != "sandbox-id" || id.ContainerName() != "main" ||
		id.PodUID() != "pod-uid" || id.Namespace() != "team-a" || id.PodName() != "app" || id.NodeName() != "node-a" || id.ImageRef() != in.Inventory.Containers[0].ImageRef {
		t.Fatalf("unexpected joined identity: %+v", id)
	}
	if !reflect.DeepEqual(id.Labels(), in.Pods[0].Labels) {
		t.Fatalf("labels = %v", id.Labels())
	}
}

func TestSnapshotRejectsIncompleteAndConflictingJoins(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Inputs)
		reason Reason
	}{
		{"no binding", func(in *Inputs) { in.Bindings = nil }, UnknownCgroup},
		{"no container", func(in *Inputs) { in.Inventory.Containers = nil }, IncompleteIdentity},
		{"nil container", func(in *Inputs) { in.Inventory.Containers = []*runtimeapi.Container{nil} }, IncompleteIdentity},
		{"no sandbox", func(in *Inputs) { in.Inventory.Sandboxes = nil }, IncompleteIdentity},
		{"nil sandbox", func(in *Inputs) { in.Inventory.Sandboxes = []*runtimeapi.PodSandbox{nil} }, IncompleteIdentity},
		{"no pod", func(in *Inputs) { in.Pods = nil }, IncompleteIdentity},
		{"missing binding lifetime", func(in *Inputs) { in.Bindings[0].Lifetime = "" }, IncompleteIdentity},
		{"shortened ID", func(in *Inputs) { in.Bindings[0].ContainerID = fullID[:12] }, IncompleteIdentity},
		{"prefixed ID", func(in *Inputs) { in.Bindings[0].ContainerID = "containerd://" + fullID }, IncompleteIdentity},
		{"different runtime", func(in *Inputs) { in.Runtime = "cri-o" }, IncompleteIdentity},
		{"malformed pod ID", func(in *Inputs) { in.Pods[0].Status.ContainerStatuses[0].ContainerID += "/extra" }, IncompleteIdentity},
		{"wrong node", func(in *Inputs) { in.Pods[0].Spec.NodeName = "node-b" }, IncompleteIdentity},
		{"unassigned pod", func(in *Inputs) { in.Pods[0].Spec.NodeName = "" }, IncompleteIdentity},
		{"wrong namespace", func(in *Inputs) { in.Pods[0].Namespace = "team-b" }, IncompleteIdentity},
		{"missing namespace", func(in *Inputs) { in.Pods[0].Namespace = "" }, IncompleteIdentity},
		{"recreated UID", func(in *Inputs) { in.Pods[0].UID = "replacement-uid" }, IncompleteIdentity},
		{"missing UID", func(in *Inputs) { in.Pods[0].UID = "" }, IncompleteIdentity},
		{"wrong sandbox name", func(in *Inputs) { in.Inventory.Sandboxes[0].Metadata.Name = "another" }, IncompleteIdentity},
		{"nil sandbox metadata", func(in *Inputs) { in.Inventory.Sandboxes[0].Metadata = nil }, IncompleteIdentity},
		{"sandbox not ready", func(in *Inputs) { in.Inventory.Sandboxes[0].State = runtimeapi.PodSandboxState_SANDBOX_NOTREADY }, IncompleteIdentity},
		{"container exited", func(in *Inputs) { in.Inventory.Containers[0].State = runtimeapi.ContainerState_CONTAINER_EXITED }, IncompleteIdentity},
		{"nil container metadata", func(in *Inputs) { in.Inventory.Containers[0].Metadata = nil }, IncompleteIdentity},
		{"wrong container name", func(in *Inputs) { in.Inventory.Containers[0].Metadata.Name = "sidecar" }, IncompleteIdentity},
		{"undeclared container", func(in *Inputs) { in.Pods[0].Spec.Containers = nil }, IncompleteIdentity},
		{"old attempt", func(in *Inputs) { in.Inventory.Containers[0].Metadata.Attempt = 1 }, IncompleteIdentity},
		{"negative restart count", func(in *Inputs) { in.Pods[0].Status.ContainerStatuses[0].RestartCount = -1 }, IncompleteIdentity},
		{"pod status waiting", func(in *Inputs) {
			in.Pods[0].Status.ContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{}}
		}, IncompleteIdentity},
		{"unbound sandbox", func(in *Inputs) { in.Inventory.Containers[0].PodSandboxId = "other" }, IncompleteIdentity},
		{"conflicting runtime UID", func(in *Inputs) { in.Inventory.Containers[0].Labels["io.kubernetes.pod.uid"] = "other" }, IncompleteIdentity},
		{"conflicting runtime namespace", func(in *Inputs) { in.Inventory.Containers[0].Labels["io.kubernetes.pod.namespace"] = "k8s.io" }, IncompleteIdentity},
		{"conflicting runtime container", func(in *Inputs) { in.Inventory.Containers[0].Labels["io.kubernetes.container.name"] = "other" }, IncompleteIdentity},
		{"conflicting sandbox label", func(in *Inputs) {
			in.Inventory.Sandboxes[0].Labels = map[string]string{"io.kubernetes.pod.name": "other"}
		}, IncompleteIdentity},
		{"duplicate containers", func(in *Inputs) {
			in.Inventory.Containers = append(in.Inventory.Containers, in.Inventory.Containers[0])
		}, ConflictingIdentity},
		{"duplicate sandboxes", func(in *Inputs) { in.Inventory.Sandboxes = append(in.Inventory.Sandboxes, in.Inventory.Sandboxes[0]) }, ConflictingIdentity},
		{"duplicate pods", func(in *Inputs) { in.Pods = append(in.Pods, *in.Pods[0].DeepCopy()) }, ConflictingIdentity},
		{"old and recreated pod both present", func(in *Inputs) {
			replacement := in.Pods[0].DeepCopy()
			replacement.UID = "replacement-uid"
			replacement.Status.ContainerStatuses = nil
			in.Pods = append(in.Pods, *replacement)
		}, ConflictingIdentity},
		{"duplicate statuses", func(in *Inputs) {
			in.Pods[0].Status.ContainerStatuses = append(in.Pods[0].Status.ContainerStatuses, in.Pods[0].Status.ContainerStatuses[0])
		}, ConflictingIdentity},
		{"cross kind duplicate statuses", func(in *Inputs) { in.Pods[0].Status.InitContainerStatuses = in.Pods[0].Status.ContainerStatuses }, ConflictingIdentity},
		{"duplicate cgroup claims", func(in *Inputs) { in.Bindings = append(in.Bindings, in.Bindings[0]) }, ConflictingIdentity},
		{"third cgroup claim cannot repair conflict", func(in *Inputs) { in.Bindings = append(in.Bindings, in.Bindings[0], in.Bindings[0]) }, ConflictingIdentity},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			in := fixture()
			test.mutate(&in)
			snapshot, err := NewSnapshot(in)
			if err != nil {
				t.Fatal(err)
			}
			identity, reason := snapshot.Lookup(42, lifetime)
			if reason != test.reason || identity.PodUID() != "" {
				t.Fatalf("lookup = %+v, %s; want unknown %s", identity, reason, test.reason)
			}
		})
	}
}

func TestSnapshotLifetimeAndZeroValues(t *testing.T) {
	snapshot, err := NewSnapshot(fixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		id     uint64
		token  string
		reason Reason
	}{
		{42, "old-boot:old-incarnation", LifetimeMismatch}, {42, "", LifetimeMismatch},
		{0, lifetime, UnknownCgroup}, {99, lifetime, UnknownCgroup},
	} {
		identity, reason := snapshot.Lookup(test.id, test.token)
		if reason != test.reason || identity.PodUID() != "" {
			t.Fatalf("lookup = %+v, %s", identity, reason)
		}
	}
	var nilSnapshot *Snapshot
	if _, reason := nilSnapshot.Lookup(42, lifetime); reason != UnknownCgroup {
		t.Fatal(reason)
	}
	for _, test := range []struct{ node, runtime string }{{"", "containerd"}, {"node-a", ""}, {"node-a", "containerd://"}} {
		in := fixture()
		in.NodeName, in.Runtime = test.node, test.runtime
		if _, err := NewSnapshot(in); err == nil {
			t.Fatalf("accepted config %+v", test)
		}
	}
}

func TestSnapshotContainerKinds(t *testing.T) {
	for _, kind := range []containerKind{regular, initContainer, ephemeral} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			in := fixture()
			p := &in.Pods[0]
			statuses := p.Status.ContainerStatuses
			p.Spec.Containers, p.Status.ContainerStatuses = nil, nil
			switch kind {
			case regular:
				p.Spec.Containers = []corev1.Container{{Name: "main"}}
				p.Status.ContainerStatuses = statuses
			case initContainer:
				p.Spec.InitContainers = []corev1.Container{{Name: "main"}}
				p.Status.InitContainerStatuses = statuses
			case ephemeral:
				p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "main"}}}
				p.Status.EphemeralContainerStatuses = statuses
			}
			verifiedIdentity(t, in)
			// Incorrect names must not fall back to a different container kind.
			in.Inventory.Containers[0].Metadata.Name = "missing"
			if s, err := NewSnapshot(in); err != nil {
				t.Fatal(err)
			} else if _, reason := s.Lookup(42, lifetime); reason == Verified {
				t.Fatal("incorrect name verified")
			}
		})
	}
}

func TestSnapshotDoesNotAliasInputsOrLabels(t *testing.T) {
	in := fixture()
	snapshot, err := NewSnapshot(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Pods[0].Labels["app"] = "changed"
	in.Pods[0].Name = "changed"
	in.Inventory.Containers[0].Metadata.Name = "changed"
	in.Inventory.Sandboxes[0].Metadata.Uid = "changed"
	in.Bindings[0].Lifetime = "changed"
	id, reason := snapshot.Lookup(42, lifetime)
	if reason != Verified || id.PodName() != "app" || id.ContainerName() != "main" || id.Labels()["app"] != "api" {
		t.Fatalf("mutated snapshot: %+v %s", id, reason)
	}
	id.Labels()["app"] = "changed"
	if id.Labels()["app"] != "api" {
		t.Fatal("returned labels alias snapshot")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				id, reason := snapshot.Lookup(42, lifetime)
				if reason != Verified {
					t.Error(reason)
				}
				id.Labels()["app"] = "private-copy"
			}
		})
	}
	wg.Wait()
}

func TestSnapshotReplacementDropsOldBindings(t *testing.T) {
	in := fixture()
	old, err := NewSnapshot(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Bindings = nil
	next, err := NewSnapshot(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, reason := next.Lookup(42, lifetime); reason != UnknownCgroup {
		t.Fatal(reason)
	}
	if _, reason := old.Lookup(42, lifetime); reason != Verified {
		t.Fatal("old snapshot changed")
	}
	in = fixture()
	in.Pods[0].Labels["app"] = "new-label"
	in.Bindings[0].Lifetime = "new-incarnation"
	next, err = NewSnapshot(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, reason := next.Lookup(42, lifetime); reason != LifetimeMismatch {
		t.Fatal(reason)
	}
	id, reason := next.Lookup(42, "new-incarnation")
	if reason != Verified || id.Labels()["app"] != "new-label" {
		t.Fatalf("new snapshot = %+v %s", id, reason)
	}
}

func TestCRIOOptionalLabelsAndChildCgroups(t *testing.T) {
	in := fixture()
	in.Runtime = "cri-o"
	in.Pods[0].Status.ContainerStatuses[0].ContainerID = "cri-o://" + fullID
	in.Inventory.Containers[0].Labels = nil
	in.Bindings = append(in.Bindings, Binding{CgroupID: 43, Lifetime: "child-incarnation", ContainerID: fullID})
	snapshot, err := NewSnapshot(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range in.Bindings {
		id, reason := snapshot.Lookup(b.CgroupID, b.Lifetime)
		if reason != Verified || id.Runtime() != "cri-o" {
			t.Fatalf("lookup = %+v %s", id, reason)
		}
	}
}

func TestOpaqueIDValidation(t *testing.T) {
	for _, id := range []string{"", "a/b", "a:b", "a b", "ä", strings.Repeat("a", 257)} {
		if validID(id) {
			t.Fatalf("accepted %q", id)
		}
	}
	if !validID("opaque.ID_123-abc") {
		t.Fatal("rejected supported opaque ID")
	}
}
