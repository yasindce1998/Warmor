package container

import (
	"strings"
	"testing"
)

func TestDetectRuntime_ReturnsKnownValue(t *testing.T) {
	switch rt := DetectRuntime(); rt {
	case RuntimeContainerd, RuntimeCRIO, RuntimeDocker, RuntimeUnknown:
	default:
		t.Errorf("DetectRuntime returned unexpected value %q", rt)
	}
}

func TestContainerFromCgroup_LabelsInitialized(t *testing.T) {
	info, err := ContainerFromCgroup("/kubepods/burstable/cri-containerd-abc.scope")
	if err != nil {
		t.Fatal(err)
	}
	if info.Labels == nil {
		t.Error("expected Labels map to be initialized")
	}
}

func TestContainerFromCgroup_FirstMatchWins(t *testing.T) {
	info, err := ContainerFromCgroup("/a/docker-first.scope/crio-second.scope")
	if err != nil {
		t.Fatal(err)
	}
	if info.ID != "first" || info.Runtime != RuntimeDocker {
		t.Errorf("got ID=%q Runtime=%q, want first/docker", info.ID, info.Runtime)
	}
}

func TestContainerFromCgroup_NoScopeSuffix(t *testing.T) {
	info, err := ContainerFromCgroup("/sys/fs/cgroup/crio-deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if info.ID != "deadbeef" {
		t.Errorf("ID = %q, want deadbeef", info.ID)
	}
}

func TestContainerFromCgroup_64CharWithDashIgnored(t *testing.T) {
	part := strings.Repeat("a", 63) + "-"
	if _, err := ContainerFromCgroup("/sys/fs/" + part); err == nil {
		t.Error("expected error: 64-char segment containing '-' is not an ID")
	}
}

func TestReadContainerLabels_NotFound(t *testing.T) {
	_, err := ReadContainerLabels("warmor-test-definitely-not-a-container")
	if err == nil {
		t.Fatal("expected error for unknown container")
	}
	if !strings.Contains(err.Error(), "labels not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMatchImagePrefix(t *testing.T) {
	tests := []struct {
		pattern, image string
		want           bool
	}{
		{"nginx:*", "nginx:1.25", true},
		{"nginx:*", "nginx", false},
		{"nginx:*", "nginx-extra:1", false},
		{"nginx:1.25", "nginx:1.25", false}, // no wildcard: exact match handled elsewhere
		{"", "nginx:1", false},
	}
	for _, tt := range tests {
		if got := matchImagePrefix(tt.pattern, tt.image); got != tt.want {
			t.Errorf("matchImagePrefix(%q, %q) = %v, want %v", tt.pattern, tt.image, got, tt.want)
		}
	}
}

func TestPolicyScope_BindOverwrites(t *testing.T) {
	ps := NewPolicyScope()
	ps.BindWithInfo(&ContainerInfo{ID: "c", Namespace: "ns", Image: "img"}, "p1")
	ps.Bind("c", "p2")

	got, ok := ps.Lookup("c")
	if !ok || got != "p2" {
		t.Errorf("Lookup = %q,%v want p2,true", got, ok)
	}
	if all := ps.All(); len(all) != 1 {
		t.Errorf("All() len = %d, want 1", len(all))
	}
	// Plain Bind drops namespace/image metadata.
	if _, ok := ps.LookupByNamespace("ns"); ok {
		t.Error("expected namespace binding to be replaced by plain Bind")
	}
}

func TestPolicyScope_UnbindMissingIsNoOp(t *testing.T) {
	ps := NewPolicyScope()
	ps.Unbind("nope")
	if len(ps.All()) != 0 {
		t.Error("expected empty scope")
	}
}
