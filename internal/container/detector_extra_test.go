package container

import (
	"os"
	"path/filepath"
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

// withHostRoot points hostRoot at a temporary tree for the duration of the
// test. Tests using it must not run in parallel.
func withHostRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	old := hostRoot
	hostRoot = root
	t.Cleanup(func() { hostRoot = old })
	return root
}

func touch(t *testing.T, path string, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectRuntime_FakeRoot(t *testing.T) {
	root := withHostRoot(t)
	if rt := DetectRuntime(); rt != RuntimeUnknown {
		t.Fatalf("empty root: DetectRuntime = %q, want unknown", rt)
	}
	// Each socket takes precedence over the ones added before it.
	steps := []struct {
		path string
		want Runtime
	}{
		{"var/run/docker.sock", RuntimeDocker},
		{"var/run/crio/crio.sock", RuntimeCRIO},
		{"run/containerd/containerd.sock", RuntimeContainerd},
	}
	for _, s := range steps {
		touch(t, filepath.Join(root, s.path), "")
		if rt := DetectRuntime(); rt != s.want {
			t.Errorf("after creating %s: DetectRuntime = %q, want %q", s.path, rt, s.want)
		}
	}
}

func TestReadContainerLabels_FakeRoot(t *testing.T) {
	root := withHostRoot(t)
	taskDir := filepath.Join(root, "run/containerd/io.containerd.runtime.v2.task")

	// k8s.io config without annotations falls through to the default namespace.
	touch(t, filepath.Join(taskDir, "k8s.io", "c1", "config.json"), `{"ociVersion":"1.0"}`)
	touch(t, filepath.Join(taskDir, "default", "c1", "config.json"), `{"annotations":{"io.warmor/policy":"p-default"}}`)
	labels, err := ReadContainerLabels("c1")
	if err != nil {
		t.Fatalf("ReadContainerLabels: %v", err)
	}
	if labels["io.warmor/policy"] != "p-default" {
		t.Errorf("labels = %v", labels)
	}

	// k8s.io wins when both have annotations.
	touch(t, filepath.Join(taskDir, "k8s.io", "c2", "config.json"), `{"annotations":{"k":"k8s"}}`)
	touch(t, filepath.Join(taskDir, "default", "c2", "config.json"), `{"annotations":{"k":"default"}}`)
	if labels, err := ReadContainerLabels("c2"); err != nil || labels["k"] != "k8s" {
		t.Errorf("ReadContainerLabels(c2) = %v, %v; want k=k8s", labels, err)
	}

	// Malformed JSON is treated as not found.
	touch(t, filepath.Join(taskDir, "k8s.io", "c3", "config.json"), `{bad`)
	if _, err := ReadContainerLabels("c3"); err == nil {
		t.Error("expected error for malformed config")
	}
}

func TestContainerFromCgroup_BareIDUsesDetectedRuntime(t *testing.T) {
	root := withHostRoot(t)
	touch(t, filepath.Join(root, "var/run/crio/crio.sock"), "")
	id := strings.Repeat("a", 64)
	info, err := ContainerFromCgroup("/kubepods/besteffort/" + id)
	if err != nil {
		t.Fatal(err)
	}
	if info.ID != id || info.Runtime != RuntimeCRIO {
		t.Errorf("got %+v, want id=%s runtime=cri-o", info, id)
	}
}
