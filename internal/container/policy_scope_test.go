package container

import (
	"sync"
	"testing"
)

func TestPolicyScope_BindAndLookup(t *testing.T) {
	ps := NewPolicyScope()

	ps.Bind("container-1", "policy-a")

	got, ok := ps.Lookup("container-1")
	if !ok {
		t.Fatal("expected Lookup to find container-1")
	}
	if got != "policy-a" {
		t.Errorf("Lookup = %q, want %q", got, "policy-a")
	}
}

func TestPolicyScope_LookupMiss(t *testing.T) {
	ps := NewPolicyScope()

	_, ok := ps.Lookup("nonexistent")
	if ok {
		t.Error("expected Lookup to return false for nonexistent container")
	}
}

func TestPolicyScope_Unbind(t *testing.T) {
	ps := NewPolicyScope()

	ps.Bind("container-1", "policy-a")
	ps.Unbind("container-1")

	_, ok := ps.Lookup("container-1")
	if ok {
		t.Error("expected Lookup to return false after Unbind")
	}
}

func TestPolicyScope_BindWithInfo(t *testing.T) {
	ps := NewPolicyScope()

	info := &ContainerInfo{
		ID:        "ctr-abc",
		Image:     "docker.io/library/nginx:1.25",
		Namespace: "production",
	}
	ps.BindWithInfo(info, "nginx-policy")

	got, ok := ps.Lookup("ctr-abc")
	if !ok {
		t.Fatal("expected Lookup to find ctr-abc")
	}
	if got != "nginx-policy" {
		t.Errorf("Lookup = %q, want %q", got, "nginx-policy")
	}
}

func TestPolicyScope_LookupByImage_ExactMatch(t *testing.T) {
	ps := NewPolicyScope()

	ps.BindWithInfo(&ContainerInfo{
		ID:    "ctr-1",
		Image: "docker.io/library/nginx:1.25",
	}, "nginx-policy")

	got, ok := ps.LookupByImage("docker.io/library/nginx:1.25")
	if !ok {
		t.Fatal("expected LookupByImage to find exact match")
	}
	if got != "nginx-policy" {
		t.Errorf("LookupByImage = %q, want %q", got, "nginx-policy")
	}
}

func TestPolicyScope_LookupByImage_WildcardMatch(t *testing.T) {
	ps := NewPolicyScope()

	ps.BindWithInfo(&ContainerInfo{
		ID:    "ctr-1",
		Image: "docker.io/library/nginx:*",
	}, "nginx-any-tag")

	got, ok := ps.LookupByImage("docker.io/library/nginx:1.25")
	if !ok {
		t.Fatal("expected LookupByImage to match wildcard")
	}
	if got != "nginx-any-tag" {
		t.Errorf("LookupByImage = %q, want %q", got, "nginx-any-tag")
	}
}

func TestPolicyScope_LookupByImage_NoMatch(t *testing.T) {
	ps := NewPolicyScope()

	ps.BindWithInfo(&ContainerInfo{
		ID:    "ctr-1",
		Image: "docker.io/library/nginx:*",
	}, "nginx-policy")

	_, ok := ps.LookupByImage("docker.io/library/redis:7")
	if ok {
		t.Error("expected LookupByImage to return false for non-matching image")
	}
}

func TestPolicyScope_LookupByNamespace(t *testing.T) {
	ps := NewPolicyScope()

	ps.BindWithInfo(&ContainerInfo{
		ID:        "ctr-1",
		Namespace: "production",
	}, "prod-policy")

	got, ok := ps.LookupByNamespace("production")
	if !ok {
		t.Fatal("expected LookupByNamespace to find match")
	}
	if got != "prod-policy" {
		t.Errorf("LookupByNamespace = %q, want %q", got, "prod-policy")
	}

	_, ok = ps.LookupByNamespace("staging")
	if ok {
		t.Error("expected LookupByNamespace to return false for non-matching namespace")
	}
}

func TestPolicyScope_All(t *testing.T) {
	ps := NewPolicyScope()

	ps.Bind("ctr-1", "policy-a")
	ps.Bind("ctr-2", "policy-b")
	ps.Bind("ctr-3", "policy-c")

	all := ps.All()
	if len(all) != 3 {
		t.Fatalf("All() returned %d bindings, want 3", len(all))
	}

	found := make(map[string]bool)
	for _, b := range all {
		found[b.ContainerID] = true
	}
	for _, id := range []string{"ctr-1", "ctr-2", "ctr-3"} {
		if !found[id] {
			t.Errorf("All() missing container %s", id)
		}
	}
}

func TestPolicyScope_ConcurrentAccess(t *testing.T) {
	ps := NewPolicyScope()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(2)
		id := string(rune('A' + i%26))
		go func() {
			defer wg.Done()
			ps.Bind("container-"+id, "policy-"+id)
		}()
		go func() {
			defer wg.Done()
			ps.Lookup("container-" + id)
		}()
	}

	wg.Wait()
}

// Plain Bind leaves Image/Namespace empty; looking up an empty key used to
// match every such binding.
func TestPolicyScope_EmptyLookupKeysMatchNothing(t *testing.T) {
	ps := NewPolicyScope()
	ps.Bind("c1", "p1")
	ps.BindWithInfo(&ContainerInfo{ID: "c2"}, "p2")

	if got, ok := ps.LookupByImage(""); ok {
		t.Errorf("LookupByImage(\"\") = %q, true; want no match", got)
	}
	if got, ok := ps.LookupByNamespace(""); ok {
		t.Errorf("LookupByNamespace(\"\") = %q, true; want no match", got)
	}
	// Bindings without an image must not match a real image either.
	if got, ok := ps.LookupByImage("nginx:1"); ok {
		t.Errorf("LookupByImage(nginx:1) = %q, true; want no match", got)
	}
}

func TestPolicyScope_LookupByImage_MostSpecificWins(t *testing.T) {
	// Repeat to defeat lucky map iteration order.
	for i := 0; i < 50; i++ {
		ps := NewPolicyScope()
		ps.BindWithInfo(&ContainerInfo{ID: "a", Image: "docker.io/library/nginx:*"}, "wild")
		ps.BindWithInfo(&ContainerInfo{ID: "b", Image: "docker.io/library/nginx:1.25"}, "exact")
		ps.BindWithInfo(&ContainerInfo{ID: "c", Image: "nginx:*"}, "short-wild")

		if got, _ := ps.LookupByImage("docker.io/library/nginx:1.25"); got != "exact" {
			t.Fatalf("exact match should win, got %q", got)
		}
		if got, _ := ps.LookupByImage("docker.io/library/nginx:1.26"); got != "wild" {
			t.Fatalf("only wildcard should match, got %q", got)
		}
		if got, _ := ps.LookupByImage("nginx:latest"); got != "short-wild" {
			t.Fatalf("short wildcard should match, got %q", got)
		}
	}
}

func TestPolicyScope_LookupDeterministicTiebreak(t *testing.T) {
	for i := 0; i < 50; i++ {
		ps := NewPolicyScope()
		for _, id := range []string{"c3", "c1", "c2"} {
			ps.BindWithInfo(&ContainerInfo{ID: id, Namespace: "prod", Image: "redis:7"}, "p-"+id)
		}
		if got, _ := ps.LookupByNamespace("prod"); got != "p-c1" {
			t.Fatalf("LookupByNamespace = %q, want p-c1 (lowest container ID)", got)
		}
		if got, _ := ps.LookupByImage("redis:7"); got != "p-c1" {
			t.Fatalf("LookupByImage = %q, want p-c1 (lowest container ID)", got)
		}
	}
}
