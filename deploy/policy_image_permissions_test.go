package deploy_test

import (
	"os"
	"strings"
	"testing"
)

func TestBakedPolicyReadableByNonRootImageConsumers(t *testing.T) {
	data, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	// BuildKit COPY otherwise preserves the compiler's deliberately private
	// 0600 output. Both images run non-root in the chart; neither may depend on
	// the compiler bypassing its caller's umask to make public image data usable.
	seen := map[string]int{
		"/etc/warmor-controller/default-policy.wasm": 0,
		"/etc/warmor/policy.wasm":                    0,
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "COPY" {
			continue
		}
		destination := fields[len(fields)-1]
		if _, ok := seen[destination]; !ok {
			continue
		}
		seen[destination]++
		flags := map[string]bool{}
		for _, field := range fields[1 : len(fields)-2] {
			flags[field] = true
		}
		if fields[len(fields)-2] != "/work/policy.wasm" || !flags["--from=policy"] || !flags["--chmod=0644"] {
			t.Errorf("baked policy must use explicit public read-only-for-nonowners mode: %s", line)
		}
	}
	for destination, count := range seen {
		if count != 1 {
			t.Errorf("baked policy copies to %s = %d, want exactly one", destination, count)
		}
	}
}

// TestBakedPolicyParentDirectoriesTraversable guards the reason the 0644 file
// mode alone is not enough: if BuildKit auto-creates the destination directory
// for a file COPY, it applies --chmod=0644 to that directory too, so a non-root
// runtime cannot traverse it and hits EACCES. The parent must be pre-created at
// 0755 in the policy stage and copied into each final image before the file.
func TestBakedPolicyParentDirectoriesTraversable(t *testing.T) {
	data, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")

	// The policy stage must stage the public parent directories at 0755.
	mkdirLine := "RUN install -d -m 0755 /public/etc/warmor /public/etc/warmor-controller"
	if !strings.Contains(string(data), mkdirLine) {
		t.Errorf("policy stage must create public parents at 0755, want line: %s", mkdirLine)
	}

	// Each final image must copy its public parent at 0755 before the file COPY.
	wantParents := map[string]string{
		"/etc/warmor-controller": "/public/etc/warmor-controller",
		"/etc/warmor":            "/public/etc/warmor",
	}
	found := map[string]int{}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "COPY" {
			continue
		}
		for dest, src := range wantParents {
			if fields[len(fields)-1] != dest || fields[len(fields)-2] != src {
				continue
			}
			found[dest]++
			flags := map[string]bool{}
			for _, field := range fields[1 : len(fields)-2] {
				flags[field] = true
			}
			if !flags["--from=policy"] || !flags["--chmod=0755"] {
				t.Errorf("policy parent copy must be --from=policy --chmod=0755: %s", line)
			}
		}
	}
	for dest := range wantParents {
		if found[dest] != 1 {
			t.Errorf("public parent copy to %s = %d, want exactly one", dest, found[dest])
		}
	}
}
