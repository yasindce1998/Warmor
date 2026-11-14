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
