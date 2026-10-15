package policymerge

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
)

const temporalRuleYAML = `name: %s
version: 1
default_action: allow
rules:
  - name: curl-startup
    event: network
    conditions:
      all:
        - comm: { eq: "curl" }
    action: deny
    temporal:
      max_container_age: "%s"
`

// TestMergeKeepsTemporal: merging must carry a rule's temporal block through,
// or the merged rule becomes unconditional; and rules that differ only in
// their window are not duplicates.
func TestMergeKeepsTemporal(t *testing.T) {
	dir := t.TempDir()
	write := func(name, age string) *PolicyYAML {
		path := filepath.Join(dir, name+".yaml")
		data := []byte(fmt.Sprintf(temporalRuleYAML, name, age))
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		p, err := LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	a, b, c := write("a", "5m"), write("b", "5m"), write("c", "1h")

	res, err := Merge([]*PolicyYAML{a, b, c}, nil, MergeOptions{Strategy: "union", Dedup: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Policy.Rules) != 2 {
		t.Fatalf("merged %d rules, want 2 (5m deduplicated, 1h kept)", len(res.Policy.Rules))
	}
	out, err := Marshal(res.Policy)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := compiler.Parse(out)
	if err != nil {
		t.Fatalf("merged policy does not compile: %v\n%s", err, out)
	}
	for _, r := range merged.Rules {
		if r.Temporal == nil || r.Temporal.MaxContainerAge == 0 {
			t.Errorf("rule %s lost its temporal block:\n%s", r.Name, out)
		}
	}
}
