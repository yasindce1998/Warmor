package compiler_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/patterns/globcorpus"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

func yamlQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func globCaseID(i int) string {
	return fmt.Sprintf("glob-case-%03d", i)
}

// TestCompiledGlobCorpus exercises the exact same shared corpus as
// internal/patterns.TestSharedGlobCorpus, but against the generated Rust
// matcher through the compiled WASM policy and the real host evaluator.
// A single module is built: each rule is gated by a unique comm value so
// first-match precedence cannot hide another case's result.
func TestCompiledGlobCorpus(t *testing.T) {
	if !compiler.CargoAvailable() {
		if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
			t.Fatal("cargo and wasm32 target required")
		}
		t.Skip("cargo/wasm32 target unavailable")
	}

	var yaml strings.Builder
	yaml.WriteString("name: glob-corpus\nversion: 1\ndefault_action: allow\nrules:\n")
	for i, tc := range globcorpus.Cases {
		fmt.Fprintf(&yaml, "- name: %s\n  event: process\n  action: deny\n", globCaseID(i))
		fmt.Fprintf(&yaml, "  conditions: {all: [{comm: {eq: %s}}, {path: {glob: %s}}]}\n",
			yamlQuote(globCaseID(i)), yamlQuote(tc.Pattern))
	}

	p, err := compiler.Parse([]byte(yaml.String()))
	if err != nil {
		t.Fatalf("Parse policy: %v", err)
	}
	out := filepath.Join(t.TempDir(), "glob.wasm")
	built, err := compiler.Build(p, compiler.BuildOptions{OutputPath: out})
	compiler.Cleanup(built)
	if err != nil {
		t.Fatalf("Build policy: %v", err)
	}

	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)
	if err := rt.LoadPolicy(ctx, out); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	pool, err := wasm.NewPool(ctx, rt, 1)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close(ctx)
	ev := wasm.NewPolicyEvaluator(pool, "glob-corpus")

	for i, tc := range globcorpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			result, err := ev.Evaluate(ctx, &api.Event{
				Type:     api.EventTypeProcess,
				Comm:     globCaseID(i),
				Filename: tc.Path,
			})
			if err != nil {
				t.Fatalf("Evaluate(%q): %v", tc.Path, err)
			}
			got := result.Action == api.ActionDeny
			if got != tc.Want {
				t.Errorf("compiled glob %q vs %q = %v, want %v (action %v)", tc.Pattern, tc.Path, got, tc.Want, result.Action)
			}
		})
	}
}
