package patterns

import (
	"testing"

	"github.com/yasindce1998/warmor/internal/patterns/globcorpus"
)

// TestSharedGlobCorpus runs the same table the compiled-Rust/WASM test uses
// (internal/compiler/glob_corpus_test.go) against the Go matcher.
func TestSharedGlobCorpus(t *testing.T) {
	m := NewMatcher()
	for _, tc := range globcorpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			got := m.MatchGlob(tc.Pattern, tc.Path)
			if got != tc.Want {
				t.Errorf("MatchGlob(%q, %q) = %v, want %v", tc.Pattern, tc.Path, got, tc.Want)
			}
		})
	}
}
