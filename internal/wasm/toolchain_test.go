package wasm

import (
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
)

// The recorded rustc version is part of the compiled-policy identity: a change
// in the compiler must change the cache key so cached WASM is not reused.
func TestYamlCacheKeyIncludesRustcVersion(t *testing.T) {
	policy, err := compiler.Parse([]byte(yamlPolicyV1))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(yamlPolicyV1)

	first, err := yamlCacheKey(data, policy, "rustc 1.100.0 (aaaaaaaa 2026-01-01)")
	if err != nil {
		t.Fatal(err)
	}
	// Same policy, same rustc: stable key (cache hit).
	again, err := yamlCacheKey(data, policy, "rustc 1.100.0 (aaaaaaaa 2026-01-01)")
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatalf("cache key not stable for identical inputs: %s != %s", first, again)
	}

	// Same policy, different rustc: the key must change so cached bytes from
	// the other compiler are invalidated.
	changed, err := yamlCacheKey(data, policy, "rustc 1.101.0 (bbbbbbbb 2026-03-01)")
	if err != nil {
		t.Fatal(err)
	}
	if first == changed {
		t.Fatalf("cache key ignored rustc version change: %s", first)
	}

	// An unlabelled build (rustc unavailable) must also differ from a labelled
	// one, rather than colliding with either recorded version.
	unlabelled, err := yamlCacheKey(data, policy, "")
	if err != nil {
		t.Fatal(err)
	}
	if unlabelled == first || unlabelled == changed {
		t.Fatalf("cache key collided with unlabelled build: %s", unlabelled)
	}
}
