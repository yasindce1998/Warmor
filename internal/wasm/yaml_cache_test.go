package wasm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
)

const yamlPolicyV1 = `name: cache-test
version: 1
rules:
  - name: deny-x
    event: process
    conditions:
      all:
        - path: { eq: "/bin/x" }
    action: deny
default_action: allow
`

// stubYAMLBuild replaces the Rust build with a copy of the prebuilt fixture
// and returns a pointer to the number of builds performed.
func stubYAMLBuild(t *testing.T) *int {
	t.Helper()
	fixture, err := os.ReadFile(filepath.Join("testdata", "allow_policy.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	builds := 0
	orig := buildYAMLPolicy
	buildYAMLPolicy = func(_ *compiler.Policy, out string) error {
		builds++
		return os.WriteFile(out, fixture, 0o600)
	}
	t.Cleanup(func() { buildYAMLPolicy = orig })
	return &builds
}

func loadYAML(t *testing.T, cacheDir, yamlPath string) {
	t.Helper()
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{CacheDir: cacheDir})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	if err := rt.LoadPolicyFromYAML(ctx, yamlPath); err != nil {
		t.Fatalf("LoadPolicyFromYAML: %v", err)
	}
}

func TestLoadPolicyFromYAML_RecompilesWhenYAMLChanges(t *testing.T) {
	builds := stubYAMLBuild(t)
	cacheDir := t.TempDir()
	policyDir := t.TempDir()
	yamlPath := filepath.Join(policyDir, "policy.yaml")
	if err := os.WriteFile(yamlPath, []byte(yamlPolicyV1), 0o600); err != nil {
		t.Fatal(err)
	}
	// The policy directory may be a read-only ConfigMap mount.
	if err := os.Chmod(policyDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(policyDir, 0o755) })

	loadYAML(t, cacheDir, yamlPath)
	if *builds != 1 {
		t.Fatalf("builds = %d after first load, want 1", *builds)
	}
	loadYAML(t, cacheDir, yamlPath)
	if *builds != 1 {
		t.Fatalf("unchanged YAML rebuilt (builds = %d), want cache hit", *builds)
	}

	// Edit the YAML: the new content must be compiled, not the old module.
	if err := os.Chmod(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(yamlPath, []byte(
		`name: cache-test
version: 1
rules:
  - name: deny-y
    event: process
    conditions:
      all:
        - path: { eq: "/bin/y" }
    action: deny
default_action: deny
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(policyDir, 0o555); err != nil {
		t.Fatal(err)
	}
	loadYAML(t, cacheDir, yamlPath)
	if *builds != 2 {
		t.Fatalf("edited YAML was not recompiled (builds = %d), want 2", *builds)
	}

	entries, _ := os.ReadDir(policyDir)
	if len(entries) != 1 {
		t.Errorf("files written next to the YAML: %v", entries)
	}
	cached, _ := filepath.Glob(filepath.Join(cacheDir, "yaml", "*.wasm"))
	if len(cached) != 2 {
		t.Errorf("cache entries = %v, want one per YAML version", cached)
	}
}

func TestLoadPolicyFromYAML_IgnoresSiblingWasm(t *testing.T) {
	builds := stubYAMLBuild(t)
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(yamlPath, []byte(yamlPolicyV1), 0o600); err != nil {
		t.Fatal(err)
	}
	// A stale (here: invalid) sibling module must not shadow the YAML.
	if err := os.WriteFile(filepath.Join(dir, "policy.wasm"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	loadYAML(t, t.TempDir(), yamlPath)
	if *builds != 1 {
		t.Fatalf("builds = %d, want the YAML to be compiled", *builds)
	}
}

func TestLoadPolicyFromYAML_NoCacheDirUsesTempDir(t *testing.T) {
	builds := stubYAMLBuild(t)
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "policy.yml")
	if err := os.WriteFile(yamlPath, []byte(yamlPolicyV1), 0o600); err != nil {
		t.Fatal(err)
	}
	loadYAML(t, "", yamlPath)
	if *builds != 1 {
		t.Fatalf("builds = %d, want 1", *builds)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("files written next to the YAML: %v", entries)
	}
}

func TestLoadPolicyFromYAML_CorruptCacheEntryRebuilt(t *testing.T) {
	builds := stubYAMLBuild(t)
	cacheDir := t.TempDir()
	yamlPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(yamlPath, []byte(yamlPolicyV1), 0o600); err != nil {
		t.Fatal(err)
	}
	loadYAML(t, cacheDir, yamlPath)
	cached, _ := filepath.Glob(filepath.Join(cacheDir, "yaml", "*.wasm"))
	if len(cached) != 1 {
		t.Fatalf("cache entries = %v", cached)
	}
	if err := os.WriteFile(cached[0], []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	loadYAML(t, cacheDir, yamlPath)
	if *builds != 2 {
		t.Fatalf("corrupt cache entry not rebuilt (builds = %d)", *builds)
	}
}
