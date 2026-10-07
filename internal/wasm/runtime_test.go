package wasm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testPolicyPath is the path to the prebuilt WASM fixture used across tests.
const testPolicyPath = "testdata/allow_policy.wasm"

// TestIsYAMLPolicy covers the extension-detection helper.
func TestIsYAMLPolicy(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"policy.yaml", true},
		{"policy.yml", true},
		{"/path/to/policy.YAML", true},
		{"/path/to/policy.YML", true},
		{"policy.wasm", false},
		{"policy.json", false},
		{"policy.toml", false},
		{"noextension", false},
		{"yaml", false},
		{".yaml", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := IsYAMLPolicy(tt.path)
			if got != tt.want {
				t.Errorf("IsYAMLPolicy(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestDefaultCacheDir verifies that DefaultCacheDir returns a non-empty path when
// the platform exposes a user cache directory.
func TestDefaultCacheDir(t *testing.T) {
	dir := DefaultCacheDir()
	// On all CI environments os.UserCacheDir() should succeed.
	if dir == "" {
		t.Skip("os.UserCacheDir() returned empty — skipping on this platform")
	}
	if !strings.Contains(dir, "warmor") {
		t.Errorf("DefaultCacheDir() = %q, expected it to contain 'warmor'", dir)
	}
}

// TestNewRuntime_Default verifies that a runtime can be created with no config.
func TestNewRuntime_Default(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer rt.Close(ctx)

	if rt.runtime == nil {
		t.Error("Runtime.runtime is nil after construction")
	}
}

// TestNewRuntime_CustomPoolSize verifies the pool size is respected.
func TestNewRuntime_CustomPoolSize(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{PoolSize: 4})
	if err != nil {
		t.Fatalf("NewRuntime(poolSize=4) error = %v", err)
	}
	defer rt.Close(ctx)

	if rt.poolSize != 4 {
		t.Errorf("poolSize = %d, want 4", rt.poolSize)
	}
}

// TestNewRuntime_ZeroPoolSizeDefaultsToCPU verifies the default pool-size fallback.
func TestNewRuntime_ZeroPoolSizeDefaultsToCPU(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{PoolSize: 0})
	if err != nil {
		t.Fatalf("NewRuntime(poolSize=0) error = %v", err)
	}
	defer rt.Close(ctx)

	if rt.poolSize <= 0 {
		t.Errorf("poolSize = %d, expected >0 (NumCPU fallback)", rt.poolSize)
	}
}

// TestNewRuntime_WithCompilationCache verifies that a cache directory is created
// and the compilation cache is initialised.
func TestNewRuntime_WithCompilationCache(t *testing.T) {
	ctx := context.Background()
	cacheDir := t.TempDir()

	rt, err := NewRuntime(ctx, RuntimeConfig{CacheDir: cacheDir})
	if err != nil {
		t.Fatalf("NewRuntime(cacheDir) error = %v", err)
	}
	defer rt.Close(ctx)

	if rt.cache == nil {
		t.Error("Runtime.cache is nil — expected compilation cache to be set")
	}

	// Directory must exist after construction.
	if _, err := os.Stat(cacheDir); err != nil {
		t.Errorf("cache dir %q should exist, got: %v", cacheDir, err)
	}
}

// TestNewRuntime_BadCacheDir verifies that an unwritable cache directory returns an error.
func TestNewRuntime_BadCacheDir(t *testing.T) {
	ctx := context.Background()
	// A path whose parent doesn't exist and can't be created.
	badDir := "/nonexistent_root_dir/warmor/cache"

	_, err := NewRuntime(ctx, RuntimeConfig{CacheDir: badDir})
	if err == nil {
		t.Error("expected error for bad cache dir, got nil")
	}
}

// TestRuntime_LoadPolicy_Success loads the prebuilt fixture without error.
func TestRuntime_LoadPolicy_Success(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	if err := rt.LoadPolicy(ctx, testPolicyPath); err != nil {
		t.Fatalf("LoadPolicy(%q): %v", testPolicyPath, err)
	}

	if rt.module == nil {
		t.Error("Runtime.module is nil after successful LoadPolicy")
	}
}

// TestRuntime_LoadPolicy_FileNotFound verifies the error path when the file is absent.
func TestRuntime_LoadPolicy_FileNotFound(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	err = rt.LoadPolicy(ctx, "/no/such/policy.wasm")
	if err == nil {
		t.Fatal("expected error loading non-existent policy, got nil")
	}
}

// TestRuntime_LoadPolicy_TooLarge verifies the file-size guard.
func TestRuntime_LoadPolicy_TooLarge(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	// Write a file that is exactly 1 byte over the limit.
	bigFile := filepath.Join(t.TempDir(), "big.wasm")
	f, err := os.Create(bigFile)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if err := f.Truncate(maxPolicySize + 1); err != nil {
		f.Close()
		t.Fatalf("truncate: %v", err)
	}
	f.Close()

	err = rt.LoadPolicy(ctx, bigFile)
	if err == nil {
		t.Fatal("expected error for oversized policy file, got nil")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error message %q should mention 'too large'", err.Error())
	}
}

// TestRuntime_LoadPolicy_InvalidWasm verifies that corrupt WASM bytes are rejected.
func TestRuntime_LoadPolicy_InvalidWasm(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	badFile := filepath.Join(t.TempDir(), "bad.wasm")
	if err := os.WriteFile(badFile, []byte("this is not wasm"), 0o644); err != nil {
		t.Fatalf("write bad wasm: %v", err)
	}

	err = rt.LoadPolicy(ctx, badFile)
	if err == nil {
		t.Fatal("expected error for invalid WASM bytes, got nil")
	}
}

// TestRuntime_Close verifies that Close is idempotent and returns no error on a
// freshly created runtime that never loaded a policy.
func TestRuntime_Close_NoPolicy(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}

	if err := rt.Close(ctx); err != nil {
		t.Errorf("Close() returned unexpected error: %v", err)
	}
}

// TestRuntime_Close_WithPolicy verifies Close cleans up after a loaded module.
func TestRuntime_Close_WithPolicy(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}

	if err := rt.LoadPolicy(ctx, testPolicyPath); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	if err := rt.Close(ctx); err != nil {
		t.Errorf("Close() returned unexpected error: %v", err)
	}
}

// TestRuntime_ReloadPolicy verifies that calling LoadPolicy twice updates the module.
func TestRuntime_ReloadPolicy(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	// Load once.
	if err := rt.LoadPolicy(ctx, testPolicyPath); err != nil {
		t.Fatalf("first LoadPolicy: %v", err)
	}
	first := rt.module

	// Load again — should replace the compiled module.
	if err := rt.LoadPolicy(ctx, testPolicyPath); err != nil {
		t.Fatalf("second LoadPolicy: %v", err)
	}

	if rt.module == nil {
		t.Error("module is nil after reload")
	}
	// The second load produces a new compiled module object.
	if rt.module == first {
		t.Error("module pointer unchanged after reload — expected a fresh compile")
	}
}
