package wasm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/yasindce1998/warmor/internal/compiler"
)

// RuntimeConfig configures the WASM runtime.
type RuntimeConfig struct {
	// CacheDir enables the Wazero compilation cache. When non-empty, compiled
	// native code is persisted to this directory and reused across restarts.
	CacheDir string

	// PoolSize sets the number of WASM instances in the evaluation pool.
	// Defaults to runtime.NumCPU() if zero.
	PoolSize int
}

// DefaultCacheDir returns the platform-appropriate default cache directory.
func DefaultCacheDir() string {
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "warmor", "wasm-cache")
	}
	return ""
}

// Runtime wraps the WASM runtime
type Runtime struct {
	runtime  wazero.Runtime
	module   wazero.CompiledModule
	config   wazero.ModuleConfig
	cache    wazero.CompilationCache
	poolSize int
	// cacheDir is RuntimeConfig.CacheDir; compiled YAML policies are kept
	// under it (see LoadPolicyFromYAML).
	cacheDir string
}

// NewRuntime creates a new WASM runtime with compilation cache support.
func NewRuntime(ctx context.Context, cfgs ...RuntimeConfig) (*Runtime, error) {
	var cfg RuntimeConfig
	if len(cfgs) > 0 {
		cfg = cfgs[0]
	}

	poolSize := cfg.PoolSize
	if poolSize <= 0 {
		poolSize = runtime.NumCPU()
	}

	runtimeCfg := wazero.NewRuntimeConfig()

	var compilationCache wazero.CompilationCache
	if cfg.CacheDir != "" {
		if err := os.MkdirAll(cfg.CacheDir, 0o750); err != nil {
			return nil, fmt.Errorf("create cache dir: %w", err)
		}
		cache, err := wazero.NewCompilationCacheWithDir(cfg.CacheDir)
		if err != nil {
			return nil, fmt.Errorf("create compilation cache: %w", err)
		}
		compilationCache = cache
		runtimeCfg = runtimeCfg.WithCompilationCache(cache)
	}

	r := wazero.NewRuntimeWithConfig(ctx, runtimeCfg)

	// Register host callback functions before WASI
	if err := registerHostCallbacks(ctx, r); err != nil {
		r.Close(ctx)
		if compilationCache != nil {
			compilationCache.Close(ctx)
		}
		return nil, fmt.Errorf("register host callbacks: %w", err)
	}

	// Instantiate WASI
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		r.Close(ctx)
		if compilationCache != nil {
			compilationCache.Close(ctx)
		}
		return nil, fmt.Errorf("instantiate WASI: %w", err)
	}

	return &Runtime{
		runtime:  r,
		config:   wazero.NewModuleConfig(),
		cache:    compilationCache,
		poolSize: poolSize,
		cacheDir: cfg.CacheDir,
	}, nil
}

// MaxPolicySize is the largest WASM policy module the runtime will load.
const MaxPolicySize = 64 * 1024 * 1024 // 64 MiB

// LoadPolicy loads a WASM policy module from file
func (r *Runtime) LoadPolicy(ctx context.Context, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat policy file: %w", err)
	}
	if info.Size() > MaxPolicySize {
		return fmt.Errorf("policy file too large: %d bytes (max %d)", info.Size(), MaxPolicySize)
	}

	wasmBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read policy file: %w", err)
	}

	if err := r.LoadPolicyBytes(ctx, wasmBytes); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// LoadPolicyBytes compiles and loads a WASM policy module from memory. Use
// it to load exactly the bytes whose signature was verified, rather than
// re-reading a file that may have changed in between.
func (r *Runtime) LoadPolicyBytes(ctx context.Context, wasmBytes []byte) error {
	if len(wasmBytes) > MaxPolicySize {
		return fmt.Errorf("policy too large: %d bytes (max %d)", len(wasmBytes), MaxPolicySize)
	}

	// Compile module
	compiled, err := r.runtime.CompileModule(ctx, wasmBytes)
	if err != nil {
		return fmt.Errorf("compile module: %w", err)
	}

	if err := r.validateModule(ctx, compiled); err != nil {
		compiled.Close(ctx)
		return fmt.Errorf("invalid policy module: %w", err)
	}

	r.module = compiled
	return nil
}

// validateModule rejects modules that do not implement a host ABI the host
// can call, or that declare an unsupported abi_version, so a bad policy fails
// at load time instead of denying every event at runtime.
func (r *Runtime) validateModule(ctx context.Context, compiled wazero.CompiledModule) error {
	if err := validateCompiledModule(compiled); err != nil {
		return err
	}
	if _, ok := compiled.ExportedFunctions()[exportABIVersion]; !ok {
		return nil
	}
	probe, err := r.runtime.InstantiateModule(ctx, compiled, r.config.WithName(""))
	if err != nil {
		return fmt.Errorf("instantiate module: %w", err)
	}
	defer probe.Close(ctx)
	return checkABIVersion(ctx, probe)
}

// LoadPolicyFromYAML compiles a YAML policy to WASM and loads it.
//
// The compiled module is cached under the runtime's cache directory, keyed by
// the YAML content and the compiler that produced it (see yamlCacheKey), so
// editing the YAML always yields a fresh compile and an unchanged YAML is not
// rebuilt. Nothing is ever read from or written next to the YAML file: it may
// live on a read-only volume (e.g. a ConfigMap), and a stale sibling .wasm
// must never shadow the YAML that was actually configured. Without a cache
// directory the module is compiled into a temporary directory each time.
func (r *Runtime) LoadPolicyFromYAML(ctx context.Context, yamlPath string) error {
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		return fmt.Errorf("read YAML policy: %w", err)
	}
	policy, err := compiler.Parse(data)
	if err != nil {
		return fmt.Errorf("parse YAML policy: %w", err)
	}

	outDir := ""
	if r.cacheDir != "" {
		outDir = filepath.Join(r.cacheDir, "yaml")
		if err := os.MkdirAll(outDir, 0o750); err != nil {
			return fmt.Errorf("create YAML policy cache dir: %w", err)
		}
	} else {
		tmp, err := os.MkdirTemp("", "warmor-yaml-*")
		if err != nil {
			return fmt.Errorf("create temp dir: %w", err)
		}
		defer os.RemoveAll(tmp)
		outDir = tmp
	}

	key, err := yamlCacheKey(data, policy)
	if err != nil {
		return fmt.Errorf("compile YAML policy: %w", err)
	}
	wasmPath := filepath.Join(outDir, key+".wasm")
	if _, err := os.Stat(wasmPath); err == nil {
		if err := r.LoadPolicy(ctx, wasmPath); err == nil {
			return nil
		}
		// A corrupt cache entry is rebuilt rather than trusted.
		_ = os.Remove(wasmPath)
	}

	// Build to a temporary name and rename into place, so a concurrent or
	// interrupted build never leaves a truncated module at the cache key.
	tmpPath := fmt.Sprintf("%s.tmp-%d", wasmPath, os.Getpid())
	if err := buildYAMLPolicy(policy, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("compile YAML policy: %w", err)
	}
	if err := os.Rename(tmpPath, wasmPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("store compiled YAML policy: %w", err)
	}
	return r.LoadPolicy(ctx, wasmPath)
}

// yamlCacheKey identifies a compiled YAML policy: sha256 over the YAML bytes,
// the compiler version and the generated Rust source (which changes whenever
// codegen does, even if compiler.Version was not bumped).
func yamlCacheKey(yamlBytes []byte, policy *compiler.Policy) (string, error) {
	src, err := compiler.GenerateRust(policy)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	fmt.Fprintf(h, "warmor-yaml\x00%s\x00%d\x00", compiler.Version, len(yamlBytes))
	h.Write(yamlBytes)
	h.Write([]byte{0})
	h.Write([]byte(src))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// buildYAMLPolicy compiles policy to a WASM module at outPath. It is a
// variable so tests can avoid invoking the Rust toolchain.
var buildYAMLPolicy = func(policy *compiler.Policy, outPath string) error {
	result, err := compiler.Build(policy, compiler.BuildOptions{OutputPath: outPath})
	compiler.Cleanup(result)
	return err
}

// IsYAMLPolicy returns true if the path has a .yaml or .yml extension.
func IsYAMLPolicy(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

// Close cleans up the runtime
func (r *Runtime) Close(ctx context.Context) error {
	if r.module != nil {
		if err := r.module.Close(ctx); err != nil {
			return fmt.Errorf("close module: %w", err)
		}
	}

	if r.runtime != nil {
		if err := r.runtime.Close(ctx); err != nil {
			return fmt.Errorf("close runtime: %w", err)
		}
	}

	if r.cache != nil {
		if err := r.cache.Close(ctx); err != nil {
			return fmt.Errorf("close compilation cache: %w", err)
		}
	}

	return nil
}
