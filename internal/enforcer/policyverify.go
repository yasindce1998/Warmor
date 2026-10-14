package enforcer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/wasm"
)

// ReadVerifiedPolicy reads the WASM policy at path and verifies its detached
// signature (path + ".sig") against pub, returning the verified bytes. The
// file is read once and the caller must load the returned bytes, so the
// module that runs is exactly the one that was verified.
//
// YAML policies are refused: they are compiled on the host at load time, so
// there are no signed bytes to verify. Sign and deploy the compiled .wasm
// instead.
//
// Missing or invalid signatures increment
// warmor_policy_signature_failures_total{source="file"}.
func ReadVerifiedPolicy(path string, pub ed25519.PublicKey) ([]byte, error) {
	if wasm.IsYAMLPolicy(path) {
		return nil, fmt.Errorf("%s: signature verification requires a compiled .wasm policy (YAML policies are compiled at load time and cannot be signed)", path)
	}
	data, err := crypto.ReadVerifiedPolicy(pub, path, wasm.MaxPolicySize)
	if err != nil {
		if errors.Is(err, crypto.ErrPolicyUnsigned) || errors.Is(err, crypto.ErrPolicySignatureInvalid) {
			metrics.RecordPolicySignatureFailure(metrics.PolicySourceFile)
		}
		return nil, err
	}
	return data, nil
}

// PolicyValidation describes what ValidatePolicy checked.
type PolicyValidation struct {
	// Kind is "wasm" or "yaml".
	Kind string
	// SignatureVerified is true when a verification key was given and the
	// policy's detached signature verified.
	SignatureVerified bool
	// Loaded is true when a WASM module was compiled and instantiated in
	// the policy runtime. A YAML policy without a precompiled sibling .wasm
	// is only schema-checked, because compiling it needs the Rust toolchain
	// and a writable directory.
	Loaded bool
	// WASMPath is the module that was loaded (the sibling .wasm for YAML).
	WASMPath string
}

// ValidatePolicy checks the policy at path the way the daemon would load
// it, without root, BPF or any platform monitor: with pub it reads the file
// once, verifies its signature and loads the verified bytes; it then
// compiles and instantiates the module in a throwaway WASM runtime (no
// compilation cache, so nothing is written to disk).
func ValidatePolicy(ctx context.Context, path string, pub ed25519.PublicKey) (*PolicyValidation, error) {
	res := &PolicyValidation{Kind: "wasm", WASMPath: path}
	var data []byte
	switch {
	case pub != nil:
		d, err := ReadVerifiedPolicy(path, pub)
		if err != nil {
			return nil, err
		}
		data = d
		res.SignatureVerified = true
	case wasm.IsYAMLPolicy(path):
		res.Kind = "yaml"
		if _, err := compiler.ParseFile(path); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		sibling := strings.TrimSuffix(path, filepath.Ext(path)) + ".wasm"
		if _, err := os.Stat(sibling); err != nil {
			return res, nil
		}
		res.WASMPath = sibling
		fallthrough
	default:
		d, err := crypto.ReadFileLimited(res.WASMPath, wasm.MaxPolicySize)
		if err != nil {
			return nil, fmt.Errorf("read policy: %w", err)
		}
		data = d
	}

	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{PoolSize: 1})
	if err != nil {
		return nil, fmt.Errorf("create WASM runtime: %w", err)
	}
	defer rt.Close(ctx)
	if err := rt.LoadPolicyBytes(ctx, data); err != nil {
		return nil, fmt.Errorf("%s: %w", res.WASMPath, err)
	}
	pool, err := wasm.NewPool(ctx, rt, 1)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", res.WASMPath, err)
	}
	pool.Close(ctx)
	res.Loaded = true
	return res, nil
}
