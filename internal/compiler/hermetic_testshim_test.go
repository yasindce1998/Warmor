package compiler

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Existing fake-toolchain fixtures inject fake cargo/rustup binaries through
// PATH (sometimes masking rustc entirely) and select their behavior with
// WARMOR_COMPILER_TEST_HELPER. Route only those fixtures through the legacy
// cargo invocation so they keep exercising tool failure and cancellation paths.
// This file is test-only: production always uses the hermetic, allowlisted
// rustc invocation from build.go.
func init() {
	hermetic := compilerInvocation
	compilerInvocation = func(crateDir, policyName string, opts BuildOptions) (string, error) {
		_, rustcMissing := exec.LookPath("rustc")
		if os.Getenv("WARMOR_COMPILER_TEST_HELPER") == "" && rustcMissing == nil {
			return hermetic(crateDir, policyName, opts)
		}
		return legacyFakeCargoBuild(crateDir, policyName, opts)
	}
}

func legacyFakeCargoBuild(crateDir, policyName string, opts BuildOptions) (string, error) {
	safeName := crateIdentifier(policyName)
	wasmFile := fmt.Sprintf("warmor_policy_%s.wasm", safeName)
	builtPath := filepath.Join(crateDir, wasmFile)
	args := []string{"rustc", "--target", "wasm32-unknown-unknown", "--release", "--lib", "--", "--emit=link=" + wasmFile}
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, "cargo", args...)
	cmd.WaitDelay = 5 * time.Second
	cmd.Dir = crateDir
	cmd.Env = append(os.Environ(), "CARGO_TARGET_DIR="+filepath.Join(crateDir, "target"))

	output, err := runTool(ctx, cmd)
	if opts.Verbose {
		fmt.Fprint(os.Stdout, output.stdout)
		fmt.Fprint(os.Stderr, output.stderr)
	}
	if err != nil {
		return "", fmt.Errorf("cargo build failed: %w\n%s", err, output.stderr)
	}
	return builtPath, nil
}
