package compiler

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type BuildOptions struct {
	OutputPath string
	RustOnly   bool
	Verbose    bool
}

type BuildResult struct {
	WasmPath   string
	RustSource string
	CratePath  string
}

func Build(policy *Policy, opts BuildOptions) (*BuildResult, error) {
	rustSource, err := GenerateRust(policy)
	if err != nil {
		return nil, fmt.Errorf("generate rust: %w", err)
	}

	if opts.RustOnly {
		return &BuildResult{RustSource: rustSource}, nil
	}

	if err := checkCargo(); err != nil {
		return nil, err
	}

	crateDir, err := os.MkdirTemp("", "warmor-compile-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	srcDir := filepath.Join(crateDir, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		return nil, fmt.Errorf("create src dir: %w", err)
	}

	cargoToml := GenerateCargoToml(policy.Name)
	if err := os.WriteFile(filepath.Join(crateDir, "Cargo.toml"), []byte(cargoToml), 0o644); err != nil {
		return nil, fmt.Errorf("write Cargo.toml: %w", err)
	}

	if err := os.WriteFile(filepath.Join(srcDir, "lib.rs"), []byte(rustSource), 0o644); err != nil {
		return nil, fmt.Errorf("write lib.rs: %w", err)
	}

	wasmPath, err := cargoBuild(crateDir, policy.Name, opts)
	if err != nil {
		return nil, fmt.Errorf("cargo build: %w", err)
	}

	return &BuildResult{
		WasmPath:   wasmPath,
		RustSource: rustSource,
		CratePath:  crateDir,
	}, nil
}

func checkCargo() error {
	_, err := exec.LookPath("cargo")
	if err != nil {
		return fmt.Errorf("cargo not found in PATH. Install Rust from https://rustup.rs and run: rustup target add wasm32-unknown-unknown")
	}

	cmd := exec.Command("rustup", "target", "list", "--installed")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check rust targets (is rustup installed?): %w", err)
	}

	if !strings.Contains(string(output), "wasm32-unknown-unknown") {
		return fmt.Errorf("wasm32-unknown-unknown target not installed. Run: rustup target add wasm32-unknown-unknown")
	}

	return nil
}

func cargoBuild(crateDir, policyName string, opts BuildOptions) (string, error) {
	args := []string{"build", "--target", "wasm32-unknown-unknown", "--release"}
	cmd := exec.Command("cargo", args...)
	cmd.Dir = crateDir
	cmd.Env = append(os.Environ(), "CARGO_TARGET_DIR="+filepath.Join(crateDir, "target"))

	var stderr bytes.Buffer
	if opts.Verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else {
		cmd.Stderr = &stderr
	}

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("cargo build failed: %w\n%s", err, stderr.String())
	}

	safeName := crateIdentifier(policyName)
	wasmFile := fmt.Sprintf("warmor_policy_%s.wasm", safeName)
	builtPath := filepath.Join(crateDir, "target", "wasm32-unknown-unknown", "release", wasmFile)

	if _, err := os.Stat(builtPath); err != nil {
		return "", fmt.Errorf("expected wasm output not found at %s", builtPath)
	}

	outputPath := opts.OutputPath
	if outputPath == "" {
		outputPath = "policy.wasm"
	}

	if !filepath.IsAbs(outputPath) {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("get working directory: %w", err)
		}
		outputPath = filepath.Join(wd, outputPath)
	}

	data, err := os.ReadFile(builtPath)
	if err != nil {
		return "", fmt.Errorf("read built wasm: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return "", fmt.Errorf("write output wasm: %w", err)
	}

	return outputPath, nil
}

func Cleanup(result *BuildResult) {
	if result != nil && result.CratePath != "" {
		os.RemoveAll(result.CratePath)
	}
}

func CargoAvailable() bool {
	return checkCargo() == nil
}
