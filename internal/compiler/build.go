package compiler

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/yasindce1998/warmor/internal/policybuild"
)

type BuildOptions struct {
	// Context bounds toolchain checks and compilation. Nil preserves the
	// historical unbounded CLI behavior for existing callers.
	Context context.Context

	// OutputPath defaults to policy.wasm. Build replaces a regular file only
	// after metadata validation; symlinks, hard links, and special files are
	// rejected. New outputs retain private staging permissions (0600 on Unix,
	// further restricted by umask); existing permission bits are preserved.
	OutputPath string
	RustOnly   bool
	Verbose    bool
}

type BuildResult struct {
	WasmPath   string
	RustSource string
	CratePath  string
}

// Build compiles privately, appends build metadata, then publishes one complete
// artifact. Errors before replacement preserve an existing output. An error
// matching ErrArtifactPublicationIndeterminate means the destination may already
// contain the new artifact; callers must not assume the old output survived.
func Build(policy *Policy, opts BuildOptions) (*BuildResult, error) {
	if opts.Context == nil {
		opts.Context = context.Background()
	}
	if err := opts.Context.Err(); err != nil {
		return nil, err
	}
	rustSource, err := GenerateRust(policy)
	if err != nil {
		return nil, fmt.Errorf("generate rust: %w", err)
	}

	if opts.RustOnly {
		return &BuildResult{RustSource: rustSource}, nil
	}

	if err := checkCargoContext(opts.Context); err != nil {
		return nil, err
	}

	crateDir, err := os.MkdirTemp("", "warmor-compile-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	// Failed builds otherwise leak sources and target files: no BuildResult
	// reaches the caller's Cleanup.
	succeeded := false
	defer func() {
		if !succeeded {
			os.RemoveAll(crateDir)
		}
	}()

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

	builtPath, err := cargoBuild(crateDir, policy.Name, opts)
	if err != nil {
		return nil, fmt.Errorf("cargo build: %w", err)
	}
	if err := opts.Context.Err(); err != nil {
		return nil, err
	}
	data, err := readBuiltArtifact(builtPath)
	if err != nil {
		return nil, fmt.Errorf("read built wasm: %w", err)
	}
	data, err = policybuild.Append(data, policybuild.Metadata{Compiler: Identity, DefaultAction: policy.DefaultAction})
	if err != nil {
		return nil, fmt.Errorf("append build metadata: %w", err)
	}
	if len(data) > maxCompiledArtifactBytes {
		return nil, fmt.Errorf("final wasm exceeds %d bytes", maxCompiledArtifactBytes)
	}
	wasmPath, err := newArtifactPublisher().publish(opts.Context, opts.OutputPath, data)
	if err != nil {
		return nil, err
	}

	succeeded = true
	return &BuildResult{
		WasmPath:   wasmPath,
		RustSource: rustSource,
		CratePath:  crateDir,
	}, nil
}

func checkCargo() error {
	return checkCargoContext(context.Background())
}

func checkCargoContext(ctx context.Context) error {
	_, err := exec.LookPath("cargo")
	if err != nil {
		return fmt.Errorf("cargo not found in PATH. Install Rust from https://rustup.rs and run: rustup target add wasm32-unknown-unknown")
	}

	cmd := exec.CommandContext(ctx, "rustup", "target", "list", "--installed")
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("failed to check rust targets (is rustup installed?): %w", err)
	}

	if !strings.Contains(string(output), "wasm32-unknown-unknown") {
		return fmt.Errorf("wasm32-unknown-unknown target not installed. Run: rustup target add wasm32-unknown-unknown")
	}

	return nil
}

func cargoBuild(crateDir, policyName string, opts BuildOptions) (string, error) {
	safeName := crateIdentifier(policyName)
	wasmFile := fmt.Sprintf("warmor_policy_%s.wasm", safeName)
	builtPath := filepath.Join(crateDir, wasmFile)
	// Cargo normally hard-links release artifacts to its deps directory. Have
	// rustc emit the final link output directly into our private crate instead,
	// so strict rejection of hard-linked tool output also works with real Cargo.
	// rustc parses commas inside --emit even in a single argv entry. Use only
	// the sanitized basename, relative to cmd.Dir, not a caller's temp parent.
	args := []string{"rustc", "--target", "wasm32-unknown-unknown", "--release", "--lib", "--", "--emit=link=" + wasmFile}
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, "cargo", args...)
	cmd.WaitDelay = 5 * time.Second
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
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", fmt.Errorf("cargo build failed: %w\n%s", err, stderr.String())
	}

	// Cargo never receives or writes the caller's destination. Build reads this
	// private artifact with a size bound and validates metadata before publishing.
	return builtPath, nil
}

func Cleanup(result *BuildResult) {
	if result != nil && result.CratePath != "" {
		os.RemoveAll(result.CratePath)
	}
}

func CargoAvailable() bool {
	return checkCargo() == nil
}
