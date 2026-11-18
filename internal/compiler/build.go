package compiler

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/yasindce1998/warmor/internal/policybuild"
)

type BuildOptions struct {
	// Context bounds toolchain checks and compilation. Nil leaves the overall
	// CLI build without a deadline (the historical unbounded behavior for
	// existing callers); tool discovery always has its own short timeout.
	Context context.Context

	// OutputPath defaults to policy.wasm. Build replaces a regular file only
	// after metadata validation; symlinks, hard links, and special files are
	// rejected. New outputs retain private staging permissions (0600 on Unix,
	// further restricted by umask); existing permission bits are preserved.
	OutputPath string
	RustOnly   bool
	// Verbose prints bounded tool output after the command completes.
	Verbose bool
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

	builtPath, err := compile(crateDir, policy.Name, opts)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
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
	ctx, cancel := context.WithTimeout(ctx, toolCheckTimeout)
	defer cancel()
	_, err := exec.LookPath("cargo")
	if err != nil {
		return fmt.Errorf("cargo not found in PATH. Install Rust from https://rustup.rs and run: rustup target add wasm32-unknown-unknown")
	}

	output, err := runTool(ctx, exec.Command("rustup", "target", "list", "--installed"))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("failed to check rust targets (is rustup installed?): %w", err)
	}

	if !strings.Contains(output.stdout, "wasm32-unknown-unknown") {
		return fmt.Errorf("wasm32-unknown-unknown target not installed. Run: rustup target add wasm32-unknown-unknown")
	}

	return nil
}

// compilerInvocation is the single subprocess that produces the linked wasm.
// Production always uses hermeticRustcBuild. It is a variable solely so the
// package's fake-toolchain tests can exercise tool failure paths; see the
// test-only override in hermetic_testshim_test.go.
var compilerInvocation = hermeticRustcBuild

func compile(crateDir, policyName string, opts BuildOptions) (string, error) {
	return compilerInvocation(crateDir, policyName, opts)
}

// hermeticBuildEnv is the complete child environment. Nothing is inherited
// implicitly: every entry is explicit so controller-supplied policy input
// cannot reach the compiler through ambient configuration.
//
// Allowed:
//   - PATH: operator-installed toolchain location (trusted host configuration).
//   - HOME, TMPDIR, TMP, TEMP: the fresh private crate, not the caller's.
//   - CARGO_HOME: an isolated, empty directory below the crate. rustc does not
//     read it, but pinning it prevents any Cargo-based future path from
//     consulting a user or ancestor config.
//   - RUSTUP_HOME: the operator's toolchain location. rustup proxy binaries
//     need it to find the selected toolchain; it is host configuration, never
//     derived from policy input. RUSTUP_TOOLCHAIN is deliberately not allowed.
//   - CARGO_TARGET_DIR: inside the private crate, for tooling compatibility.
//   - LANG/LC_ALL: deterministic diagnostics.
//
// Deliberately absent: RUSTFLAGS, RUSTC_WRAPPER, CARGO_BUILD_RUSTC_WRAPPER,
// CARGO_ENCODED_RUSTFLAGS, RUSTC, RUSTC_BOOTSTRAP, all other RUSTC_/CARGO_/
// RUSTUP_ overrides, linker/loader injection (LD_PRELOAD, DYLD_*), and every
// other ambient variable. PATH is inherited only as tool discovery input.
func hermeticBuildEnv(crateDir string) []string {
	rustupHome := os.Getenv("RUSTUP_HOME")
	if rustupHome == "" {
		home := os.Getenv("HOME")
		if runtime.GOOS == "windows" && home == "" {
			home = os.Getenv("USERPROFILE")
		}
		if home != "" {
			rustupHome = filepath.Join(home, ".rustup")
		}
	}
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + crateDir,
		"TMPDIR=" + crateDir,
		"TMP=" + crateDir,
		"TEMP=" + crateDir,
		"CARGO_HOME=" + filepath.Join(crateDir, "cargo-home"),
		"RUSTUP_HOME=" + rustupHome,
		"CARGO_TARGET_DIR=" + filepath.Join(crateDir, "target"),
		"LANG=C",
		"LC_ALL=C",
	}
	if runtime.GOOS == "windows" {
		// Windows toolchains and rustup need these host-provided directories;
		// point writable ones into the private crate.
		env = append(env,
			"USERPROFILE="+crateDir,
			"APPDATA="+filepath.Join(crateDir, "appdata", "roaming"),
			"LOCALAPPDATA="+filepath.Join(crateDir, "appdata", "local"),
			"SYSTEMROOT="+os.Getenv("SYSTEMROOT"),
			"COMSPEC="+os.Getenv("COMSPEC"),
			"PATHEXT="+os.Getenv("PATHEXT"),
		)
	}
	return env
}

// hermeticRustcBuild invokes rustc directly. The generated crate has no
// dependencies and no build scripts, so Cargo adds no value here. Avoiding it
// also removes Cargo's config-file search: a .cargo/config.toml in any ancestor
// of the temp crate (or in CARGO_HOME) can otherwise set a rustc wrapper,
// rustflags, or injected [env] entries. Nothing outside argv and the explicit
// allowlist can influence code generation.
//
// The flags mirror [profile.release] in GenerateCargoToml (opt-level="z",
// lto=true, codegen-units=1, strip=true) and its [lib] crate-type cdylib and
// edition 2021, preserving the artifact ABI. Link output is emitted directly
// into the private crate as a singly linked regular file, never as a Cargo
// hard link into target/, and never into the caller's destination.
func hermeticRustcBuild(crateDir, policyName string, opts BuildOptions) (string, error) {
	safeName := crateIdentifier(policyName)
	wasmFile := fmt.Sprintf("warmor_policy_%s.wasm", safeName)
	builtPath := filepath.Join(crateDir, wasmFile)
	args := []string{
		"--edition=2021",
		"--crate-type=cdylib",
		"--crate-name=warmor_policy_" + safeName,
		"--target=wasm32-unknown-unknown",
		"-C", "opt-level=z",
		"-C", "lto=fat",
		"-C", "codegen-units=1",
		"-C", "strip=symbols",
		// rustc parses commas inside --emit even in a single argv entry. Use
		// only the sanitized basename, relative to cmd.Dir, not a caller path.
		"--emit=link=" + wasmFile,
		filepath.Join("src", "lib.rs"),
	}
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, "rustc", args...)
	cmd.WaitDelay = 5 * time.Second
	cmd.Dir = crateDir
	cmd.Env = hermeticBuildEnv(crateDir)

	output, err := runTool(ctx, cmd)
	if opts.Verbose {
		fmt.Fprint(os.Stdout, output.stdout)
		fmt.Fprint(os.Stderr, output.stderr)
	}

	if err != nil {
		return "", fmt.Errorf("rustc build failed: %w\n%s", err, output.stderr)
	}

	// The compiler never receives or writes the caller's destination. Build
	// reads this private artifact with a size bound and validates metadata
	// before publishing.
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
