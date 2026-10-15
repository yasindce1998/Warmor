package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yasindce1998/warmor/internal/cliflag"
	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/version"
)

var (
	output      = flag.String("o", "policy.wasm", "Output file path")
	rustOnly    = flag.Bool("rust-only", false, "Emit Rust source without compiling to WASM")
	validate    = flag.Bool("validate", false, "Only validate the YAML policy, don't compile")
	verbose     = flag.Bool("verbose", false, "Show cargo build output")
	showVersion = flag.Bool("version", false, "Print version and exit")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: warmor-compile [flags] <input.yaml>\n\n")
		fmt.Fprintf(os.Stderr, "Compiles a YAML policy definition into a WASM policy module.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  warmor-compile policy.yaml\n")
		fmt.Fprintf(os.Stderr, "  warmor-compile -o custom.wasm policy.yaml\n")
		fmt.Fprintf(os.Stderr, "  warmor-compile policy.yaml -o custom.wasm   # flags may follow the input\n")
		fmt.Fprintf(os.Stderr, "  warmor-compile --rust-only policy.yaml > policy.rs\n")
		fmt.Fprintf(os.Stderr, "  warmor-compile --validate policy.yaml\n")
	}

	args, err := cliflag.ParseInterspersed(flag.CommandLine, os.Args[1:])
	if err != nil {
		os.Exit(2)
	}

	if *showVersion {
		fmt.Printf("warmor-compile %s\n", version.Version)
		os.Exit(0)
	}

	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "error: no input file specified\n\n")
		flag.Usage()
		os.Exit(1)
	}

	inputPath := args[0]
	if len(args) > 1 {
		fmt.Fprintf(os.Stderr, "error: unexpected argument %q (only one input file is accepted)\n", args[1])
		os.Exit(1)
	}

	policy, err := compiler.ParseFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *validate {
		fmt.Printf("✓ %s is valid (%d rules, default_action=%s)\n", policy.Name, len(policy.Rules), policy.DefaultAction)
		os.Exit(0)
	}

	if *rustOnly {
		rust, err := compiler.GenerateRust(policy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(rust)
		os.Exit(0)
	}

	if !compiler.CargoAvailable() {
		fmt.Fprintf(os.Stderr, "error: Rust toolchain not found.\n")
		fmt.Fprintf(os.Stderr, "Install from https://rustup.rs and run:\n")
		fmt.Fprintf(os.Stderr, "  rustup target add wasm32-unknown-unknown\n\n")
		fmt.Fprintf(os.Stderr, "Or use --rust-only to emit Rust source for manual compilation.\n")
		os.Exit(1)
	}

	fmt.Printf("Compiling %s (%d rules)...\n", policy.Name, len(policy.Rules))

	result, err := compiler.Build(policy, compiler.BuildOptions{
		OutputPath: *output,
		Verbose:    *verbose,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer compiler.Cleanup(result)

	fmt.Printf("✓ Compiled to %s\n", result.WasmPath)
}
