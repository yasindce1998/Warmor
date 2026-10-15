package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yasindce1998/warmor/internal/cliflag"
	"github.com/yasindce1998/warmor/internal/sbompolicy"
	"github.com/yasindce1998/warmor/internal/version"
)

var (
	output              = flag.String("o", "", "Output file path (default: stdout)")
	format              = flag.String("format", "auto", "SBOM format: spdx, cyclonedx, or auto")
	level               = flag.String("level", "binary", "Enforcement level: binary, library, or all")
	rootfs              = flag.String("rootfs", "/", "Path to container rootfs for package DB resolution")
	policyName          = flag.String("name", "", "Policy name (default: derived from SBOM)")
	description         = flag.String("description", "", "Policy description")
	includeInterpreters = flag.Bool("include-interpreters", true, "Include known interpreters as allowed binaries")
	showVersion         = flag.Bool("version", false, "Print version and exit")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: warmor-sbom-policy [flags] <sbom.json>\n\n")
		fmt.Fprintf(os.Stderr, "Generate a warmor allowlist policy from an SPDX or CycloneDX SBOM.\n\n")
		fmt.Fprintf(os.Stderr, "The tool parses the SBOM, resolves package names to installed file paths\n")
		fmt.Fprintf(os.Stderr, "via the container's package database, and emits a policy that allows only\n")
		fmt.Fprintf(os.Stderr, "binaries declared in the SBOM.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	args, err := cliflag.ParseInterspersed(flag.CommandLine, os.Args[1:])
	if err != nil {
		os.Exit(2)
	}

	if *showVersion {
		fmt.Printf("warmor-sbom-policy %s\n", version.Version)
		os.Exit(0)
	}

	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Error: SBOM file path required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	inputPath := args[0]
	if len(args) > 1 {
		fmt.Fprintf(os.Stderr, "error: unexpected argument %q (only one input file is accepted)\n", args[1])
		os.Exit(1)
	}

	if *level != "binary" && *level != "library" && *level != "all" {
		fmt.Fprintf(os.Stderr, "Error: --level must be binary, library, or all\n")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Parsing SBOM: %s (format: %s)\n", inputPath, *format)

	sbom, err := sbompolicy.ParseFile(inputPath, *format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing SBOM: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "  Format: %s, Name: %s, Packages: %d\n", sbom.Format, sbom.Name, len(sbom.Packages))
	fmt.Fprintf(os.Stderr, "Resolving packages to file paths (rootfs: %s, level: %s)\n", *rootfs, *level)

	resolved, err := sbompolicy.Resolve(sbom.Packages, sbompolicy.ResolveOptions{
		RootFS: *rootfs,
		Level:  *level,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving packages: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "  Resolved %d files from package databases\n", len(resolved))

	yamlBytes, err := sbompolicy.Generate(resolved, sbompolicy.GenerateOptions{
		PolicyName:          *policyName,
		Description:         *description,
		SBOMName:            sbom.Name,
		IncludeInterpreters: *includeInterpreters,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating policy: %v\n", err)
		os.Exit(1)
	}

	if *output == "" {
		os.Stdout.Write(yamlBytes)
	} else {
		if err := os.WriteFile(*output, yamlBytes, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Policy written to: %s\n", *output)
	}
}
