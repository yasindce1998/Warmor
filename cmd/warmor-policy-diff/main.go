package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yasindce1998/warmor/internal/policydiff"
	"github.com/yasindce1998/warmor/internal/policymerge"
)

var version = "dev"

func main() {
	output := flag.String("o", "", "Output file (default: stdout)")
	summary := flag.Bool("summary", false, "Show only summary counts")
	showVersion := flag.Bool("version", false, "Print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: warmor-policy-diff [flags] <policy-a.yaml> <policy-b.yaml>\n\n")
		fmt.Fprintf(os.Stderr, "Compare two warmor policies and show which rules are unique to each.\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  warmor-policy-diff sbom-policy.yaml audit-policy.yaml\n")
		fmt.Fprintf(os.Stderr, "  warmor-policy-diff --summary sbom.yaml audit.yaml\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	args, err := parseInterspersed(flag.CommandLine, os.Args[1:])
	if err != nil {
		os.Exit(2)
	}

	if *showVersion {
		fmt.Printf("warmor-policy-diff %s\n", version)
		os.Exit(0)
	}

	if len(args) != 2 {
		fmt.Fprintf(os.Stderr, "error: exactly 2 policy files required\n")
		flag.Usage()
		os.Exit(1)
	}

	a, err := policymerge.LoadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading %s: %v\n", args[0], err)
		os.Exit(1)
	}
	b, err := policymerge.LoadFile(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading %s: %v\n", args[1], err)
		os.Exit(1)
	}

	result := policydiff.Diff(a, b)

	nameA := filepath.Base(args[0])
	nameB := filepath.Base(args[1])

	var out string
	if *summary {
		out = policydiff.FormatSummary(result, nameA, nameB)
	} else {
		out = policydiff.FormatDetailed(result, nameA, nameB)
	}

	if *output != "" {
		if err := os.WriteFile(*output, []byte(out), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *output, err)
			os.Exit(1)
		}
	} else {
		fmt.Print(out)
	}
}

// parseInterspersed parses flags that may appear before, between or after
// positional arguments (Go's flag package stops at the first positional)
// and returns the positionals in order. A "--" ends flag parsing; every
// argument after it is positional.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if n := len(args) - len(rest); n > 0 && args[n-1] == "--" {
			return append(positional, rest...), nil
		}
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}
