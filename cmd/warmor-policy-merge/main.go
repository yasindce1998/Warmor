package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yasindce1998/warmor/internal/policymerge"
)

var version = "dev"

func main() {
	dir := flag.String("dir", "", "Directory containing policy YAML files to merge")
	output := flag.String("o", "", "Output file (default: stdout)")
	name := flag.String("name", "", "Name for merged policy (default: merged-policy)")
	description := flag.String("description", "", "Description for merged policy")
	strategy := flag.String("strategy", "union", "Merge strategy: union, intersection, deny-wins")
	annotate := flag.Bool("annotate", true, "Add provenance annotations to rule reasons")
	dedup := flag.Bool("dedup", true, "Deduplicate identical rules and variables")
	validate := flag.Bool("validate", false, "Validate merged policy against compiler schema")
	showVersion := flag.Bool("version", false, "Print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: warmor-policy-merge [flags] [file1.yaml file2.yaml ...]\n\n")
		fmt.Fprintf(os.Stderr, "Merge multiple warmor policy YAML files into a single unified policy.\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  warmor-policy-merge sbom-policy.yaml audit-policy.yaml -o merged.yaml\n")
		fmt.Fprintf(os.Stderr, "  warmor-policy-merge --dir ./policies -o merged.yaml\n")
		fmt.Fprintf(os.Stderr, "  warmor-policy-merge --strategy deny-wins a.yaml b.yaml c.yaml\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	files, err := parseInterspersed(flag.CommandLine, os.Args[1:])
	if err != nil {
		os.Exit(2)
	}

	if *showVersion {
		fmt.Printf("warmor-policy-merge %s\n", version)
		os.Exit(0)
	}

	var policies []*policymerge.PolicyYAML
	var sources []string

	if *dir != "" {
		policies, sources, err = policymerge.LoadDir(*dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Loaded %d policies from %s\n", len(policies), *dir)
	}

	for _, arg := range files {
		p, err := policymerge.LoadFile(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		policies = append(policies, p)
		sources = append(sources, arg)
	}

	if len(policies) < 2 {
		fmt.Fprintf(os.Stderr, "error: at least 2 policies required to merge\n")
		fmt.Fprintf(os.Stderr, "Provide files as arguments or use --dir to point at a directory\n")
		flag.Usage()
		os.Exit(1)
	}

	opts := policymerge.MergeOptions{
		Name:        *name,
		Description: *description,
		Strategy:    *strategy,
		Annotate:    *annotate,
		Dedup:       *dedup,
	}

	result, err := policymerge.Merge(policies, sources, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *validate {
		if err := policymerge.Validate(result.Policy); err != nil {
			fmt.Fprintf(os.Stderr, "validation error: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Validation passed\n")
	}

	data, err := policymerge.Marshal(result.Policy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshal: %v\n", err)
		os.Exit(1)
	}

	if *output != "" {
		if err := os.WriteFile(*output, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error: write %s: %v\n", *output, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Merged %d policies (%d rules, %d deduplicated) → %s\n",
			result.Sources, len(result.Policy.Rules), result.DedupedRules, *output)
	} else {
		os.Stdout.Write(data)
		fmt.Fprintf(os.Stderr, "Merged %d policies (%d rules, %d deduplicated)\n",
			result.Sources, len(result.Policy.Rules), result.DedupedRules)
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
