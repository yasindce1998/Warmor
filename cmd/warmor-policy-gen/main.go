package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/yasindce1998/warmor/internal/cliflag"
	"github.com/yasindce1998/warmor/internal/policygen"
	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/internal/version"
)

var (
	output       = flag.String("o", "", "Output file path (default: stdout)")
	policyName   = flag.String("name", "generated-policy", "Policy name in output")
	description  = flag.String("description", "", "Policy description (auto-generated if empty)")
	minCount     = flag.Int("min-count", 2, "Minimum observation count to include a behavior")
	commFilter   = flag.String("comm-filter", "", "Only include events from these processes (comma-separated)")
	eventTypes   = flag.String("event-types", "exec,file,network", "Event types to generate rules for (comma-separated)")
	collapse     = flag.Bool("collapse-paths", true, "Collapse similar paths into glob patterns")
	networkGroup = flag.String("network-group", "subnet", "Network grouping strategy: exact, subnet, any")
	showVersion  = flag.Bool("version", false, "Print version and exit")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: warmor-policy-gen [flags] <audit-log.ndjson>\n\n")
		fmt.Fprintf(os.Stderr, "Generates an allowlist YAML policy from warmor audit logs.\n\n")
		fmt.Fprintf(os.Stderr, "The input file should be NDJSON output from warmor-daemon's\n")
		fmt.Fprintf(os.Stderr, "--event-sink=file:<path> option run in --audit mode.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  warmor-policy-gen /var/log/warmor/events.ndjson\n")
		fmt.Fprintf(os.Stderr, "  warmor-policy-gen -o policy.yaml --name my-app audit.ndjson\n")
		fmt.Fprintf(os.Stderr, "  warmor-policy-gen --comm-filter nginx,python3 --min-count 5 audit.ndjson\n")
		fmt.Fprintf(os.Stderr, "  cat audit.ndjson | warmor-policy-gen -\n")
	}

	args, err := cliflag.ParseInterspersed(flag.CommandLine, os.Args[1:])
	if err != nil {
		os.Exit(2)
	}

	if *showVersion {
		fmt.Printf("warmor-policy-gen %s\n", version.Version)
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

	var commList []string
	if *commFilter != "" {
		for _, c := range strings.Split(*commFilter, ",") {
			if t := strings.TrimSpace(c); t != "" {
				commList = append(commList, t)
			}
		}
	}

	var typeList []string
	for _, t := range strings.Split(*eventTypes, ",") {
		if t := strings.TrimSpace(t); t != "" {
			typeList = append(typeList, t)
		}
	}

	readOpts := policygen.ReadOptions{
		CommFilter: commList,
		EventTypes: typeList,
	}

	var events []streaming.SecurityEvent

	if inputPath == "-" {
		events, err = policygen.ReadEvents(os.Stdin, readOpts)
	} else {
		events, err = policygen.ReadFile(inputPath, readOpts)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if len(events) == 0 {
		fmt.Fprintf(os.Stderr, "error: no matching events found in input\n")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Read %d events from audit log\n", len(events))

	aggResult := policygen.Aggregate(events, policygen.AggregateOptions{
		MinCount:      *minCount,
		CollapsePaths: *collapse,
		NetworkGroup:  *networkGroup,
	})

	fmt.Fprintf(os.Stderr, "Aggregated into %d behavior groups\n", len(aggResult.Behaviors))

	yamlBytes, err := policygen.Generate(aggResult, policygen.GenerateOptions{
		PolicyName:  *policyName,
		Description: *description,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating policy: %v\n", err)
		os.Exit(1)
	}

	if *output == "" {
		fmt.Print(string(yamlBytes))
	} else {
		if err := os.WriteFile(*output, yamlBytes, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Policy written to %s\n", *output)
	}
}
