package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yasindce1998/warmor/internal/simulator"
	"github.com/yasindce1998/warmor/internal/wasm"
)

var version = "dev"

func main() {
	policy := flag.String("policy", "", "Path to candidate policy (.yaml or .wasm)")
	dataDir := flag.String("data", "", "Path to event store directory")
	since := flag.Duration("since", 7*24*time.Hour, "Only replay events from this duration ago")
	output := flag.String("o", "", "Output file (default: stdout)")
	format := flag.String("format", "text", "Output format: text or json")
	showVersion := flag.Bool("version", false, "Print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: warmor-simulate [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Replay recorded events against a candidate policy to preview impact.\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  warmor-simulate --policy new-policy.yaml --data ./events/ --since 24h\n")
		fmt.Fprintf(os.Stderr, "  warmor-simulate --policy strict.wasm --data ./events/ -o report.json --format json\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("warmor-simulate %s\n", version)
		os.Exit(0)
	}

	if *policy == "" {
		fmt.Fprintf(os.Stderr, "error: --policy is required\n")
		os.Exit(1)
	}
	if *dataDir == "" {
		fmt.Fprintf(os.Stderr, "error: --data is required\n")
		os.Exit(1)
	}
	// Validate before doing any work so a typo is not silently rendered as text.
	if *format != "text" && *format != "json" {
		fmt.Fprintf(os.Stderr, "error: unknown --format %q (valid: text, json)\n", *format)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\nAborting simulation...\n")
		cancel()
	}()

	sinceTime := time.Now().Add(-*since)
	fmt.Fprintf(os.Stderr, "Loading events from %s (since %s)...\n", *dataDir, sinceTime.Format(time.RFC3339))

	events, err := simulator.ReadEvents(*dataDir, sinceTime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading events: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Loaded %d events\n", len(events))

	if len(events) == 0 {
		fmt.Fprintf(os.Stderr, "No events to replay. Nothing to do.\n")
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "Loading policy from %s...\n", *policy)
	rt, err := wasm.NewRuntime(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating WASM runtime: %v\n", err)
		os.Exit(1)
	}
	defer rt.Close(ctx)

	if wasm.IsYAMLPolicy(*policy) {
		err = rt.LoadPolicyFromYAML(ctx, *policy)
	} else {
		err = rt.LoadPolicy(ctx, *policy)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading policy: %v\n", err)
		os.Exit(1)
	}

	pool, err := wasm.NewPool(ctx, rt, 1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating policy pool: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close(ctx)

	hostname, _ := os.Hostname()
	evaluator := wasm.NewPolicyEvaluator(pool, hostname)

	fmt.Fprintf(os.Stderr, "Replaying %d events...\n", len(events))
	result, err := simulator.Replay(ctx, events, evaluator)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error during replay: %v\n", err)
		os.Exit(1)
	}

	w := os.Stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}

	switch *format {
	case "json":
		if err := simulator.FormatJSON(w, result); err != nil {
			fmt.Fprintf(os.Stderr, "error writing report: %v\n", err)
			os.Exit(1)
		}
	case "text":
		if err := simulator.FormatText(w, result); err != nil {
			fmt.Fprintf(os.Stderr, "error writing report: %v\n", err)
			os.Exit(1)
		}
	}

	if *output != "" {
		fmt.Fprintf(os.Stderr, "Report written to %s\n", *output)
	}
}
