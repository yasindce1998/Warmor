package simulator

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
)

// FormatJSON writes the simulation result as indented JSON.
func FormatJSON(w io.Writer, result *SimulationResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// FormatText writes a human-readable simulation report.
func FormatText(w io.Writer, result *SimulationResult) error {
	fmt.Fprintf(w, "Policy Simulation Report\n")
	fmt.Fprintf(w, "========================\n\n")
	fmt.Fprintf(w, "Events replayed: %d\n", result.TotalEvents)
	fmt.Fprintf(w, "Duration:        %s\n\n", result.Duration.Round(1e6))

	fmt.Fprintf(w, "Decision breakdown:\n")
	fmt.Fprintf(w, "  ALLOW: %d (%.1f%%)\n", result.WouldAllow, pct(result.WouldAllow, result.TotalEvents))
	fmt.Fprintf(w, "  DENY:  %d (%.1f%%)\n", result.WouldDeny, pct(result.WouldDeny, result.TotalEvents))
	fmt.Fprintf(w, "  LOG:   %d (%.1f%%)\n\n", result.WouldLog, pct(result.WouldLog, result.TotalEvents))

	// Sort copies: formatting must not reorder the caller's result.
	if len(result.UniqueNewDenials) > 0 {
		denials := slices.Clone(result.UniqueNewDenials)
		sort.SliceStable(denials, func(i, j int) bool {
			return denials[i].Count > denials[j].Count
		})
		fmt.Fprintf(w, "New denials (%d unique patterns):\n", len(denials))
		fmt.Fprintf(w, "  %-10s %-16s %-40s %s\n", "TYPE", "COMMAND", "TARGET", "COUNT")
		fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 80))
		for _, d := range denials {
			fmt.Fprintf(w, "  %-10s %-16s %-40s %d\n", d.EventType, d.Comm, truncate(d.Target, 40), d.Count)
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintf(w, "No new denials — all previously-allowed events remain allowed.\n\n")
	}

	if len(result.UniqueNewAllows) > 0 {
		allows := slices.Clone(result.UniqueNewAllows)
		sort.SliceStable(allows, func(i, j int) bool {
			return allows[i].Count > allows[j].Count
		})
		fmt.Fprintf(w, "New allows (%d unique patterns):\n", len(allows))
		fmt.Fprintf(w, "  %-10s %-16s %-40s %s\n", "TYPE", "COMMAND", "TARGET", "COUNT")
		fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 80))
		for _, a := range allows {
			fmt.Fprintf(w, "  %-10s %-16s %-40s %d\n", a.EventType, a.Comm, truncate(a.Target, 40), a.Count)
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintf(w, "No new allows — all previously-denied events remain denied.\n\n")
	}

	return nil
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
