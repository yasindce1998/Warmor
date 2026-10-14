package cliflag

import (
	"flag"
	"io"
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	good := map[string]time.Duration{
		"7d":    7 * 24 * time.Hour,
		"1d12h": 36 * time.Hour,
		"1.5d":  36 * time.Hour,
		"0d":    0,
		"168h":  168 * time.Hour,
		"90m":   90 * time.Minute,
		"1h30m": 90 * time.Minute,
		" 2d ":  48 * time.Hour,
	}
	for in, want := range good {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "d", "xd", "-1d", "1d-1h", "1dx", "7days", "1e3d", "7", "infd", "NaNd", "99999999d"} {
		if _, err := ParseDuration(in); err == nil {
			t.Errorf("ParseDuration(%q) succeeded, want error", in)
		}
	}
}

func TestDurationFlag(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	since := Duration(fs, "since", 7*24*time.Hour, "")
	if got := fs.Lookup("since").DefValue; got != "7d" {
		t.Errorf("DefValue = %q, want 7d", got)
	}
	if err := fs.Parse([]string{"--since", "3d"}); err != nil {
		t.Fatal(err)
	}
	if *since != 72*time.Hour {
		t.Errorf("since = %v, want 72h", *since)
	}
	if err := fs.Parse([]string{"--since", "36h"}); err != nil || *since != 36*time.Hour {
		t.Errorf("since = %v, %v; want 36h", *since, err)
	}
	if fs.Lookup("since").Value.String() != "36h0m0s" {
		t.Errorf("String() = %q", fs.Lookup("since").Value.String())
	}
	if err := fs.Parse([]string{"--since", "soon"}); err == nil {
		t.Error("expected error for invalid duration")
	}
}
