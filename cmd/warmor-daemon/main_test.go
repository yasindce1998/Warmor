package main

import (
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/version"
)

func TestFlagDefaults(t *testing.T) {
	want := map[string]string{
		"policy":         "policies/example/policy.wasm",
		"stats-interval": (30 * time.Second).String(),
		"log-level":      "info",
		"metrics-port":   "9090",
		"audit":          "false",
		"cgroup-filter":  "",
		"lsm-enforce":    "false",
		"require-lsm":    "false",
		"no-lsm":         "false",
		"event-sink":     "",
		"event-file-max": "104857600",
		"webhook-header": "",
		"event-labels":   "",
		"version":        "false",
		"server":         "",
		"server-token":   "",
		"tls-ca":         "",
		"tls-cert":       "",
		"tls-key":        "",
		"agent-id":       "",
		"poll-interval":  (30 * time.Second).String(),
	}
	for name, def := range want {
		f := flag.CommandLine.Lookup(name)
		if f == nil {
			t.Errorf("flag -%s not registered", name)
			continue
		}
		if f.DefValue != def {
			t.Errorf("-%s default = %q, want %q", name, f.DefValue, def)
		}
	}
}

func TestPrintBanner(t *testing.T) {
	_, stderr := runMainFunc(t, printBanner)
	assertContains(t, "banner", stderr, "WASM-Powered Security Enforcer", "Version: "+version.Version)
}

func TestMain_VersionFlag(t *testing.T) {
	_, stderr := runMain(t, "", "-version")
	assertContains(t, "log", stderr, "warmor version "+version.Version)
	// -version returns before the banner / privilege check / enforcer.
	if strings.Contains(stderr, "WASM-Powered") || strings.Contains(stderr, "elevated") {
		t.Errorf("-version should short-circuit:\n%s", stderr)
	}
}

func TestMain_UnknownFlag(t *testing.T) {
	r := runChild(t, nil, "-definitely-not-a-flag")
	if r.code != 2 {
		t.Errorf("exit = %d, want 2", r.code)
	}
	assertContains(t, "stderr", r.stderr, "flag provided but not defined", "-lsm-enforce")
}

func TestMain_InvalidFlagValues(t *testing.T) {
	for _, args := range [][]string{
		{"-stats-interval", "soon"},
		{"-metrics-port", "http"},
		{"-event-file-max", "big"},
	} {
		r := runChild(t, nil, args...)
		if r.code != 2 {
			t.Errorf("%v: exit = %d, want 2", args, r.code)
		}
		assertContains(t, "stderr", r.stderr, "invalid value")
	}
}
