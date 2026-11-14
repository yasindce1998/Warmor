package main

import (
	"strings"
	"testing"
	"time"
)

func TestSupervisedBackendRequiresExplicitOptIn(t *testing.T) {
	for _, tc := range []struct {
		enabled             bool
		path, digest, trust string
		valid               bool
	}{
		{valid: true},
		{path: "/host"},
		{digest: strings.Repeat("a", 64)},
		{trust: strings.Repeat("b", 64)},
		{enabled: true},
		{enabled: true, path: "/host"},
		{enabled: true, path: "/host", digest: strings.Repeat("a", 64), valid: true},
	} {
		c, err := supervisedBackendConfig(tc.enabled, tc.path, tc.digest, tc.trust, 50*time.Millisecond)
		if (err == nil) != tc.valid || tc.valid && tc.enabled != (c != nil) {
			t.Fatalf("unexpected opt-in result %+v %v", tc, err)
		}
	}
}

func TestSignedBackendCombinationsRejectBeforeConfiguration(t *testing.T) {
	for _, tc := range []struct{ signed, atomic, host bool }{
		{true, false, false}, {false, false, true}, {false, true, true},
		{true, true, false}, {true, false, true}, {true, true, true},
	} {
		err := checkSignedBackendCombination(tc.signed, tc.atomic, tc.host)
		if (err != nil) != (tc.signed && (tc.atomic || tc.host)) {
			t.Fatalf("wrong combination decision %+v: %v", tc, err)
		}
	}
}

func TestMainSignedExperimentalCombinationsRejectBeforeSideEffects(t *testing.T) {
	for _, flags := range [][]string{
		{"--experimental-atomic-generations"},
		{"--experimental-supervised-policy-host"},
		{"--experimental-atomic-generations", "--experimental-supervised-policy-host"},
	} {
		args := append([]string{"--signed-assignments", "--assignment-state-dir", "/not-opened/state", "--event-sink", "file:/not-opened/events"}, flags...)
		r := runChild(t, nil, args...)
		if r.code != 1 || !strings.Contains(r.stderr, "unsupported until one commit/recovery model is tested") || strings.Contains(r.stderr, "elevated privileges") || strings.Contains(r.stderr, "signed assignment configuration/state") {
			t.Fatalf("signed combination reached side effects: %+v", r)
		}
	}
}
