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
		c, err := supervisedBackendConfig(tc.enabled, tc.path, tc.digest, tc.trust, 50*time.Millisecond, 5*time.Second)
		if (err == nil) != tc.valid || tc.valid && tc.enabled != (c != nil) {
			t.Fatalf("unexpected opt-in result %+v %v", tc, err)
		}
	}
}

func TestSignedBackendCombinationsRejectBeforeConfiguration(t *testing.T) {
	for _, tc := range []struct{ signed, atomic, host bool }{
		{false, false, false}, {false, true, false},
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
		{"--experimental-supervised-policy-host", "--verify-key", "/not-opened/public.pem", "--policy-host", "/not-executed/host", "--policy-host-sha256", strings.Repeat("a", 64), "--policy-host-load-timeout", "1s"},
	} {
		args := append([]string{"--signed-assignments", "--assignment-state-dir", "/not-opened/state", "--event-sink", "file:/not-opened/events"}, flags...)
		r := runChild(t, nil, args...)
		if r.code != 1 || !strings.Contains(r.stderr, "unsupported until one commit/recovery model is tested") || strings.Contains(r.stderr, "elevated privileges") || strings.Contains(r.stderr, "signed assignment configuration/state") {
			t.Fatalf("signed combination reached side effects: %+v", r)
		}
	}
}

func TestSupervisedLoadDeadlineBounds(t *testing.T) {
	for _, timeout := range []time.Duration{0, -1, 11 * time.Second} {
		if _, err := supervisedBackendConfig(true, "/host", strings.Repeat("a", 64), "", time.Second, timeout); err == nil {
			t.Fatalf("accepted load deadline %s", timeout)
		}
	}
	c, err := supervisedBackendConfig(true, "/host", strings.Repeat("a", 64), "", time.Second, 100*time.Millisecond)
	if err != nil || c.LoadTimeout != 100*time.Millisecond {
		t.Fatalf("explicit bounded load deadline lost: %+v %v", c, err)
	}
	if _, err := supervisedBackendConfig(false, "", "", "", time.Second, time.Second); err == nil {
		t.Fatal("load configuration implicitly enabled backend")
	}
}
