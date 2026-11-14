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
