//go:build !linux

package policyhost

import (
	"errors"
	"testing"
)

func TestUnsupportedPlatformNeverFallsBack(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported startup = %v", err)
	}
}
