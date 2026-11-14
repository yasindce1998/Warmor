//go:build !windows

package policyserver

import (
	"os"
	"testing"
)

func preparePrivateSnapshotDir(t *testing.T, path string) { t.Helper() }

func assertPrivateSnapshot(t *testing.T, path string) {
	t.Helper()
	if info, err := os.Stat(path); err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatalf("snapshot permissions not private: %v %v", info, err)
	}
}
