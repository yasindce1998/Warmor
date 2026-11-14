// Package testutil provides isolated test fixtures.
package testutil

import (
	"path/filepath"
	"testing"
)

// PhysicalTempDir returns a test-owned temporary directory without platform
// aliases in its ancestors (for example, macOS /var -> /private/var). Resolve
// only this fixture root, before adding any recording paths or adversarial
// symlinks. Production privatefile operations must continue rejecting symlinks.
func PhysicalTempDir(t testing.TB) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
