//go:build !windows

package simulator

import (
	"testing"

	"github.com/yasindce1998/warmor/internal/testutil"
)

func recordingTempDir(t *testing.T) string {
	t.Helper()
	return testutil.PhysicalTempDir(t)
}

// Referenced only in the Windows branch of the shared outcome test. Keeping the
// native assertion in a Windows file avoids importing Windows APIs on Unix.
func assertWindowsRecordingPrivate(t *testing.T, path string) {
	t.Helper()
	t.Fatal("Windows ACL assertion called on a non-Windows platform")
}
