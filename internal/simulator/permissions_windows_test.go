//go:build windows

package simulator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/internal/testutil"
	"github.com/yasindce1998/warmor/pkg/api"
	"golang.org/x/sys/windows"
)

func recordingTempDir(t *testing.T) string {
	t.Helper()
	path := testutil.PhysicalTempDir(t)
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	// An elevated token's configurable default owner can be Administrators.
	// The contract requires the token user, so make that fixture explicit
	// without changing any process token, privilege, or host policy.
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, u.User.Sid, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertWindowsRecordingPrivate(t *testing.T, path string) {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || !windows.EqualSid(owner, u.User.Sid) {
		t.Fatalf("unexpected owner: %v %v", owner, err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("unprotected DACL: %v", err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 1 {
		t.Fatalf("not an owner-only DACL: %v", err)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 ||
		ace.Mask != windows.STANDARD_RIGHTS_ALL|0x1ff || !windows.EqualSid((*windows.SID)(unsafe.Pointer(&ace.SidStart)), u.User.Sid) {
		t.Fatalf("unexpected ACL: %s", sd.String())
	}
}

func TestWindowsEventStorePrivateRecordings(t *testing.T) {
	root := recordingTempDir(t)
	dir := filepath.Join(root, "new", "store")
	store, err := NewEventStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	legacy := filepath.Join(dir, "events-2001-01-01.ndjson")
	if err := os.WriteFile(legacy, []byte("old secret"), 0644); err != nil {
		t.Fatal(err)
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(legacy, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, u.User.Sid, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewEventStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Dir(dir), dir, legacy} {
		assertWindowsRecordingPrivate(t, path)
	}
	event := streaming.FromAPIEvent(&api.Event{Process: &api.ProcessEvent{Args: []string{"app", "--password", "secret-token"}}}, nil)
	if err := store.Write(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	store.curDate = "previous-day"
	if err := store.Write(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "events-"+time.Now().UTC().Format("2006-01-02")+".ndjson")
	assertWindowsRecordingPrivate(t, path)
	if data, err := os.ReadFile(path); err != nil || !strings.Contains(string(data), "secret-token") {
		t.Fatalf("missing private replay input: %q %v", data, err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	// Close first: Win32 deletion of a live file can remain delete-pending.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	store.curDate = "previous-day"
	for i := 0; i < 2; i++ {
		if err := store.Write(context.Background(), event); err == nil {
			t.Fatal("daily reopen followed symlink")
		}
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "keep" {
		t.Fatalf("symlink target changed: %q %v", data, err)
	}
}
