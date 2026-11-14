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
	defer func() { _ = store.Close() }()
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

func permissiveWindowsDailyFixture(t *testing.T, path string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte("legacy secret\n"), 0644); err != nil {
		t.Fatal(err)
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, u.User.Sid, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;OW)(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	return windowsDailySecurity(t, path)
}

func windowsDailySecurity(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

func TestWindowsEventStoreSecuresCaseVariantLegacyDays(t *testing.T) {
	dir := recordingTempDir(t)
	recordings := []string{
		"Events-2001-01-01.ndjson", "EVENTS-2001-01-02.NDJSON", "eVeNtS-2001-01-03.NdJsOn",
		"EVENTS-" + time.Now().UTC().Format("2006-01-02") + ".NDJSON",
	}
	for _, name := range recordings {
		permissiveWindowsDailyFixture(t, filepath.Join(dir, name))
	}
	// Neither invalid dates nor unrelated files are recording migrations.
	unrelated := map[string]string{}
	for _, name := range []string{"EVENTS-2001-02-30.NDJSON", "EVENTS-not-a-date.NDJSON", "notes.NDJSON"} {
		path := filepath.Join(dir, name)
		unrelated[path] = permissiveWindowsDailyFixture(t, path)
	}
	store, err := NewEventStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	assertWindowsRecordingPrivate(t, dir)
	for _, name := range recordings {
		path := filepath.Join(dir, name)
		assertWindowsRecordingPrivate(t, path)
		if data, err := os.ReadFile(path); err != nil || string(data) != "legacy secret\n" {
			t.Fatalf("legacy daily recording changed: %q %v", data, err)
		}
	}
	for path, before := range unrelated {
		if after := windowsDailySecurity(t, path); after != before {
			t.Fatalf("changed unrelated child ACL: before %s, after %s", before, after)
		}
	}
}

func TestWindowsEventStoreRejectsCaseVariantLinkedDays(t *testing.T) {
	for name, link := range map[string]func(string, string) error{"symlink": os.Symlink, "hardlink": os.Link} {
		t.Run(name, func(t *testing.T) {
			root := recordingTempDir(t)
			dir := filepath.Join(root, "store")
			store, err := NewEventStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, "target")
			before := permissiveWindowsDailyFixture(t, target)
			if err := link(target, filepath.Join(dir, "EVENTS-2001-01-01.NDJSON")); err != nil {
				t.Fatal(err)
			}
			if reopened, err := NewEventStore(dir); err == nil {
				_ = reopened.Close()
				t.Fatal("accepted case-variant linked daily recording")
			}
			if after := windowsDailySecurity(t, target); after != before {
				t.Fatalf("changed linked target ACL: before %s, after %s", before, after)
			}
			if data, err := os.ReadFile(target); err != nil || string(data) != "legacy secret\n" {
				t.Fatalf("linked target changed: %q %v", data, err)
			}
		})
	}
}
