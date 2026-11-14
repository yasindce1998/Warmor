package policyserver

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func snapshotTestUserSID(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid.String()
}

// Windows mode bits do not encode a DACL. Production requires a private parent
// directory; give this fixture an explicit inheritable user/SYSTEM/admin DACL
// and verify that snapshot creation/replacement preserves that boundary.
func preparePrivateSnapshotDir(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + snapshotTestUserSID(t) + ")")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func assertPrivateSnapshot(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		t.Fatalf("snapshot has no private DACL: %v", err)
	}
	user := snapshotTestUserSID(t)
	userAllowed := false
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatalf("unexpected snapshot DACL entry type: %d", ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if sid != user && sid != "S-1-5-18" && sid != "S-1-5-32-544" {
			t.Fatalf("snapshot inherited access outside user/SYSTEM/administrators: %s", sid)
		}
		userAllowed = userAllowed || sid == user
	}
	if !userAllowed {
		t.Fatal("snapshot lost creating user's inherited access")
	}
}
