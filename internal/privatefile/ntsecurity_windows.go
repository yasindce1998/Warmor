//go:build windows

package privatefile

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// x/sys/windows does not currently wrap NtSetSecurityObject. Resolve the
// documented native API through its system-directory-only DLL loader, as with
// the other native handle operations in this package; never load from PATH.
var procNtSetSecurityObject = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtSetSecurityObject")

// setRecordingDACL changes only the validated handle's DACL. SetSecurityInfo
// must NOT be used here: its automatic inheritance conversion can rewrite child
// ACE flags even with exclusive sharing or MAXIMUM_ALLOWED. In particular, a
// private parent must not change ACLs on foreign-owned children, reparse targets,
// hardlink aliases, or unrelated siblings that have not been validated.
//
// NtSetSecurityObject issues the security update for this handle, without the
// Win32 inheritance propagation/tree walk. Only the DACL/protection is set; no
// owner, group, SACL, privilege adjustment, or pathname-based reopen is involved.
// Existing ownership and object-type checks precede this call, and the exact
// protected owner-only DACL is queried/verified afterward by protect.
// https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetsecurityobject
// https://learn.microsoft.com/windows/win32/secauthz/automatic-propagation-of-inheritable-aces
func setRecordingDACL(h windows.Handle, sd *windows.SECURITY_DESCRIPTOR) error {
	if err := procNtSetSecurityObject.Find(); err != nil {
		return fmt.Errorf("private recording requires NtSetSecurityObject: %w", err)
	}
	status, _, _ := procNtSetSecurityObject.Call(uintptr(h),
		uintptr(windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION), uintptr(unsafe.Pointer(sd)))
	runtime.KeepAlive(sd)
	// NTSTATUS, not GetLastError: all non-success statuses fail closed. There
	// is no fallback to an API that could traverse or mutate children.
	if status := windows.NTStatus(status); status != windows.STATUS_SUCCESS {
		return fmt.Errorf("set private recording DACL: %w", status)
	}
	return nil
}
