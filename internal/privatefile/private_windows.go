//go:build windows

package privatefile

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows recordings deliberately support only local, fixed NTFS volumes. In
// particular, neither chmod nor a pathname-based ACL update is a substitute for
// the Unix descriptor contract. All components are opened relative to checked
// directory handles, all reparse points are rejected, and security is installed
// on the same handle that was validated, before returning an append handle.
// Administrators/backup privileges, like Unix root, are outside this boundary.

const (
	fileAllAccess       = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff
	fileDeleteChild     = 0x40
	fileAddFile         = windows.FILE_WRITE_DATA
	fileAddSubdirectory = windows.FILE_APPEND_DATA
)

type recordingSecurity struct {
	user *windows.SID
	sd   *windows.SECURITY_DESCRIPTOR
	// x/sys v0.43.0 SetDACL/SetOwner install Go pointers through Windows,
	// without Go write barriers (go.dev/issue/73199). Keep explicit typed
	// references in this bundle before invoking either setter, and keep the
	// entire bundle alive through every native use of the absolute descriptor.
	acl *windows.ACL
}

func currentSecurity() (*recordingSecurity, error) {
	u, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: fileAllAccess,
		AccessMode:        windows.SET_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(u.User.Sid),
		},
	}}, nil)
	if err != nil {
		return nil, err
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	s := &recordingSecurity{user: u.User.Sid, sd: sd, acl: acl}
	defer runtime.KeepAlive(s)
	if err = s.sd.SetOwner(s.user, false); err != nil {
		return nil, err
	}
	if err = s.sd.SetDACL(s.acl, true, false); err != nil {
		return nil, err
	}
	if err = s.sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return nil, err
	}
	return s, nil
}

// recordingPath excludes device/UNC namespaces, drive-relative paths, alternate
// data streams and Win32-normalized aliases before any filesystem mutation.
func recordingPath(path string) (string, []string, error) {
	path = filepath.FromSlash(path)
	if path == "" || strings.HasPrefix(path, `\\`) || (filepath.VolumeName(path) != "" && !filepath.IsAbs(path)) {
		return "", nil, fmt.Errorf("recording requires a local drive path")
	}
	// Check even components which Abs/Clean would otherwise discard.
	for _, part := range strings.Split(strings.TrimPrefix(path, filepath.VolumeName(path)), `\`) {
		if part != "" && part != "." && part != ".." && !safeComponent(part) {
			return "", nil, fmt.Errorf("unsafe recording path component")
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", nil, err
	}
	vol := filepath.VolumeName(abs)
	if len(vol) != 2 || vol[1] != ':' || len(abs) <= 3 {
		return "", nil, fmt.Errorf("recording requires a local drive file path")
	}
	parts := strings.Split(abs[3:], `\`)
	for _, part := range parts {
		if !safeComponent(part) {
			return "", nil, fmt.Errorf("unsafe recording path component")
		}
	}
	return abs[:3], parts, nil
}

func safeComponent(name string) bool {
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) ||
		strings.ContainsAny(name, "\\/:*?\"<>|") || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return false
	}
	for _, c := range name {
		if c < 32 { // Win32 forbids NUL and the remaining ASCII control characters.
			return false
		}
	}
	// Do not delegate device-name policy to filepath.IsLocal: newer Windows
	// releases allow some reserved bases with extensions. Recordings must be
	// unambiguous to Win32 readers on every supported release, not just NT opens.
	base, _, _ := strings.Cut(name, ".")
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return false
	}
	if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
		switch base[3:] {
		case "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
			return false
		}
	}
	return true
}

func openRelative(parent windows.Handle, name string, access, disposition, options, share uint32, security *recordingSecurity) (windows.Handle, error) {
	n, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	oa := windows.OBJECT_ATTRIBUTES{
		RootDirectory: parent, ObjectName: n,
		Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	if security != nil {
		oa.SecurityDescriptor = security.sd
	}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var h windows.Handle
	err = windows.NtCreateFile(&h, access|windows.SYNCHRONIZE, &oa, &windows.IO_STATUS_BLOCK{}, nil,
		windows.FILE_ATTRIBUTE_NORMAL, share, disposition,
		options|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	// Older Windows versions/filesystems which cannot enforce these flags fail
	// closed: do not retry without the no-reparse guarantee.
	runtime.KeepAlive(security)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return h, nil
}

func handleInfo(h windows.Handle, dir bool) (*windows.ByHandleFileInformation, error) {
	typ, err := windows.GetFileType(h)
	if err != nil || typ != windows.FILE_TYPE_DISK {
		return nil, fmt.Errorf("recording must be a disk file/directory: %v", err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE) != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != dir || (!dir && info.NumberOfLinks != 1) {
		return nil, fmt.Errorf("recording requires a non-reparse directory or singly-linked regular file")
	}
	return &info, nil
}

func ownerDescriptor(h windows.Handle) (*windows.SECURITY_DESCRIPTOR, *windows.SID, error) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, nil, err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		return nil, nil, fmt.Errorf("cannot establish recording owner: %v", err)
	}
	return sd, owner, nil
}

func (s *recordingSecurity) protect(h windows.Handle) error {
	_, owner, err := ownerDescriptor(h)
	if err != nil {
		return err
	}
	if !windows.EqualSid(owner, s.user) {
		return fmt.Errorf("recording is not owned by current user")
	}
	if err := s.setRecordingDACL(h); err != nil {
		return err
	}
	// Fail closed on filesystems which ignore protection or ACL replacement.
	sd, owner, err := ownerDescriptor(h)
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 || !windows.EqualSid(owner, s.user) {
		return fmt.Errorf("recording ACL protection not established: %v", err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 1 {
		return fmt.Errorf("recording must have an owner-only DACL: %v", err)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &ace); err != nil {
		return err
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 ||
		ace.Mask != fileAllAccess || !windows.EqualSid((*windows.SID)(unsafe.Pointer(&ace.SidStart)), s.user) {
		return fmt.Errorf("recording DACL is not owner-only")
	}
	return nil
}

func (s *recordingSecurity) trusted(sid *windows.SID) bool {
	// These are the Windows equivalents of trusted root-owned ancestors; they
	// are never accepted as owners of a recording or private store directory.
	return windows.EqualSid(sid, s.user) || sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		sid.String() == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" // TrustedInstaller
}

func (s *recordingSecurity) checkDirectory(h windows.Handle, leaf bool) error {
	sd, owner, err := ownerDescriptor(h)
	if err != nil {
		return err
	}
	if !s.trusted(owner) {
		return fmt.Errorf("untrusted recording directory owner")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return fmt.Errorf("untrusted recording directory DACL: %v", err)
	}
	// Shared ancestors may allow creation (as with Unix sticky /tmp), but not
	// deletion/replacement of other users' children or modification of the
	// ancestor itself. The leaf must also forbid foreign child creation.
	unsafeRights := windows.ACCESS_MASK(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
		fileDeleteChild | windows.FILE_WRITE_ATTRIBUTES | windows.FILE_WRITE_EA | windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.MAXIMUM_ALLOWED)
	if leaf {
		unsafeRights |= fileAddFile | fileAddSubdirectory
	}
	for i := uint16(0); i < acl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, uint32(i), &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		// Conditional/object/callback ACEs cannot be interpreted as simple
		// grants. Reject instead of guessing about their effective access.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("unsupported recording directory ACE")
		}
		if ace.Mask&unsafeRights != 0 && !s.trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return fmt.Errorf("recording directory is writable by another principal")
		}
	}
	return nil
}

func closeDirectories(handles []windows.Handle) {
	for i := len(handles) - 1; i >= 0; i-- {
		_ = windows.CloseHandle(handles[i])
	}
}

func (s *recordingSecurity) directory(root string, parts []string, privateLeaf, create bool) (_ []windows.Handle, err error) {
	root16, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return nil, err
	}
	if windows.GetDriveType(root16) != windows.DRIVE_FIXED {
		return nil, fmt.Errorf("recording requires a fixed local NTFS volume")
	}
	access := uint32(windows.FILE_LIST_DIRECTORY | windows.FILE_TRAVERSE | windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL)
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE) // pin every ancestor against rename/deletion
	h, err := openRelative(0, `\??\`+root, access, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, share, nil)
	if err != nil {
		return nil, err
	}
	handles := []windows.Handle{h}
	defer func() {
		if err != nil {
			closeDirectories(handles)
		}
	}()
	var flags uint32
	var fs [32]uint16
	if err = windows.GetVolumeInformationByHandle(h, nil, 0, nil, nil, &flags, &fs[0], uint32(len(fs))); err != nil {
		return nil, err
	}
	if flags&windows.FILE_PERSISTENT_ACLS == 0 || windows.UTF16ToString(fs[:]) != "NTFS" {
		return nil, fmt.Errorf("recording requires NTFS persistent ACLs")
	}
	if _, err = handleInfo(h, true); err != nil {
		return nil, err
	}
	if err = s.checkDirectory(h, len(parts) == 0); err != nil {
		return nil, err
	}
	for i, part := range parts {
		leaf := i == len(parts)-1
		a := access
		if leaf && privateLeaf {
			a |= windows.WRITE_DAC
		}
		next, openErr := openRelative(h, part, a, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, share, nil)
		if openErr == windows.STATUS_OBJECT_NAME_NOT_FOUND && create {
			next, openErr = openRelative(h, part, a, windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE, share, s)
			if openErr == windows.STATUS_OBJECT_NAME_COLLISION {
				next, openErr = openRelative(h, part, a, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, share, nil)
			}
		}
		if openErr != nil {
			return nil, openErr
		}
		handles = append(handles, next)
		h = next
		if _, err = handleInfo(h, true); err != nil {
			return nil, err
		}
		if leaf && privateLeaf {
			err = s.protect(h)
		} else {
			err = s.checkDirectory(h, leaf)
		}
		if err != nil {
			return nil, err
		}
	}
	return handles, nil
}

// OpenAppend creates files with a protected owner-only DACL atomically, or
// tightens an existing, current-user-owned singly-linked file by handle. The
// returned handle has FILE_APPEND_DATA but not FILE_WRITE_DATA, so seeks cannot
// turn appends into overwrites. No pathname-based reopening follows validation.
func OpenAppend(path string, privateDir, createDirs bool) (*os.File, error) {
	// An impersonation token is thread-local; keep identity and access checks
	// on the same OS thread for the entire operation.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	root, parts, err := recordingPath(path)
	if err != nil {
		return nil, err
	}
	s, err := currentSecurity()
	if err != nil {
		return nil, err
	}
	dirs, err := s.directory(root, parts[:len(parts)-1], privateDir, createDirs)
	if err != nil {
		return nil, err
	}
	defer closeDirectories(dirs)
	access := uint32(windows.FILE_GENERIC_WRITE&^windows.FILE_WRITE_DATA | windows.FILE_READ_ATTRIBUTES | windows.WRITE_DAC)
	h, err := openRelative(dirs[len(dirs)-1], parts[len(parts)-1], access, windows.FILE_OPEN_IF,
		windows.FILE_NON_DIRECTORY_FILE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, s)
	if err != nil {
		return nil, err
	}
	if _, err = handleInfo(h, false); err == nil {
		err = s.protect(h)
	}
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

// Rotate checks the supplied descriptor against a no-follow, directory-relative
// source handle and renames that handle within the checked directory. Windows
// performs the destination nonexistence check atomically (ReplaceIfExists=0).
func Rotate(path, archive string, file *os.File) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	root, parts, err := recordingPath(path)
	if err != nil {
		return err
	}
	aroot, aparts, err := recordingPath(archive)
	if err != nil {
		return err
	}
	if !strings.EqualFold(root, aroot) || !strings.EqualFold(strings.Join(parts[:len(parts)-1], `\`), strings.Join(aparts[:len(aparts)-1], `\`)) {
		return fmt.Errorf("archive must share recording directory")
	}
	s, err := currentSecurity()
	if err != nil {
		return err
	}
	dirs, err := s.directory(root, parts[:len(parts)-1], false, false)
	if err != nil {
		return err
	}
	defer closeDirectories(dirs)
	dir := dirs[len(dirs)-1]
	// DELETE is requested only for the rename handle, not the returned append
	// handle: normal Windows readers do not share DELETE access.
	h, err := openRelative(dir, parts[len(parts)-1], windows.DELETE|windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	expected, err := handleInfo(windows.Handle(file.Fd()), false)
	if err != nil {
		return err
	}
	actual, err := handleInfo(h, false)
	if err != nil {
		return err
	}
	if actual.VolumeSerialNumber != expected.VolumeSerialNumber || actual.FileIndexHigh != expected.FileIndexHigh || actual.FileIndexLow != expected.FileIndexLow {
		return fmt.Errorf("active recording path changed")
	}
	if err := s.protect(h); err != nil {
		return err
	}
	name, err := windows.UTF16FromString(aparts[len(aparts)-1])
	if err != nil {
		return err
	}
	// Native FILE_RENAME_INFORMATION layout, including pointer-size alignment.
	type renameInformation struct {
		ReplaceIfExists uint32
		RootDirectory   windows.Handle
		FileNameLength  uint32
		FileName        [1]uint16
	}
	size := int(unsafe.Sizeof(renameInformation{})) + 2*(len(name)-1)
	buf := make([]byte, size)
	rename := (*renameInformation)(unsafe.Pointer(&buf[0]))
	rename.RootDirectory = dir
	rename.FileNameLength = uint32(2 * (len(name) - 1))
	copy(unsafe.Slice(&rename.FileName[0], len(name)-1), name[:len(name)-1])
	return windows.NtSetInformationFile(h, &windows.IO_STATUS_BLOCK{}, &buf[0], uint32(size), windows.FileRenameInformation)
}
