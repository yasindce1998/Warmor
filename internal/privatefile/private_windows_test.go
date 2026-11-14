//go:build windows

package privatefile

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func assertOwnerDACL(t *testing.T, path string) {
	t.Helper()
	s, err := currentSecurity()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || !windows.EqualSid(owner, s.user) {
		t.Fatalf("owner = %v, want current user: %v", owner, err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("DACL is not protected: %v", err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 1 {
		t.Fatalf("expected one owner ACE: %v", err)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Mask != fileAllAccess ||
		!windows.EqualSid((*windows.SID)(unsafe.Pointer(&ace.SidStart)), s.user) {
		t.Fatalf("unexpected recording ACL: %s", sd.String())
	}
}

func securityString(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

// Explicitly assign fixture ownership rather than relying on an elevated
// runner's configurable default owner (which can be Administrators).
func ownedFixture(t *testing.T, path string) {
	t.Helper()
	s, err := currentSecurity()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, s.user, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsOpenAppendOwnerDACL(t *testing.T) {
	parent := t.TempDir()
	before := securityString(t, parent)
	store := filepath.Join(parent, "store")
	path := filepath.Join(store, "events")
	f, err := OpenAppend(path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	assertOwnerDACL(t, store)
	assertOwnerDACL(t, path)
	if _, err := f.WriteString("first"); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	// FILE_APPEND_DATA without FILE_WRITE_DATA must append even after Seek.
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("second"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "firstsecond" {
		t.Fatalf("append changed prior data: %q %v", data, err)
	}
	if securityString(t, parent) != before {
		t.Fatal("modified parent ACL")
	}
}

func TestWindowsOpenAppendTightensExistingOwnerDACL(t *testing.T) {
	parent := t.TempDir()
	store := filepath.Join(parent, "store")
	if err := os.Mkdir(store, 0755); err != nil {
		t.Fatal(err)
	}
	ownedFixture(t, store)
	path := filepath.Join(store, "events")
	if err := os.WriteFile(path, []byte("legacy"), 0644); err != nil {
		t.Fatal(err)
	}
	ownedFixture(t, path)
	// An explicit Everyone read grant must be removed, not merged.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;OW)(A;OICI;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{store, path} {
		if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
			t.Fatal(err)
		}
	}
	sibling := filepath.Join(store, "unrelated")
	if err := os.WriteFile(sibling, []byte("untouched"), 0644); err != nil {
		t.Fatal(err)
	}
	siblingSecurity := securityString(t, sibling)
	f, err := OpenAppend(path, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	assertOwnerDACL(t, store)
	assertOwnerDACL(t, path)
	if securityString(t, sibling) != siblingSecurity {
		t.Fatal("private store tightening changed unrelated child ACL")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "legacy" {
		t.Fatalf("legacy data changed: %q %v", data, err)
	}
}

func requireInheritedDACL(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatalf("missing inherited fixture DACL: %v", err)
	}
	for i := uint16(0); i < acl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, uint32(i), &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return
		}
	}
	t.Fatalf("fixture did not exercise inherited ACE metadata: %s", sd.String())
}

func TestWindowsPrivateDirectoryPreservesInheritedChildACLs(t *testing.T) {
	root := t.TempDir()
	store := filepath.Join(root, "store")
	if err := os.Mkdir(store, 0700); err != nil {
		t.Fatal(err)
	}
	ownedFixture(t, store)
	// Install inherited owner/full and Everyone/read grants before creating
	// descendants. Do not protect the children: the native CI failure was an
	// inherited-to-explicit metadata conversion, not a change in access masks.
	s, err := currentSecurity()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + s.user.String() + ")(A;OICI;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(store, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(store, "unrelated")
	nested := filepath.Join(store, "nested")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	grandchild := filepath.Join(nested, "unrelated")
	for _, path := range []string{child, grandchild} {
		if err := os.WriteFile(path, []byte("keep"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	before := map[string]string{}
	for _, path := range []string{child, nested, grandchild} {
		requireInheritedDACL(t, path)
		before[path] = securityString(t, path)
	}
	// An inherited child with an alias outside the store must not have its
	// ACL changed via an implicit walk before its link count can be checked.
	alias := filepath.Join(root, "outside-alias")
	if err := os.Link(child, alias); err != nil {
		t.Fatal(err)
	}
	before[alias] = securityString(t, alias)
	for i := 0; i < 2; i++ {
		f, err := OpenAppend(filepath.Join(store, "events"), true, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		assertOwnerDACL(t, store)
		for path, want := range before {
			if got := securityString(t, path); got != want {
				t.Fatalf("private directory update changed child %s:\nbefore: %s\nafter:  %s", path, want, got)
			}
		}
	}
}

func TestWindowsOpenAppendRejectsUnsafePaths(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	ownedFixture(t, target)
	before := securityString(t, target)
	hard := filepath.Join(dir, "hard")
	if err := os.Link(target, hard); err != nil {
		t.Fatal(err)
	}
	directoryFile := filepath.Join(dir, "directory")
	if err := os.Mkdir(directoryFile, 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{target, hard, directoryFile, target + ":stream", target + ".", target + " ",
		`\\.\NUL`, `\\?\` + target, `\\localhost\c$\events`, filepath.Join(dir, "NUL"), filepath.Join(dir, "NUL.txt"), filepath.Join(dir, "COM1.txt")} {
		t.Run(path, func(t *testing.T) {
			if f, err := OpenAppend(path, false, false); err == nil {
				_ = f.Close()
				t.Fatal("accepted unsafe recording")
			}
		})
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "keep" || securityString(t, target) != before {
		t.Fatalf("rejected alias changed target: %q %v", data, err)
	}
}

func TestWindowsOpenAppendRejectsReparsePoints(t *testing.T) {
	dir := t.TempDir()
	ownedFixture(t, dir)
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	requireInheritedDACL(t, target)
	before := securityString(t, target)
	link := filepath.Join(dir, "link")
	// Windows CI is elevated. Do not skip this security check on a runner
	// lacking symlink support; that runner has not validated the contract.
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(dir, "junction")
	createJunction(t, junction, dir)
	for _, path := range []string{link, filepath.Join(alias, "new"), filepath.Join(alias, "nested", "new"), filepath.Join(junction, "new")} {
		if f, err := OpenAppend(path, true, true); err == nil {
			_ = f.Close()
			t.Fatalf("accepted reparse point %s", path)
		}
		if after := securityString(t, target); after != before {
			t.Fatalf("rejected %q changed target ACL:\nbefore: %s\nafter:  %s", path, before, after)
		}
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "keep" {
		t.Fatalf("reparse target changed: %q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "nested")); !os.IsNotExist(err) {
		t.Fatalf("created directory through reparse point: %v", err)
	}
}

// Build a mount-point reparse record through the Windows API, not cmd/mklink or
// PowerShell. This exercises a reparse tag other than IO_REPARSE_TAG_SYMLINK.
func createJunction(t *testing.T, path, target string) {
	t.Helper()
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	substitute, err := windows.UTF16FromString(`\??\` + target)
	if err != nil {
		t.Fatal(err)
	}
	printName, err := windows.UTF16FromString(target)
	if err != nil {
		t.Fatal(err)
	}
	// REPARSE_DATA_BUFFER header (8 bytes), mount-point name offsets (8
	// bytes), followed by NUL-terminated substitute and print UTF-16 names.
	buf := make([]byte, 16+2*(len(substitute)+len(printName)))
	binary.LittleEndian.PutUint32(buf, windows.IO_REPARSE_TAG_MOUNT_POINT)
	binary.LittleEndian.PutUint16(buf[4:], uint16(len(buf)-8))
	binary.LittleEndian.PutUint16(buf[10:], uint16(2*(len(substitute)-1)))
	binary.LittleEndian.PutUint16(buf[12:], uint16(2*len(substitute)))
	binary.LittleEndian.PutUint16(buf[14:], uint16(2*(len(printName)-1)))
	for i, c := range append(substitute, printName...) {
		binary.LittleEndian.PutUint16(buf[16+2*i:], c)
	}
	var returned uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &buf[0], uint32(len(buf)), nil, 0, &returned, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
	})
}

func TestWindowsOpenAppendRejectsForeignOwnership(t *testing.T) {
	// A normal owner can assign an object to an owner-capable group in its
	// token. Hosted CI is elevated, so Administrators provides a real foreign
	// owner fixture without enabling privileges or changing host policy.
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "directory"}[directory], func(t *testing.T) {
			dir := t.TempDir()
			ownedFixture(t, dir)
			path := filepath.Join(dir, "foreign")
			if directory {
				err = os.Mkdir(path, 0700)
			} else {
				err = os.WriteFile(path, []byte("keep"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			ownedFixture(t, path)
			t.Cleanup(func() { ownedFixture(t, path) })
			if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admin, nil, nil, nil); err != nil {
				t.Fatal(err)
			}
			requireInheritedDACL(t, path)
			before := securityString(t, path)
			filePath := path
			if directory {
				filePath = filepath.Join(path, "events")
			}
			if f, err := OpenAppend(filePath, true, false); err == nil {
				_ = f.Close()
				t.Fatal("accepted foreign owner")
			}
			if after := securityString(t, path); after != before {
				t.Fatalf("changed foreign-owned ACL:\nbefore: %s\nafter:  %s", before, after)
			}
			if !directory {
				if data, err := os.ReadFile(path); err != nil || string(data) != "keep" {
					t.Fatalf("changed foreign-owned contents: %q %v", data, err)
				}
			}
		})
	}
}

func TestWindowsOpenAppendRejectsWritableAncestors(t *testing.T) {
	dir := t.TempDir()
	shared := filepath.Join(dir, "shared")
	if err := os.Mkdir(shared, 0700); err != nil {
		t.Fatal(err)
	}
	ownedFixture(t, shared)
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;OW)(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(shared, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	before := securityString(t, shared)
	if f, err := OpenAppend(filepath.Join(shared, "private", "events"), true, true); err == nil {
		_ = f.Close()
		t.Fatal("accepted writable ancestor")
	}
	if securityString(t, shared) != before {
		t.Fatal("changed ancestor ACL")
	}
	if _, err := os.Stat(filepath.Join(shared, "private")); !os.IsNotExist(err) {
		t.Fatalf("created path under unsafe ancestor: %v", err)
	}
}

func TestWindowsRotateChecksDescriptorAndNeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events")
	f, err := OpenAppend(path, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString("original"); err != nil {
		t.Fatal(err)
	}
	archive := path + ".1"
	if err := os.WriteFile(archive, []byte("archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Rotate(path, archive, f); err == nil {
		t.Fatal("overwrote archive")
	}
	if data, err := os.ReadFile(archive); err != nil || string(data) != "archive" {
		t.Fatalf("archive changed: %q %v", data, err)
	}
	if err := Rotate(path, path+".2", f); err != nil {
		t.Fatal(err)
	}
	assertOwnerDACL(t, path+".2")
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	before := securityString(t, path)
	if err := Rotate(path, path+".3", f); err == nil {
		t.Fatal("rotated replacement instead of descriptor")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "replacement" || securityString(t, path) != before {
		t.Fatalf("replacement changed: %q %v", data, err)
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Fatalf("created archive for mismatched descriptor: %v", err)
	}
}

func TestWindowsPathValidation(t *testing.T) {
	for _, path := range []string{`C:\store\events`, `C:/store/events`} {
		root, parts, err := recordingPath(path)
		if err != nil || root != `C:\` || !reflect.DeepEqual(parts, []string{"store", "events"}) {
			t.Fatalf("path parse: %q %v %v", root, parts, err)
		}
	}
	for _, path := range []string{"", `C:events`, `\\server\share\events`, `\\?\C:\events`, `C:\events:secret`, `C:\events.\..\secret`, `C:\NUL.txt`, `C:\store\events `} {
		if _, _, err := recordingPath(path); err == nil {
			t.Fatalf("accepted ambiguous/unsafe path %q", path)
		}
	}
}

func TestWindowsReservedNamesRejectedBeforeFilesystemMutation(t *testing.T) {
	dir := t.TempDir()
	rootSecurity := securityString(t, dir)
	names := []string{"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
	for _, prefix := range []string{"COM", "LPT"} {
		for _, digit := range []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"} {
			names = append(names, prefix+digit)
		}
	}
	for _, base := range names {
		for _, name := range []string{base, strings.ToLower(base) + ".txt", base + ".tar.gz", base + " .log", base + ".", base + " "} {
			t.Run(name, func(t *testing.T) {
				for _, path := range []string{filepath.Join(dir, name), filepath.Join(dir, name, "events")} {
					if _, _, err := recordingPath(path); err == nil {
						t.Fatalf("accepted reserved component %q", path)
					}
					if f, err := OpenAppend(path, true, true); err == nil {
						_ = f.Close()
						t.Fatalf("opened reserved component %q", path)
					}
				}
			})
		}
	}
	for _, name := range []string{"file\x00suffix", "file\x01suffix", "file\x1fsuffix", "file\xff", "file.", "file ", "file:stream"} {
		path := filepath.Join(dir, name)
		if _, _, err := recordingPath(path); err == nil {
			t.Fatalf("accepted invalid Win32 component %q", path)
		}
		if f, err := OpenAppend(path, true, true); err == nil {
			_ = f.Close()
			t.Fatalf("opened invalid Win32 component %q", path)
		}
	}
	// No invalid name can create a private parent or even tighten the root.
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("rejected names mutated fixture: %v %v", entries, err)
	}
	if after := securityString(t, dir); after != rootSecurity {
		t.Fatalf("rejected names changed fixture ACL:\nbefore: %s\nafter:  %s", rootSecurity, after)
	}
	for _, name := range []string{"events.ndjson", ".events", "COM10.txt", "LPT10", "CONSOLE", "NUL-data", "雪.log"} {
		if !safeComponent(name) {
			t.Fatalf("rejected ordinary recording name %q", name)
		}
	}
}

func TestWindowsHandleInfoRejectsSpecialFiles(t *testing.T) {
	var read, write windows.Handle
	if err := windows.CreatePipe(&read, &write, nil, 0); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(read) }()
	defer func() { _ = windows.CloseHandle(write) }()
	if _, err := handleInfo(write, false); err == nil {
		t.Fatal("accepted pipe as a regular recording")
	}
}

func TestWindowsDirectoryHandlesPinAncestors(t *testing.T) {
	rootDir := t.TempDir()
	parent := filepath.Join(rootDir, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := currentSecurity()
	if err != nil {
		t.Fatal(err)
	}
	root, parts, err := recordingPath(filepath.Join(parent, "events"))
	if err != nil {
		t.Fatal(err)
	}
	handles, err := s.directory(root, parts[:len(parts)-1], false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDirectories(handles)
	if err := os.Rename(parent, parent+".moved"); err == nil {
		t.Fatal("directory could be swapped while handles were checked")
	}
}

func TestWindowsSecurityBundleSurvivesConcurrentGC(t *testing.T) {
	// Native SetDACL/SetOwner in the pinned x/sys version do not issue Go
	// write barriers. Force marking while bundles are constructed and used,
	// including creation before protect can replace an incorrectly created ACL.
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-stop:
				return
			default:
				runtime.GC()
			}
		}
	}()
	defer func() {
		close(stop)
		<-stopped
	}()
	t.Run("workers", func(t *testing.T) {
		for worker := 0; worker < 4; worker++ {
			t.Run(strconv.Itoa(worker), func(t *testing.T) {
				t.Parallel()
				parent := t.TempDir()
				for iteration := 0; iteration < 16; iteration++ {
					exerciseWindowsSecurityBundle(t, filepath.Join(parent, strconv.Itoa(iteration), "events"))
				}
			})
		}
	})
}

func exerciseWindowsSecurityBundle(t *testing.T, path string) {
	t.Helper()
	s, err := currentSecurity()
	if err != nil {
		t.Fatal(err)
	}
	// A forced completed cycle between construction and native use also tests
	// that the descriptor is not its ACL/SID's only remaining GC reference.
	runtime.GC()
	root, parts, err := recordingPath(path)
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := s.directory(root, parts[:len(parts)-1], true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDirectories(dirs)
	h, err := openRelative(dirs[len(dirs)-1], parts[len(parts)-1],
		windows.FILE_APPEND_DATA|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_CREATE, windows.FILE_NON_DIRECTORY_FILE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, s)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	// This check deliberately precedes the hardening call: a stale ACL at
	// creation must not be hidden by a subsequent correct NtSetSecurityObject.
	assertOwnerDACL(t, path)
	assertOwnerDACL(t, filepath.Dir(path))
	runtime.GC()
	if err := s.protect(h); err != nil {
		t.Fatal(err)
	}
	assertOwnerDACL(t, path)
}
