package compiler

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func openArtifact(path string, write bool) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	access := uint32(windows.GENERIC_READ)
	if write {
		access = windows.GENERIC_WRITE
	}
	h, err := windows.CreateFile(name, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	var info windows.ByHandleFileInformation
	kind, err := windows.GetFileType(h)
	if err == nil && kind != windows.FILE_TYPE_DISK {
		err = fmt.Errorf("wasm artifact must be a disk file")
	}
	if err == nil {
		err = windows.GetFileInformationByHandle(h, &info)
	}
	if err == nil && info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
		err = fmt.Errorf("wasm artifact must be a regular non-reparse file")
	}
	if err == nil && info.NumberOfLinks != 1 {
		err = fmt.Errorf("wasm artifact must be singly-linked (link count %d)", info.NumberOfLinks)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func checkArtifactLinkCount(f *os.File, _ os.FileInfo) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return err
	}
	if info.NumberOfLinks != 1 {
		return fmt.Errorf("wasm artifact must be singly-linked (link count %d)", info.NumberOfLinks)
	}
	return nil
}

func checkArtifactIdentity(path string, f *os.File, _ os.FileInfo) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// os.SameFile may lazily reopen a path with share=0 on Windows, which can
	// fail while our checked handle is open. Compare two sharing handles instead.
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	var current, opened windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &current); err != nil {
		return err
	}
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &opened); err != nil {
		return err
	}
	if current.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_DEVICE) != 0 ||
		current.NumberOfLinks != 1 || opened.NumberOfLinks != 1 ||
		current.VolumeSerialNumber != opened.VolumeSerialNumber || current.FileIndexHigh != opened.FileIndexHigh || current.FileIndexLow != opened.FileIndexLow {
		return fmt.Errorf("wasm artifact changed while opening or is not singly-linked")
	}
	return nil
}

// Windows cannot directory-fsync via os.File.Sync. As in agentstore and
// policyserver, replace existing files with a write-through move instead.
func replaceArtifact(from, to string) (bool, error) {
	src, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return false, err
	}
	dst, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return false, err
	}
	err = windows.MoveFileEx(src, dst, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
	// A write-through error can occur after the move. Conservatively classify
	// any error from this call as indeterminate, not proof the old file remains.
	return true, err
}
