//go:build windows

package winutil

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// processNameNative asks QueryFullProcessImageName for the NT device path.
const processNameNative = 0x1

// LoadDriveDevices returns the drive letter → NT device mapping for every
// mounted drive, e.g. {"C:": `\Device\HarddiskVolume3`}.
func LoadDriveDevices() map[string]string {
	drives := make(map[string]string)
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return drives
	}
	buf := make([]uint16, windows.MAX_PATH)
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		drive := string(rune('A'+i)) + ":"
		name, err := windows.UTF16PtrFromString(drive)
		if err != nil {
			continue
		}
		n, err := windows.QueryDosDevice(name, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			continue
		}
		// The result is a NUL-separated list; the first entry is current.
		drives[drive] = windows.UTF16ToString(buf[:n])
	}
	return drives
}

// QueryImageNT returns the NT device path of a running process's image.
func QueryImageNT(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer func() { _ = windows.CloseHandle(h) }()

	buf := make([]uint16, 1024)
	for {
		size := uint32(len(buf))
		err := windows.QueryFullProcessImageName(h, processNameNative, &buf[0], &size)
		if err == nil {
			return windows.UTF16ToString(buf[:size]), nil
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || len(buf) >= 32768 {
			return "", err
		}
		buf = make([]uint16, len(buf)*4)
	}
}

// QueryCommandLine reads a running process's command line. Requires only
// PROCESS_QUERY_LIMITED_INFORMATION (Windows 8.1+).
func QueryCommandLine(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer func() { _ = windows.CloseHandle(h) }()

	size := uint32(4096)
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]byte, size)
		var ret uint32
		err := windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation,
			unsafe.Pointer(&buf[0]), uint32(len(buf)), &ret)
		if err == nil {
			us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
			if us.Length == 0 || us.Buffer == nil {
				return "", nil
			}
			chars := unsafe.Slice(us.Buffer, us.Length/2)
			return windows.UTF16ToString(chars), nil
		}
		if !errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) || ret <= size {
			return "", fmt.Errorf("NtQueryInformationProcess: %w", err)
		}
		size = ret
	}
	return "", fmt.Errorf("NtQueryInformationProcess: command line kept growing")
}

// ProcessCreateTime returns when a running process was created.
func ProcessCreateTime(pid uint32) (time.Time, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	return processHandleCreateTime(h)
}

func processHandleCreateTime(h windows.Handle) (time.Time, error) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, created.Nanoseconds()), nil
}

// SnapshotProcesses returns the processes running right now, so the process
// table is populated for processes started before the daemon.
func SnapshotProcesses(paths *DevicePathMap) ([]ProcInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return nil, fmt.Errorf("Process32First: %w", err)
	}

	var procs []ProcInfo
	for {
		info := ProcInfo{
			PID:  entry.ProcessID,
			PPID: entry.ParentProcessID,
			Comm: CommFromPath(windows.UTF16ToString(entry.ExeFile[:])),
		}
		// Protected and system processes refuse these queries; keep the
		// snapshot's file name in that case.
		if nt, err := QueryImageNT(info.PID); err == nil {
			info.NTImage = nt
			info.Image = paths.TranslateImage(nt)
			info.Comm = CommFromPath(nt)
		}
		if ct, err := ProcessCreateTime(info.PID); err == nil {
			info.CreateTime = ct
		}
		if cmd, err := QueryCommandLine(info.PID); err == nil {
			info.CmdLine = cmd
		}
		procs = append(procs, info)

		if err := windows.Process32Next(snap, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				return procs, nil
			}
			return procs, fmt.Errorf("Process32Next: %w", err)
		}
	}
}
