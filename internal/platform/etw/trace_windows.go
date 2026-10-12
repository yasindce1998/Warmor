//go:build windows

package etw

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")

	procStartTraceW    = advapi32.NewProc("StartTraceW")
	procControlTraceW  = advapi32.NewProc("ControlTraceW")
	procEnableTraceEx2 = advapi32.NewProc("EnableTraceEx2")
	procOpenTraceW     = advapi32.NewProc("OpenTraceW")
	procProcessTrace   = advapi32.NewProc("ProcessTrace")
	procCloseTrace     = advapi32.NewProc("CloseTrace")
)

// Provider GUIDs.
var (
	// Microsoft-Windows-Kernel-Process {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
	processProviderGUID = windows.GUID{Data1: 0x22fb2cd6, Data2: 0x0e7b, Data3: 0x422b,
		Data4: [8]byte{0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}}

	// Microsoft-Windows-Kernel-File {EDD08927-9CC4-4E65-B970-C2560FB5C289}
	fileProviderGUID = windows.GUID{Data1: 0xedd08927, Data2: 0x9cc4, Data3: 0x4e65,
		Data4: [8]byte{0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89}}

	// Microsoft-Windows-Kernel-Network {7DD42A49-5329-4832-8DFD-43D979153A88}
	networkProviderGUID = windows.GUID{Data1: 0x7dd42a49, Data2: 0x5329, Data3: 0x4832,
		Data4: [8]byte{0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}}

	// Session GUID for the Warmor real-time session.
	// {6B1A3F52-8C1E-4D2B-9E47-57A3C0D9F1A4}
	sessionGUID = windows.GUID{Data1: 0x6b1a3f52, Data2: 0x8c1e, Data3: 0x4d2b,
		Data4: [8]byte{0x9e, 0x47, 0x57, 0xa3, 0xc0, 0xd9, 0xf1, 0xa4}}
)

func (p Provider) guid() windows.GUID {
	switch p {
	case ProviderProcess:
		return processProviderGUID
	case ProviderFile:
		return fileProviderGUID
	default:
		return networkProviderGUID
	}
}

const (
	wnodeFlagTracedGUID = 0x00020000

	eventTraceRealTimeMode = 0x00000100

	eventTraceControlStop = 1

	eventControlCodeEnableProvider = 1

	traceLevelInformation = 4

	processTraceModeRealTime    = 0x00000100
	processTraceModeEventRecord = 0x10000000

	invalidProcessTraceHandle = ^uint64(0)

	eventHeaderFlag32BitHeader = 0x0020
)

// wnodeHeader mirrors WNODE_HEADER.
type wnodeHeader struct {
	BufferSize        uint32
	ProviderID        uint32
	HistoricalContext uint64
	TimeStamp         int64
	GUID              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

// eventTraceProperties mirrors EVENT_TRACE_PROPERTIES (120 bytes on 64-bit).
type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      windows.Handle
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

// eventTraceHeader mirrors EVENT_TRACE_HEADER.
type eventTraceHeader struct {
	Size          uint16
	HeaderType    uint16
	Flags         uint16
	EventProperty uint16
	ThreadID      uint32
	ProcessID     uint32
	TimeStamp     int64
	GUID          windows.GUID
	ClientContext uint32
	Flags2        uint32
}

// eventTrace mirrors EVENT_TRACE.
type eventTrace struct {
	Header           eventTraceHeader
	InstanceID       uint32
	ParentInstanceID uint32
	ParentGUID       windows.GUID
	MofData          uintptr
	MofLength        uint32
	ClientContext    uint32
}

// traceLogfileHeader mirrors TRACE_LOGFILE_HEADER.
type traceLogfileHeader struct {
	BufferSize         uint32
	Version            uint32
	ProviderVersion    uint32
	NumberOfProcessors uint32
	EndTime            int64
	TimerResolution    uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	BuffersWritten     uint32
	StartBuffers       uint32
	PointerSize        uint32
	EventsLost         uint32
	CPUSpeedInMHz      uint32
	LoggerName         *uint16
	LogFileName        *uint16
	TimeZone           windows.Timezoneinformation
	BootTime           int64
	PerfFreq           int64
	StartTime          int64
	ReservedFlags      uint32
	BuffersLost        uint32
}

// eventTraceLogfile mirrors EVENT_TRACE_LOGFILEW.
type eventTraceLogfile struct {
	LogFileName         *uint16
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        eventTrace
	LogfileHeader       traceLogfileHeader
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	Context             uintptr
}

// eventDescriptor mirrors EVENT_DESCRIPTOR.
type eventDescriptor struct {
	ID      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

// eventHeader mirrors EVENT_HEADER.
type eventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadID        uint32
	ProcessID       uint32
	TimeStamp       int64
	ProviderID      windows.GUID
	EventDescriptor eventDescriptor
	ProcessorTime   uint64
	ActivityID      windows.GUID
}

// etwBufferContext mirrors ETW_BUFFER_CONTEXT.
type etwBufferContext struct {
	ProcessorNumber uint8
	Alignment       uint8
	LoggerID        uint16
}

// eventRecord mirrors EVENT_RECORD.
type eventRecord struct {
	EventHeader       eventHeader
	BufferContext     etwBufferContext
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          uintptr
	UserContext       uintptr
}

// newTraceProperties allocates EVENT_TRACE_PROPERTIES followed by room for
// the logger name, as StartTrace/ControlTrace require. StartTrace copies the
// name into that room itself.
func newTraceProperties(sessionName string) *eventTraceProperties {
	nameBytes := (len(sessionName) + 1) * 2
	size := unsafe.Sizeof(eventTraceProperties{}) + uintptr(nameBytes)
	buf := make([]byte, size)
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = uint32(size)
	props.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))
	return props
}

// startSession starts a real-time trace session. A session with the same
// name left behind by a crashed daemon (ETW sessions outlive their
// controller) is stopped and replaced.
func startSession(name string) (uint64, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}

	for attempt := 0; ; attempt++ {
		props := newTraceProperties(name)
		props.Wnode.Flags = wnodeFlagTracedGUID
		props.Wnode.ClientContext = 2 // system time: EVENT_HEADER.TimeStamp is a FILETIME
		props.Wnode.GUID = sessionGUID
		props.BufferSize = 64 // KB
		props.MinimumBuffers = 32
		props.MaximumBuffers = 256
		props.LogFileMode = eventTraceRealTimeMode
		props.FlushTimer = 1 // seconds

		var handle uint64
		ret, _, _ := procStartTraceW.Call(
			uintptr(unsafe.Pointer(&handle)),
			uintptr(unsafe.Pointer(namePtr)),
			uintptr(unsafe.Pointer(props)),
		)
		if ret == 0 {
			return handle, nil
		}
		if windows.Errno(ret) == windows.ERROR_ALREADY_EXISTS && attempt == 0 {
			if err := stopSessionByName(name); err != nil {
				return 0, fmt.Errorf("stop stale session %q: %w", name, err)
			}
			continue
		}
		return 0, fmt.Errorf("StartTrace(%q): %w", name, windows.Errno(ret))
	}
}

// stopSessionByName stops a trace session. A session that does not exist is
// not an error.
func stopSessionByName(name string) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	props := newTraceProperties(name)
	ret, _, _ := procControlTraceW.Call(
		0,
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(props)),
		eventTraceControlStop,
	)
	switch windows.Errno(ret) {
	case 0, windows.ERROR_WMI_INSTANCE_NOT_FOUND:
		return nil
	default:
		return fmt.Errorf("ControlTrace(stop %q): %w", name, windows.Errno(ret))
	}
}

// enableProvider enables a provider on a session.
func enableProvider(session uint64, guid windows.GUID, keywords uint64) error {
	ret, _, _ := procEnableTraceEx2.Call(
		uintptr(session),
		uintptr(unsafe.Pointer(&guid)),
		eventControlCodeEnableProvider,
		traceLevelInformation,
		uintptr(keywords), // MatchAnyKeyword
		0,                 // MatchAllKeyword
		0,                 // Timeout: asynchronous
		0,                 // EnableParameters
	)
	if ret != 0 {
		return fmt.Errorf("EnableTraceEx2: %w", windows.Errno(ret))
	}
	return nil
}

// openRealtimeTrace opens a consumer handle for a real-time session.
func openRealtimeTrace(name string, callback uintptr) (uint64, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	logfile := eventTraceLogfile{
		LoggerName:          namePtr,
		ProcessTraceMode:    processTraceModeRealTime | processTraceModeEventRecord,
		EventRecordCallback: callback,
	}
	handle, _, errno := procOpenTraceW.Call(uintptr(unsafe.Pointer(&logfile)))
	if uint64(handle) == invalidProcessTraceHandle {
		return 0, fmt.Errorf("OpenTrace(%q): %w", name, errno)
	}
	return uint64(handle), nil
}

// processTrace delivers events to the callback until the trace is closed or
// the session stops.
func processTrace(handle uint64) error {
	ret, _, _ := procProcessTrace.Call(uintptr(unsafe.Pointer(&handle)), 1, 0, 0)
	switch windows.Errno(ret) {
	case 0, windows.ERROR_CANCELLED:
		return nil
	default:
		return fmt.Errorf("ProcessTrace: %w", windows.Errno(ret))
	}
}

func closeTrace(handle uint64) error {
	ret, _, _ := procCloseTrace.Call(uintptr(handle))
	switch err := windows.Errno(ret); {
	case ret == 0, errors.Is(err, windows.ERROR_CTX_CLOSE_PENDING):
		return nil
	default:
		return fmt.Errorf("CloseTrace: %w", err)
	}
}
