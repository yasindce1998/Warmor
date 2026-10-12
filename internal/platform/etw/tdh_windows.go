//go:build windows

package etw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	tdh = windows.NewLazySystemDLL("tdh.dll")

	procTdhGetPropertySize = tdh.NewProc("TdhGetPropertySize")
	procTdhGetProperty     = tdh.NewProc("TdhGetProperty")
)

// propertyDataDescriptor mirrors PROPERTY_DATA_DESCRIPTOR.
type propertyDataDescriptor struct {
	PropertyName uint64 // LPCWSTR
	ArrayIndex   uint32
	Reserved     uint32
}

const noArrayIndex = 0xFFFFFFFF

var errNoProperty = errors.New("property not present")

// propertyNames caches UTF-16 property names so the hot path does not
// allocate a new one per event.
var propertyNames sync.Map // string → *uint16

func propertyName(name string) *uint16 {
	if v, ok := propertyNames.Load(name); ok {
		if p, ok := v.(*uint16); ok {
			return p
		}
	}
	p, _ := windows.UTF16PtrFromString(name)
	propertyNames.Store(name, p)
	return p
}

// propBytes returns the raw bytes of a top-level property, decoded with the
// schema the provider registered (its manifest), so field order and sizes
// never have to be hard-coded.
func propBytes(rec *eventRecord, name string) ([]byte, error) {
	namePtr := propertyName(name)
	desc := propertyDataDescriptor{
		PropertyName: uint64(uintptr(unsafe.Pointer(namePtr))),
		ArrayIndex:   noArrayIndex,
	}

	var size uint32
	ret, _, _ := procTdhGetPropertySize.Call(
		uintptr(unsafe.Pointer(rec)),
		0, 0,
		1, uintptr(unsafe.Pointer(&desc)),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret != 0 {
		if windows.Errno(ret) == windows.ERROR_NOT_FOUND {
			return nil, errNoProperty
		}
		return nil, fmt.Errorf("TdhGetPropertySize(%s): %w", name, windows.Errno(ret))
	}
	if size == 0 {
		return nil, nil
	}

	buf := make([]byte, size)
	ret, _, _ = procTdhGetProperty.Call(
		uintptr(unsafe.Pointer(rec)),
		0, 0,
		1, uintptr(unsafe.Pointer(&desc)),
		uintptr(size), uintptr(unsafe.Pointer(&buf[0])),
	)
	if ret != 0 {
		return nil, fmt.Errorf("TdhGetProperty(%s): %w", name, windows.Errno(ret))
	}
	return buf, nil
}

// propUint reads an unsigned integer or pointer property of any width.
func propUint(rec *eventRecord, name string) (uint64, error) {
	b, err := propBytes(rec, name)
	if err != nil {
		return 0, err
	}
	switch len(b) {
	case 1:
		return uint64(b[0]), nil
	case 2:
		return uint64(binary.LittleEndian.Uint16(b)), nil
	case 4:
		return uint64(binary.LittleEndian.Uint32(b)), nil
	case 8:
		return binary.LittleEndian.Uint64(b), nil
	default:
		return 0, fmt.Errorf("property %s: unexpected size %d", name, len(b))
	}
}

// propString reads a NUL-terminated UTF-16 string property.
func propString(rec *eventRecord, name string) (string, error) {
	b, err := propBytes(rec, name)
	if err != nil || len(b) < 2 {
		return "", err
	}
	u := unsafe.Slice((*uint16)(unsafe.Pointer(&b[0])), len(b)/2)
	return windows.UTF16ToString(u), nil
}

// firstString returns the first of several candidate string properties that
// is present: property names have changed between manifest versions.
func firstString(rec *eventRecord, names ...string) string {
	for _, n := range names {
		if s, err := propString(rec, n); err == nil && s != "" {
			return s
		}
	}
	return ""
}
