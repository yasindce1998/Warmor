//go:build windows

package etw

import (
	"testing"
	"unsafe"
)

// The ETW structs are passed to advapi32 by pointer, so their layout must
// match the C definitions exactly (sizes from the 64-bit Windows SDK).
func TestStructLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("sizes below are for 64-bit Windows")
	}
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"EVENT_TRACE_PROPERTIES", unsafe.Sizeof(eventTraceProperties{}), 120},
		{"EVENT_TRACE_LOGFILEW", unsafe.Sizeof(eventTraceLogfile{}), 448},
		{"EVENT_RECORD", unsafe.Sizeof(eventRecord{}), 112},
		{"EVENT_HEADER", unsafe.Sizeof(eventHeader{}), 80},
		{"TRACE_LOGFILE_HEADER", unsafe.Sizeof(traceLogfileHeader{}), 280},
		{"PROPERTY_DATA_DESCRIPTOR", unsafe.Sizeof(propertyDataDescriptor{}), 16},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("sizeof(%s) = %d, want %d", c.name, c.got, c.want)
		}
	}
	if off := unsafe.Offsetof(eventTraceLogfile{}.EventRecordCallback); off != 424 {
		t.Errorf("EVENT_TRACE_LOGFILEW.EventRecordCallback at %d, want 424", off)
	}
}
