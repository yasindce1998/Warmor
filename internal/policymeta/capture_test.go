package policymeta_test

import (
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/policymeta"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestCaptureFieldVocabularyAndMask(t *testing.T) {
	if got := policymeta.CaptureFieldNames(policymeta.FieldBitPPID | policymeta.FieldBitCgroupID); len(got) != 2 || got[0] != "cgroup_id" || got[1] != "ppid" {
		t.Fatalf("capture field names = %v", got)
	}
	// The require bit is a declaration flag, never a capturable event field.
	if policymeta.CaptureFields&policymeta.FieldBitRequireCompleteCapture != 0 {
		t.Fatal("require-complete bit must not be a capture field")
	}
	if policymeta.CaptureFields&policymeta.FieldBitTime != 0 || policymeta.CaptureFields&policymeta.FieldBitContainerAge != 0 {
		t.Fatal("temporal context must not be a capture field")
	}
}

func TestIncompleteCaptureFields(t *testing.T) {
	tests := []struct {
		name  string
		event *api.Event
		want  uint32
	}{
		{
			name:  "truncated telemetry marks the named field",
			event: &api.Event{TruncatedFields: []string{"filename", "process.args"}},
			want:  policymeta.FieldBitPath | policymeta.FieldBitArgs,
		},
		{
			name:  "trusted sensor with absent parent and cgroup",
			event: &api.Event{KernelTimestampNS: 42, PPID: 0, ParentComm: "", CgroupID: 0},
			want:  policymeta.FieldBitPPID | policymeta.FieldBitParentComm | policymeta.FieldBitCgroupID,
		},
		{
			name:  "trusted sensor with present parent and cgroup",
			event: &api.Event{KernelTimestampNS: 42, PPID: 7, ParentComm: "bash", CgroupID: 9, TruncatedFields: []string{"path"}},
			want:  policymeta.FieldBitPath,
		},
		{
			name:  "replay without trusted timestamp is never marked incomplete",
			event: &api.Event{PPID: 0, ParentComm: "", CgroupID: 0},
			want:  0,
		},
		{
			name:  "unknown truncation names are ignored",
			event: &api.Event{TruncatedFields: []string{"mystery"}},
			want:  0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := policymeta.IncompleteCaptureFields(tc.event); got != tc.want {
				t.Fatalf("incomplete = %#x, want %#x", got, tc.want)
			}
		})
	}
}

func TestRequiredCaptureFields(t *testing.T) {
	declared := uint32(policymeta.FieldBitPath | policymeta.FieldBitPPID | policymeta.FieldBitTime | policymeta.FieldBitRequireCompleteCapture)
	want := uint32(policymeta.FieldBitPath | policymeta.FieldBitPPID)
	if got := policymeta.RequiredCaptureFields(declared); got != want {
		t.Fatalf("required = %#x, want %#x", got, want)
	}
	// No declaration, unknown declaration, or a declaration without the bit all
	// disable the gate (backward compatibility).
	for _, mask := range []uint32{0, policymeta.FieldBitPath, policymeta.FieldsUnknown} {
		if got := policymeta.RequiredCaptureFields(mask); got != 0 {
			t.Fatalf("mask %#x requires %#x, want none", mask, got)
		}
	}
}

func TestCaptureDeclarationRoundTripThroughObservation(t *testing.T) {
	declared := uint32(policymeta.FieldBitPPID | policymeta.FieldBitParentComm | policymeta.FieldBitRequireCompleteCapture)
	m := policymeta.Observe(strings.Repeat("a", 64), policymeta.MaxABIVersion, policymeta.EncodingJSON,
		[3]uint32{declared, declared, declared},
		policymeta.StaticDomain{}, policymeta.StaticDomain{})
	if err := m.Validate(m.ModuleSHA256); err != nil {
		t.Fatal(err)
	}
	for _, e := range m.Events {
		if e.FieldsRead != declared {
			t.Fatalf("declaration bit lost in observation: %#x", e.FieldsRead)
		}
		if got := policymeta.RequiredCaptureFields(e.FieldsRead); got != declared&policymeta.CaptureFields {
			t.Fatalf("required = %#x, want %#x", got, declared&policymeta.CaptureFields)
		}
	}
}
