package wasm

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/yasindce1998/warmor/internal/policymeta"
	"github.com/yasindce1998/warmor/pkg/api"
)

// TestCacheKeyInputs_AllObservableU32Fields pins the host-callback half of
// PolicyInputsForABI. Before PPID (17) and capture quality (16) were added,
// a guest could read both while the cache-key coverage test saw neither.
func TestCacheKeyInputs_AllObservableU32Fields(t *testing.T) {
	event := &api.Event{
		PID: 100, UID: 200, GID: 300,
		PPID: 42, ParentComm: "bash", CgroupID: 9,
		KernelTimestampNS: 1234,
		TruncatedFields:   []string{"filename"},
	}
	ctx := contextWithEvent(context.Background(), event)
	for version := uint32(0); version <= MaxABIVersion; version++ {
		inputs := PolicyInputsForABI(event, version)
		if len(inputs) != 3 {
			t.Fatalf("ABI %d: PolicyInputsForABI returned %d inputs", version, len(inputs))
		}
		cb := inputs[2]
		const nBase = 6 // PID, UID, GID, Flags, RemotePort, LocalPort
		if len(cb) < (nBase+2)*4 {
			t.Fatalf("ABI %d: callback input too short: %d bytes", version, len(cb))
		}
		for i, id := range []uint32{FieldPID, FieldUID, FieldGID, FieldFlags, FieldRemotePort, FieldLocalPort} {
			if got, want := binary.LittleEndian.Uint32(cb[i*4:]), hostGetFieldU32(ctx, nil, id); got != want {
				t.Errorf("ABI %d: callback %d = %d, want %d", version, id, got, want)
			}
		}
		if got, want := binary.LittleEndian.Uint32(cb[nBase*4:]), uint32(policymeta.FieldBitPath); got != want {
			t.Errorf("ABI %d: capture quality = %#x, want %#x", version, got, want)
		}
		if got, want := binary.LittleEndian.Uint32(cb[(nBase+1)*4:]), event.PPID; got != want {
			t.Errorf("ABI %d: PPID = %d, want %d", version, got, want)
		}
	}
}

// TestCacheKeyInputs_PPIDAndQualityDistinguishable makes the coverage gap
// explicit: two events differing only in a host-observed field must produce
// different observable inputs at every ABI version.
func TestCacheKeyInputs_PPIDAndQualityDistinguishable(t *testing.T) {
	base := &api.Event{PID: 1, Filename: "/bin/tool", PPID: 10, ParentComm: "init", CgroupID: 3}
	ppid := *base
	ppid.PPID = 11
	lossy := *base
	lossy.TruncatedFields = []string{"filename"}
	clean := &api.Event{PID: 1, Filename: "/bin/tool", PPID: 10, ParentComm: "init", CgroupID: 3}

	for version := uint32(0); version <= MaxABIVersion; version++ {
		want := PolicyInputsForABI(base, version)
		if got := PolicyInputsForABI(&ppid, version); bytes.Equal(want[2], got[2]) {
			t.Errorf("ABI %d: PPID-only change is invisible", version)
		}
		if got := PolicyInputsForABI(&lossy, version); bytes.Equal(want[2], got[2]) {
			t.Errorf("ABI %d: capture-quality-only change is invisible", version)
		}
		if got := PolicyInputsForABI(clean, version); !bytes.Equal(want[2], got[2]) {
			t.Errorf("ABI %d: identical events differ in observable inputs", version)
		}
	}
}
