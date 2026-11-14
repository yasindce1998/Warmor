package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/policymeta"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestFrameBoundsAndStrictDecoding(t *testing.T) {
	for _, n := range []uint32{0, MaxControl + 1, ^uint32(0)} {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], n)
		if _, err := Read(bytes.NewReader(b[:]), MaxControl); !errors.Is(err, ErrProtocol) {
			t.Fatalf("length %d: %v", n, err)
		}
	}
	for _, body := range []string{`{"Version":1,"Unknown":true}`, `{} {}`, `{`, `null {}`} {
		var buf bytes.Buffer
		if err := Write(&buf, []byte(body), MaxControl); err != nil {
			t.Fatal(err)
		}
		if err := Receive(&buf, new(Control), MaxControl); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	for _, body := range []string{`{"Version":1,"Sequence":1}`, `{"Version":1,"Sequence":1,"Action":null,"Audit":false,"Reason":"","Failed":false}`, `{"Version":1,"Sequence":1,"Action":1,"Action":0,"Audit":false,"Reason":"","Failed":false}`} {
		var buf bytes.Buffer
		if err := Write(&buf, []byte(body), MaxResult); err != nil {
			t.Fatal(err)
		}
		if err := Receive(&buf, new(Result), MaxResult); err == nil {
			t.Fatal("accepted ambiguous/missing result")
		}
	}
	if _, err := Read(bytes.NewReader([]byte{0, 0, 0, 2, 1}), MaxControl); err == nil {
		t.Fatal("accepted truncated frame")
	}
}

func TestReadyMetadataRequiredAndBounded(t *testing.T) {
	m := policymeta.Observe(strings.Repeat("a", 64), 5, policymeta.EncodingBinary, [3]uint32{0, 0, 0}, policymeta.StaticDomain{}, policymeta.StaticDomain{})
	r := Ready{Control: Control{Version: Version, Kind: "ready", Digest: m.ModuleSHA256}, Metadata: m}
	var b bytes.Buffer
	if err := Send(&b, r, MaxMetadata); err != nil {
		t.Fatal(err)
	}
	var got Ready
	if err := Receive(&b, &got, MaxMetadata); err != nil || got.Metadata.Validate(m.ModuleSHA256) != nil {
		t.Fatal("valid metadata rejected", err)
	}
	for _, body := range []string{`{"Control":{},"Metadata":null}`, `{"Control":{},"Metadata":{},"Metadata":{}}`, `{"Control":{}}`} {
		b.Reset()
		if err := Write(&b, []byte(body), MaxMetadata); err != nil {
			t.Fatal(err)
		}
		got = Ready{}
		if err := Receive(&b, &got, MaxMetadata); err == nil {
			t.Fatal("missing/duplicate metadata accepted")
		}
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], MaxMetadata+1)
	if _, err := Read(bytes.NewReader(header[:]), MaxMetadata); !errors.Is(err, ErrProtocol) {
		t.Fatal("oversized metadata allocated")
	}
}

func TestParentReadyValidationRejectsMalformedObservations(t *testing.T) {
	digest := strings.Repeat("a", 64)
	limits := Limits{AddressSpaceBytes: 4 << 30, CPUSeconds: 10, MemoryPages: 256, MaxRequests: 100}
	metadata := policymeta.Observe(digest, 5, policymeta.EncodingBinary, [3]uint32{compiler.FieldBitPath, 0, 0}, policymeta.StaticDomain{Eligible: true, Rules: []compiler.StaticRule{{Event: "process", Pattern: "/bin/tool"}}}, policymeta.StaticDomain{})
	for name, mutate := range map[string]func(*Ready){
		"none":              func(*Ready) {},
		"protocol":          func(r *Ready) { r.Control.Version = 1 },
		"kind":              func(r *Ready) { r.Control.Kind = "loading" },
		"limits":            func(r *Ready) { r.Control.Limits.CPUSeconds++ },
		"sequence":          func(r *Ready) { r.Control.Sequence = 1 },
		"control identity":  func(r *Ready) { r.Control.Digest = strings.Repeat("b", 64) },
		"metadata identity": func(r *Ready) { r.Metadata.ModuleSHA256 = strings.Repeat("b", 64) },
		"missing events":    func(r *Ready) { r.Metadata.Events = nil },
		"duplicate events":  func(r *Ready) { r.Metadata.Events[1] = r.Metadata.Events[0] },
		"missing domain":    func(r *Ready) { r.Metadata.Domains = r.Metadata.Domains[:1] },
		"unknown ABI":       func(r *Ready) { r.Metadata.ABIVersion = 6 },
		"unknown flags":     func(r *Ready) { r.Metadata.Events[0].Flags |= 1 << 31 },
		"long path": func(r *Ready) {
			r.Metadata.Domains[0].Rules[0].Pattern = strings.Repeat("a", policymeta.MaxPatternBytes+1)
		},
		"duplicate rule": func(r *Ready) {
			r.Metadata.Domains[0].Rules = append(r.Metadata.Domains[0].Rules, r.Metadata.Domains[0].Rules[0])
		},
		"excess rules": func(r *Ready) { r.Metadata.Domains[0].Rules = make([]compiler.StaticRule, policymeta.MaxStaticRules+1) },
	} {
		t.Run(name, func(t *testing.T) {
			r := Ready{Control: Control{Version: Version, Kind: "ready", Digest: digest, Limits: limits}, Metadata: metadata.Clone()}
			mutate(&r)
			var frame bytes.Buffer
			if err := Send(&frame, r, MaxMetadata); err != nil {
				t.Fatal(err)
			}
			var received Ready
			if err := Receive(&frame, &received, MaxMetadata); err != nil {
				t.Fatal(err)
			}
			err := received.Validate(digest, limits)
			if name == "none" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrProtocol) {
				t.Fatal("parent accepted invalid ready metadata", err)
			}
		})
	}
}

func TestMaximumEscapedMetadataFitsBoundedFrame(t *testing.T) {
	domain := policymeta.StaticDomain{Eligible: true}
	for i := range policymeta.MaxStaticRules {
		// Legal non-NUL control bytes need six-byte JSON escapes. The cap
		// must admit the full contract, not only pleasant printable paths.
		pattern := fmt.Sprintf("%08d", i) + strings.Repeat("\x01", 127-8)
		domain.Rules = append(domain.Rules, compiler.StaticRule{Event: "process", Pattern: pattern})
	}
	m := policymeta.Observe(strings.Repeat("a", 64), 5, policymeta.EncodingJSON, [3]uint32{compiler.FieldBitPath, 0, 0}, domain, policymeta.StaticDomain{})
	if err := m.Validate(m.ModuleSHA256); err != nil {
		t.Fatal(err)
	}
	if len(m.Domains[0].Rules) != policymeta.MaxStaticRules {
		t.Fatal("capacity fixture was silently declined")
	}
	var b bytes.Buffer
	if err := Send(&b, Ready{Control: Control{Version: Version, Kind: "ready", Digest: m.ModuleSHA256}, Metadata: m}, MaxMetadata); err != nil {
		t.Fatal("valid capacity exceeds wire cap", err)
	}
	var r Ready
	if err := Receive(&b, &r, MaxMetadata); err != nil || r.Metadata.Validate(m.ModuleSHA256) != nil {
		t.Fatal("max capacity failed round trip", err)
	}
}

func TestSnapshotPreservesInputsWithoutRepair(t *testing.T) {
	e := &api.Event{PID: 42, UID: 7, GID: 8, Comm: "bad\xff", Filename: "legacy", ParentComm: "parent", CgroupID: 99, Timestamp: time.Unix(5, 0).UTC(), ContainerStart: time.Unix(2, 0).UTC(), Process: &api.ProcessEvent{Filename: "tool", Args: []string{"tool", "\xff", ""}}, File: &api.FileEvent{Path: "file", Operation: "open", Flags: 7}, Network: &api.NetworkEvent{Operation: "recvfrom", Protocol: "udp", RemoteAddr: "::1", RemotePort: 53, LocalPort: 12}}
	e.SetType(api.EventTypeProcess) // explicitly process despite other populated members
	s, err := Snapshot(e)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := Send(&b, s, MaxEvent); err != nil {
		t.Fatal(err)
	}
	var r Event
	if err := Receive(&b, &r, MaxEvent); err != nil {
		t.Fatal(err)
	}
	got := r.API()
	if got.GetType() != api.EventTypeProcess || !reflect.DeepEqual(got.Process.Args, e.Process.Args) || got.Comm != e.Comm || got.File.Path != e.File.Path || got.Network.Operation != e.Network.Operation || got.ParentComm != e.ParentComm || got.CgroupID != e.CgroupID || !got.Timestamp.Equal(e.Timestamp) || !got.ContainerStart.Equal(e.ContainerStart) {
		t.Fatalf("snapshot changed policy inputs: %+v", got)
	}
	if e.Timestamp != s.Timestamp {
		t.Fatal("mutated caller")
	}
}

func TestSnapshotBoundsAndUnknown(t *testing.T) {
	for _, e := range []*api.Event{nil, {Type: 99}, {Comm: strings.Repeat("x", MaxEvent)}, {Process: &api.ProcessEvent{Args: make([]string, 4097)}}} {
		if _, err := Snapshot(e); err == nil {
			t.Fatal("accepted invalid/oversized event")
		}
	}
	// Unknown remains unknown; missing context is not invented by transport.
	s, err := Snapshot(&api.Event{})
	if err != nil {
		t.Fatal(err)
	}
	if !s.API().ContainerStart.IsZero() || s.API().Process != nil {
		t.Fatal("invented context")
	}
}
