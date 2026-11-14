// Package protocol defines the bounded, versioned policy-host wire contract.
// It deliberately depends on neither wazero nor the policy runtime.
package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/yasindce1998/warmor/internal/policymeta"
	"github.com/yasindce1998/warmor/pkg/api"
)

const (
	Version    = 2
	MaxModule  = 64 << 20
	MaxControl = 4096
	MaxEvent   = 256 << 10
	MaxResult  = 8192
	MaxReason  = 1024
	// Includes worst-case JSON escaping of 4096 full-size patterns, while
	// decoded rule counts/pattern lengths are independently bounded.
	MaxMetadata = 8 << 20
)

var ErrProtocol = errors.New("invalid policy-host protocol")

// Ready is required in protocol v2. Older workers cannot silently omit
// declarations and be mistaken for a cacheable constant policy.
type Ready struct {
	Control  Control
	Metadata policymeta.Module
}

// Limits are checked independently on both sides, before module upload.
// AddressSpaceBytes is RLIMIT_AS, not an RSS quota. CPUSeconds is a
// cumulative process-lifetime budget, rounded to whole seconds.
type Limits struct {
	AddressSpaceBytes uint64
	CPUSeconds        uint64
	MemoryPages       uint32
	MaxRequests       uint64
}

func (l Limits) Validate() error {
	if l.AddressSpaceBytes < 2<<30 || l.AddressSpaceBytes > 16<<30 || l.CPUSeconds < 1 || l.CPUSeconds > 3600 || l.MemoryPages < 1 || l.MemoryPages > 1024 || l.MaxRequests < 1 || l.MaxRequests > 1000000 {
		return errors.New("policy-host limits out of range")
	}
	return nil
}

type Control struct {
	Version  uint32
	Kind     string
	Sequence uint64
	Digest   string
	Limits   Limits
}

type Result struct {
	Version  uint32
	Sequence uint64
	Action   api.Action
	Audit    bool
	Reason   string
	Failed   bool
}

// Bytes, rather than JSON strings, preserve invalid UTF-8 from sensors. Such
// inputs must remain unknown to compiled policies, not become U+FFFD matches.
// No event fields are truncated or repaired by transport. Fields not observable
// by the current WASM ABIs/callbacks are intentionally not transmitted.
type Event struct {
	Version                    uint32
	Sequence                   uint64
	Type                       api.EventType
	PID, UID, GID              uint32
	Comm, Filename, ParentComm []byte
	Timestamp, ContainerStart  time.Time
	CgroupID                   uint64
	Process                    *Process
	File                       *File
	Network                    *Network
}
type Process struct {
	Filename []byte
	Args     [][]byte
}
type File struct {
	Path, Operation []byte
	Flags           uint32
}
type Network struct {
	Operation, Protocol, RemoteAddr []byte
	RemotePort, LocalPort           uint16
}

func Snapshot(e *api.Event) (*Event, error) {
	if e == nil {
		return nil, errors.New("nil policy event")
	}
	t := e.GetType()
	if t < api.EventTypeProcess || t > api.EventTypeNetwork {
		return nil, errors.New("unknown policy event type")
	}
	// Check sizes before allocating a copy or base64/JSON output.
	n := len(e.Comm) + len(e.Filename) + len(e.ParentComm)
	if e.Process != nil {
		if len(e.Process.Args) > 4096 {
			return nil, errors.New("too many policy arguments")
		}
		n += len(e.Process.Filename)
		for _, a := range e.Process.Args {
			if len(a) > MaxEvent {
				return nil, errors.New("policy event too large")
			}
			n += len(a) + 8
		}
	}
	if e.File != nil {
		n += len(e.File.Path) + len(e.File.Operation)
	}
	if e.Network != nil {
		n += len(e.Network.Operation) + len(e.Network.Protocol) + len(e.Network.RemoteAddr)
	}
	if n > MaxEvent/2 {
		return nil, errors.New("policy event too large")
	}
	s := &Event{Version: Version, Type: t, PID: e.PID, UID: e.UID, GID: e.GID, Comm: []byte(e.Comm), Filename: []byte(e.Filename), ParentComm: []byte(e.ParentComm), Timestamp: e.Timestamp, ContainerStart: e.ContainerStart, CgroupID: e.CgroupID}
	if e.Process != nil {
		s.Process = &Process{Filename: []byte(e.Process.Filename)}
		for _, a := range e.Process.Args {
			s.Process.Args = append(s.Process.Args, []byte(a))
		}
	}
	if e.File != nil {
		s.File = &File{Path: []byte(e.File.Path), Operation: []byte(e.File.Operation), Flags: e.File.Flags}
	}
	if e.Network != nil {
		s.Network = &Network{Operation: []byte(e.Network.Operation), Protocol: []byte(e.Network.Protocol), RemoteAddr: []byte(e.Network.RemoteAddr), RemotePort: e.Network.RemotePort, LocalPort: e.Network.LocalPort}
	}
	return s, nil
}

func (s *Event) API() *api.Event {
	e := &api.Event{PID: s.PID, UID: s.UID, GID: s.GID, Comm: string(s.Comm), Filename: string(s.Filename), ParentComm: string(s.ParentComm), Timestamp: s.Timestamp, ContainerStart: s.ContainerStart, CgroupID: s.CgroupID}
	e.SetType(s.Type)
	if s.Process != nil {
		e.Process = &api.ProcessEvent{Filename: string(s.Process.Filename)}
		for _, a := range s.Process.Args {
			e.Process.Args = append(e.Process.Args, string(a))
		}
	}
	if s.File != nil {
		e.File = &api.FileEvent{Path: string(s.File.Path), Operation: string(s.File.Operation), Flags: s.File.Flags}
	}
	if s.Network != nil {
		e.Network = &api.NetworkEvent{Operation: string(s.Network.Operation), Protocol: string(s.Network.Protocol), RemoteAddr: string(s.Network.RemoteAddr), RemotePort: s.Network.RemotePort, LocalPort: s.Network.LocalPort}
	}
	return e
}

func Read(r io.Reader, max uint32) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > max {
		return nil, ErrProtocol
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}
func Write(w io.Writer, b []byte, max uint32) error {
	if len(b) == 0 || uint64(len(b)) > uint64(max) {
		return ErrProtocol
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if _, err := io.Copy(w, bytes.NewReader(h[:])); err != nil {
		return err
	}
	_, err := io.Copy(w, bytes.NewReader(b))
	return err
}
func Send(w io.Writer, v any, max uint32) error {
	b, err := json.Marshal(v)
	if err != nil {
		return ErrProtocol
	}
	return Write(w, b, max)
}
func Receive(r io.Reader, v any, max uint32) error {
	b, err := Read(r, max)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return ErrProtocol
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return ErrProtocol
	}
	// V1 requires the canonical encoding produced by Send, including every
	// field. In particular an omitted Action must not become zero/ALLOW.
	// This also rejects duplicate keys, null scalars and case-folded keys.
	canonical, err := json.Marshal(v)
	if err != nil || !bytes.Equal(b, canonical) {
		return ErrProtocol
	}
	return nil
}
