package wasm

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"

	wazeroapi "github.com/tetratelabs/wazero/api"
	"github.com/yasindce1998/warmor/pkg/api"
)

const eventStructSize = 256

// Binary event struct layout (256 bytes, little-endian):
//
//	Offset  Size   Field
//	0       4      pid (u32)
//	4       4      uid (u32)
//	8       4      gid (u32)
//	12      1      event_type (0=process, 1=file, 2=network)
//	13      64     comm (null-padded UTF-8)
//	77      128    primary_str (filename/path/remote_addr, null-padded)
//	205     4      flags (u32)
//	209     2      remote_port (u16)
//	211     2      local_port (u16)
//	213     32     secondary_str (operation/protocol, null-padded)
//	245     4      wall_clock_unix (u32, UTC seconds; 0 = unknown)  ABI >= 3
//	249     6      container_age_ms (u48 LE; 0 = unknown)          ABI >= 3
//	255     1      reserved (0)
//
// The temporal fields (offset 245 on) are only filled for modules that
// export abi_version() >= 3 (see temporalInputs). For older modules they
// stay zero, like the padding they replace.

// Policy represents a loaded WASM policy instance.
type Policy struct {
	runtime  *Runtime
	instance wazeroapi.Module

	// Pre-allocated WASM memory region for binary event struct.
	eventBufPtr uint32
	// Which ABI does this module support?
	useBinaryABI bool
	// abiVersion is the version the module declared (0 when it declares
	// none). It selects which optional context the host sends: >= 3 the
	// temporal fields, >= 4 the process-context fields (args, parent_comm,
	// cgroup_id, direction).
	abiVersion uint32
}

// temporal reports whether the module is sent the event's time context
// (ABI version >= TemporalABIVersion).
func (p *Policy) temporal() bool { return p.abiVersion >= TemporalABIVersion }

// NewPolicy creates a new policy instance from a compiled module.
func NewPolicy(ctx context.Context, runtime *Runtime) (*Policy, error) {
	instance, err := runtime.runtime.InstantiateModule(ctx, runtime.module, runtime.config)
	if err != nil {
		return nil, fmt.Errorf("instantiate module: %w", err)
	}

	return initPolicy(ctx, runtime, instance)
}

// Evaluate evaluates an event against the policy.
func (p *Policy) Evaluate(ctx context.Context, event *api.Event) (api.Action, error) {
	ctx = contextWithEvent(ctx, event)

	if p.useBinaryABI {
		return p.evaluateBinary(ctx, event)
	}
	return p.evaluateJSON(ctx, event)
}

func (p *Policy) evaluateBinary(ctx context.Context, event *api.Event) (api.Action, error) {
	buf := make([]byte, eventStructSize)
	writeEventBinary(buf, event, p.temporal())

	if !p.instance.Memory().Write(p.eventBufPtr, buf) {
		return api.ActionDeny, fmt.Errorf("failed to write event to WASM memory")
	}

	evaluateFn := p.instance.ExportedFunction("evaluate_event")
	results, err := evaluateFn.Call(ctx, uint64(p.eventBufPtr))
	if err != nil {
		return api.ActionDeny, fmt.Errorf("evaluate_event failed: %w", err)
	}

	return api.Action(results[0]), nil
}

func (p *Policy) evaluateJSON(ctx context.Context, event *api.Event) (api.Action, error) {
	eventJSON, err := marshalEventForWASM(event, p.abiVersion)
	if err != nil {
		return api.ActionDeny, fmt.Errorf("marshal event: %w", err)
	}

	malloc := p.instance.ExportedFunction("malloc")
	if malloc == nil {
		return api.ActionDeny, fmt.Errorf("malloc function not found")
	}

	results, err := malloc.Call(ctx, uint64(len(eventJSON)))
	if err != nil {
		return api.ActionDeny, fmt.Errorf("malloc failed: %w", err)
	}
	ptr := uint32(results[0])

	defer func() {
		if freeFn := p.instance.ExportedFunction("free"); freeFn != nil {
			_, _ = freeFn.Call(ctx, uint64(ptr), uint64(len(eventJSON)))
		}
	}()

	if !p.instance.Memory().Write(ptr, eventJSON) {
		return api.ActionDeny, fmt.Errorf("failed to write event to WASM memory")
	}

	evaluateFn := p.instance.ExportedFunction("evaluate_syscall")
	if evaluateFn == nil {
		return api.ActionDeny, fmt.Errorf("evaluate_syscall function not found")
	}

	results, err = evaluateFn.Call(ctx, uint64(ptr), uint64(len(eventJSON)))
	if err != nil {
		return api.ActionDeny, fmt.Errorf("evaluate_syscall failed: %w", err)
	}

	return api.Action(results[0]), nil
}

// GetMatchedRule reads the last matched rule reason from the WASM module.
func (p *Policy) GetMatchedRule(ctx context.Context) string {
	fn := p.instance.ExportedFunction("get_last_matched_rule")
	if fn == nil {
		return ""
	}

	const reasonBufSize = 512
	malloc := p.instance.ExportedFunction("malloc")
	if malloc == nil {
		return ""
	}

	results, err := malloc.Call(ctx, reasonBufSize)
	if err != nil {
		return ""
	}
	bufPtr := uint32(results[0])

	defer func() {
		if freeFn := p.instance.ExportedFunction("free"); freeFn != nil {
			_, _ = freeFn.Call(ctx, uint64(bufPtr), reasonBufSize)
		}
	}()

	results, err = fn.Call(ctx, uint64(bufPtr), reasonBufSize)
	if err != nil {
		return ""
	}
	written := uint32(results[0])
	if written == 0 {
		return ""
	}

	data, ok := p.instance.Memory().Read(bufPtr, written)
	if !ok {
		return ""
	}
	return string(data)
}

// Binary ABI offsets of the temporal fields (ABI version 3).
const (
	offWallClock    = 245
	offContainerAge = 249
	maxU48          = 1<<48 - 1
)

func writeEventBinary(buf []byte, event *api.Event, temporal bool) {
	for i := range buf {
		buf[i] = 0
	}

	if temporal {
		wall, age := temporalInputs(event)
		if wall > math.MaxUint32 {
			wall = 0 // after 2106: not representable, so unknown
		}
		binary.LittleEndian.PutUint32(buf[offWallClock:offWallClock+4], uint32(wall))
		var a [8]byte
		binary.LittleEndian.PutUint64(a[:], min(age, maxU48))
		copy(buf[offContainerAge:offContainerAge+6], a[:6])
	}

	binary.LittleEndian.PutUint32(buf[0:4], event.PID)
	binary.LittleEndian.PutUint32(buf[4:8], event.UID)
	binary.LittleEndian.PutUint32(buf[8:12], event.GID)

	buf[12] = byte(event.GetType())

	copyStringToBuffer(buf[13:77], event.Comm)

	switch event.GetType() {
	case api.EventTypeProcess:
		filename := event.Filename
		if event.Process != nil {
			filename = event.Process.Filename
		}
		copyStringToBuffer(buf[77:205], filename)

	case api.EventTypeFile:
		if event.File != nil {
			copyStringToBuffer(buf[77:205], event.File.Path)
			binary.LittleEndian.PutUint32(buf[205:209], event.File.Flags)
			copyStringToBuffer(buf[213:245], event.File.Operation)
		} else {
			copyStringToBuffer(buf[77:205], event.Filename)
			copyStringToBuffer(buf[213:245], "open")
		}

	case api.EventTypeNetwork:
		if event.Network != nil {
			copyStringToBuffer(buf[77:205], event.Network.RemoteAddr)
			binary.LittleEndian.PutUint16(buf[209:211], event.Network.RemotePort)
			binary.LittleEndian.PutUint16(buf[211:213], event.Network.LocalPort)
			copyStringToBuffer(buf[213:245], event.Network.Protocol)
		}
	}
}

func copyStringToBuffer(dst []byte, s string) {
	if len(s) == 0 {
		return
	}
	n := len(s)
	if n > len(dst) {
		n = len(dst)
	}
	copy(dst[:n], s[:n])
}

// marshalEventForWASM produces the flat JSON document passed to the JSON ABI
// (evaluate_syscall). Keys sent per "type":
//
//	all:     type, pid, uid, gid, comm, filename
//	PROCESS: filename = executed binary
//	FILE:    operation, path, flags
//	NETWORK: operation, protocol, remote_addr, remote_port, local_port
//
// With temporal (modules declaring ABI version >= 3) every document also
// carries wall_clock_unix (UTC seconds) and container_age_ms, each 0 when
// unknown (see temporalInputs). With process context (modules declaring
// ABI version >= 4, see docs/design/abi-v4-process-context.md) it also
// carries cgroup_id (all types), parent_comm and args (PROCESS) and
// direction (NETWORK).
func marshalEventForWASM(event *api.Event, abiVersion uint32) ([]byte, error) {
	// Every key below is always present so policies that deserialize into a
	// fixed struct do not fail to parse (and deny) on event types that lack a
	// field. "filename" is the executed binary and is only non-empty for
	// PROCESS events; file events carry their target in "path".
	m := map[string]any{
		"pid":      event.PID,
		"uid":      event.UID,
		"gid":      event.GID,
		"comm":     event.Comm,
		"filename": "",
	}
	if abiVersion >= TemporalABIVersion {
		wall, age := temporalInputs(event)
		m["wall_clock_unix"] = wall
		m["container_age_ms"] = age
	}
	if abiVersion >= ProcessContextABIVersion {
		m["cgroup_id"] = event.CgroupID
	}

	switch event.GetType() {
	case api.EventTypeProcess:
		m["type"] = "PROCESS"
		m["filename"] = event.Filename
		if event.Process != nil {
			m["filename"] = event.Process.Filename
		}
		if abiVersion >= ProcessContextABIVersion {
			m["parent_comm"] = event.ParentComm
			args := []string{}
			if event.Process != nil {
				args = event.Process.Args
			}
			if args == nil {
				args = []string{}
			}
			m["args"] = args
		}
	case api.EventTypeFile:
		m["type"] = "FILE"
		if event.File != nil {
			m["operation"] = event.File.Operation
			m["path"] = event.File.Path
			m["flags"] = event.File.Flags
		} else {
			m["operation"] = "open"
			m["path"] = event.Filename
			m["flags"] = uint32(0)
		}
	case api.EventTypeNetwork:
		m["type"] = "NETWORK"
		if event.Network != nil {
			m["operation"] = event.Network.Operation
			m["protocol"] = event.Network.Protocol
			m["remote_addr"] = event.Network.RemoteAddr
			m["remote_port"] = event.Network.RemotePort
			m["local_port"] = event.Network.LocalPort
		} else {
			m["operation"] = "connect"
			m["protocol"] = "tcp"
			m["remote_addr"] = ""
			m["remote_port"] = uint16(0)
			m["local_port"] = uint16(0)
		}
		if abiVersion >= ProcessContextABIVersion {
			// The sensors only see outbound connects today; sendto/recvfrom
			// hooks do not exist yet. connect/sendto are egress, recvfrom
			// ingress, matching what the crates' zero-trust rules expect.
			switch m["operation"] {
			case "recvfrom":
				m["direction"] = "ingress"
			default:
				m["direction"] = "egress"
			}
		}
	default:
		m["type"] = "PROCESS"
		m["filename"] = event.Filename
	}

	return json.Marshal(m)
}

// Close cleans up the policy instance.
func (p *Policy) Close(ctx context.Context) error {
	if p.instance != nil {
		return p.instance.Close(ctx)
	}
	return nil
}
