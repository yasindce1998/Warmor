package wasm

import (
	"context"
	"strings"

	"github.com/tetratelabs/wazero"
	wazeroapi "github.com/tetratelabs/wazero/api"

	"github.com/yasindce1998/warmor/pkg/api"
)

type eventContextKey struct{}

func contextWithEvent(ctx context.Context, event *api.Event) context.Context {
	return context.WithValue(ctx, eventContextKey{}, event)
}

func eventFromContext(ctx context.Context) *api.Event {
	ev, _ := ctx.Value(eventContextKey{}).(*api.Event)
	return ev
}

const (
	FieldPID        uint32 = 0
	FieldUID        uint32 = 1
	FieldGID        uint32 = 2
	FieldFlags      uint32 = 3
	FieldRemotePort uint32 = 4
	FieldLocalPort  uint32 = 5

	FieldComm       uint32 = 10
	FieldPath       uint32 = 11
	FieldOperation  uint32 = 12
	FieldProtocol   uint32 = 13
	FieldRemoteAddr uint32 = 14
	FieldArgs       uint32 = 15
)

func registerHostCallbacks(ctx context.Context, r wazero.Runtime) error {
	_, err := r.NewHostModuleBuilder("env").
		NewFunctionBuilder().
		WithFunc(hostGetFieldU32).
		Export("get_field_u32").
		NewFunctionBuilder().
		WithFunc(hostGetFieldStr).
		Export("get_field_str").
		Instantiate(ctx)
	return err
}

func hostGetFieldU32(ctx context.Context, _ wazeroapi.Module, fieldID uint32) uint32 {
	event := eventFromContext(ctx)
	if event == nil {
		return 0
	}

	switch fieldID {
	case FieldPID:
		return event.PID
	case FieldUID:
		return event.UID
	case FieldGID:
		return event.GID
	case FieldFlags:
		if event.File != nil {
			return event.File.Flags
		}
		return 0
	case FieldRemotePort:
		if event.Network != nil {
			return uint32(event.Network.RemotePort)
		}
		return 0
	case FieldLocalPort:
		if event.Network != nil {
			return uint32(event.Network.LocalPort)
		}
		return 0
	default:
		return 0
	}
}

func hostGetFieldStr(ctx context.Context, m wazeroapi.Module, fieldID, bufPtr, bufLen uint32) uint32 {
	event := eventFromContext(ctx)
	if event == nil {
		return 0
	}

	var value string
	switch fieldID {
	case FieldComm:
		value = event.Comm
	case FieldPath:
		value = getEventPath(event)
	case FieldOperation:
		value = getEventOperation(event)
	case FieldProtocol:
		if event.Network != nil {
			value = event.Network.Protocol
		}
	case FieldRemoteAddr:
		if event.Network != nil {
			value = event.Network.RemoteAddr
		}
	case FieldArgs:
		value = eventArgs(event)
	default:
		return 0
	}

	// A zero-capacity call queries the required byte length without writing.
	if bufLen == 0 {
		return uint32(len(value))
	}
	if value == "" {
		return 0
	}

	data := []byte(value)
	if uint32(len(data)) > bufLen {
		data = data[:bufLen]
	}

	if !m.Memory().Write(bufPtr, data) {
		return 0
	}
	return uint32(len(data))
}

// YAML args conditions use the space-joined argv, including argv[0]. This
// is not shell parsing: quotes and argument boundaries are not synthesized.
func eventArgs(event *api.Event) string {
	if event.Process == nil {
		return ""
	}
	return strings.Join(event.Process.Args, " ")
}

func getEventPath(event *api.Event) string {
	if event.Process != nil && event.Process.Filename != "" {
		return event.Process.Filename
	}
	if event.File != nil && event.File.Path != "" {
		return event.File.Path
	}
	if event.Network != nil && event.Network.RemoteAddr != "" {
		return event.Network.RemoteAddr
	}
	return event.Filename
}

func getEventOperation(event *api.Event) string {
	if event.File != nil {
		return event.File.Operation
	}
	if event.Network != nil {
		return event.Network.Operation
	}
	return ""
}
