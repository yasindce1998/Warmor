package wasm

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/yasindce1998/warmor/pkg/api"
)

// PolicyInputs returns everything a policy module can observe about event,
// through every channel the host offers: the binary ABI event struct, the
// JSON ABI document, and the values the get_field_* host callbacks return.
// temporal selects what a module declaring ABI >= TemporalABIVersion sees
// (which adds the wall clock and container age). Two events with equal
// PolicyInputs are indistinguishable to any such policy (pure policies
// decide them identically). It exists so the decision cache's key can be
// checked against the real serialization in tests.
func PolicyInputs(event *api.Event, temporal bool) [][]byte {
	bin := make([]byte, eventStructSize)
	writeEventBinary(bin, event, temporal)

	js, err := marshalEventForWASM(event, temporal)
	if err != nil {
		js = []byte("marshal error: " + err.Error())
	}

	ctx := contextWithEvent(context.Background(), event)
	var cb []byte
	for _, id := range []uint32{FieldPID, FieldUID, FieldGID, FieldFlags, FieldRemotePort, FieldLocalPort} {
		cb = binary.LittleEndian.AppendUint32(cb, hostGetFieldU32(ctx, nil, id))
	}
	for _, s := range []string{
		event.Comm, getEventPath(event), getEventOperation(event),
		networkField(event, func(n *api.NetworkEvent) string { return n.Protocol }),
		networkField(event, func(n *api.NetworkEvent) string { return n.RemoteAddr }),
	} {
		cb = append(cb, fmt.Sprintf("%d:%s;", len(s), s)...)
	}
	return [][]byte{bin, js, cb}
}

func networkField(event *api.Event, f func(*api.NetworkEvent) string) string {
	if event.Network == nil {
		return ""
	}
	return f(event.Network)
}
