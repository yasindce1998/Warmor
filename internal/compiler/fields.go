package compiler

import (
	"fmt"
	"sort"
	"strings"
)

// Field bits for the fields-read declaration a policy module exports as
//
//	warmor_fields_read(event_type: u32) -> u32
//
// It returns the set of event fields the module's decision for that event
// type can depend on. The host uses it to decide which caches and kernel
// fast-path keys are sound for the policy: a decision may only be reused
// for another event if every field it depends on is the same. A module that
// does not export the function, or returns FieldsUnknown, is treated as
// depending on everything.
//
// Hand-written (non-YAML) policies may export the same function to opt in;
// the declaration must be exhaustive or cached and kernel-compiled decisions
// will be applied to events the policy would have decided differently.
const (
	FieldBitPID uint32 = 1 << iota
	FieldBitUID
	FieldBitGID
	FieldBitComm
	FieldBitPath
	FieldBitArgs
	FieldBitFlags
	FieldBitOperation
	FieldBitProtocol
	FieldBitRemoteAddr
	FieldBitRemotePort
	FieldBitLocalPort

	// FieldBitTime and FieldBitContainerAge are not event fields but the
	// temporal context the host sends to ABI >= 3 modules (the event's wall
	// clock and its container's age). A decision depending on either can
	// change for the same event over time, so the host never caches it
	// and no kernel key covers it.
	FieldBitTime
	FieldBitContainerAge

	// FieldsUnknown means the decision may depend on any part of the event.
	FieldsUnknown uint32 = 0xFFFFFFFF
)

// FieldsReadExport is the name of the exported fields-read declaration.
const FieldsReadExport = "warmor_fields_read"

var fieldBits = map[string]uint32{
	"pid":         FieldBitPID,
	"uid":         FieldBitUID,
	"gid":         FieldBitGID,
	"comm":        FieldBitComm,
	"path":        FieldBitPath,
	"args":        FieldBitArgs,
	"flags":       FieldBitFlags,
	"operation":   FieldBitOperation,
	"protocol":    FieldBitProtocol,
	"remote_addr": FieldBitRemoteAddr,
	"remote_port": FieldBitRemotePort,
	"local_port":  FieldBitLocalPort,

	// Temporal context, read by rules with a temporal: block.
	"wall_clock":    FieldBitTime,
	"container_age": FieldBitContainerAge,
}

// FieldBit returns the bit for a YAML condition field name. Unknown names
// map to FieldsUnknown so that a new field can never be silently ignored.
func FieldBit(name string) uint32 {
	if b, ok := fieldBits[name]; ok {
		return b
	}
	return FieldsUnknown
}

// FieldMask ORs together the bits of the named fields.
func FieldMask(names ...string) uint32 {
	var m uint32
	for _, n := range names {
		m |= FieldBit(n)
	}
	return m
}

// FieldNames lists the field names in mask, sorted (for messages and tests).
func FieldNames(mask uint32) []string {
	if mask == FieldsUnknown {
		return []string{"*"}
	}
	var names []string
	for n, b := range fieldBits {
		if mask&b != 0 {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

// eventTypeIDs are the event_type values of the binary ABI.
var eventTypeIDs = []struct {
	name string
	id   int
}{{"process", 0}, {"file", 1}, {"network", 2}}

// FieldsRead returns, per event type ID (0 process, 1 file, 2 network), the
// mask of fields any rule for that event type references. The default
// action and rule order are constants of the policy, so these fields fully
// determine the decision.
func FieldsRead(policy *Policy) map[int]uint32 {
	out := make(map[int]uint32, len(eventTypeIDs))
	for _, et := range eventTypeIDs {
		var m uint32
		for _, r := range rulesForEvent(policy, et.name) {
			for _, list := range [][]Condition{r.Conditions.All, r.Conditions.Any, r.Conditions.Not} {
				for _, c := range list {
					m |= FieldBit(c.Field)
				}
			}
		}
		out[et.id] = m
	}
	return out
}

func writeFieldsRead(b *strings.Builder, policy *Policy) {
	fr := FieldsRead(policy)
	b.WriteString("// Fields each event type's decision depends on (see compiler.FieldsRead).\n")
	b.WriteString("#[no_mangle]\npub extern \"C\" fn " + FieldsReadExport + "(event_type: u32) -> u32 {\n")
	b.WriteString("    match event_type {\n")
	for _, et := range eventTypeIDs {
		b.WriteString(fmt.Sprintf("        %d => 0x%08X,\n", et.id, fr[et.id]))
	}
	b.WriteString(fmt.Sprintf("        _ => 0x%08X,\n", FieldsUnknown))
	b.WriteString("    }\n}\n\n")
}
