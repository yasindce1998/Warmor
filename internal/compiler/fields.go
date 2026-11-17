package compiler

import (
	"fmt"
	"sort"
	"strings"

	"github.com/yasindce1998/warmor/internal/policymeta"
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
//
// Note for network policies on Linux: bind, listen and connect share this
// single network declaration (the ABI has no separate per-hook domain), while
// the live sensor reports operation "connect" for bind events. Because the
// kernel's bind key covers only remote_addr/remote_port, a policy that reads
// "operation" cannot have its bind decisions compiled into the kernel map;
// such decisions are refused rather than applied to other events. For now,
// network policies that want the bind kernel fast-path must not read
// "operation". Listen is keyed by family+port only: its kernel key carries no
// address, so a listen decision that reads "remote_addr" or "protocol" is
// likewise refused rather than applied to other events; only "remote_port"
// is a sound listen key field.
//
// Mount is a file-kind LSM event (Hook="mount") whose kernel key carries only
// the filesystem type. That fstype is hook metadata, not a compiler field a
// policy declares it reads, and the mount source/target are never in the key.
// There is therefore no sound mount key field: a mount decision that reads any
// policy field (path, uid, temporal context, ...) is refused kernel write-back
// and stays userspace-only. Only a decision fully determined by the key alone
// may be compiled in, as a coarse DENY that blocks every mount of that fstype.
const (
	FieldBitPID        = policymeta.FieldBitPID
	FieldBitUID        = policymeta.FieldBitUID
	FieldBitGID        = policymeta.FieldBitGID
	FieldBitComm       = policymeta.FieldBitComm
	FieldBitPath       = policymeta.FieldBitPath
	FieldBitArgs       = policymeta.FieldBitArgs
	FieldBitFlags      = policymeta.FieldBitFlags
	FieldBitOperation  = policymeta.FieldBitOperation
	FieldBitProtocol   = policymeta.FieldBitProtocol
	FieldBitRemoteAddr = policymeta.FieldBitRemoteAddr
	FieldBitRemotePort = policymeta.FieldBitRemotePort
	FieldBitLocalPort  = policymeta.FieldBitLocalPort

	// Process-context capture fields, added to the vocabulary so policies that
	// read them can declare the dependency. The host capture-quality gate
	// treats their absence on a trusted live event as incomplete capture.
	FieldBitPPID       = policymeta.FieldBitPPID
	FieldBitParentComm = policymeta.FieldBitParentComm
	FieldBitCgroupID   = policymeta.FieldBitCgroupID

	// FieldBitTime and FieldBitContainerAge are not event fields but the
	// temporal context the host sends to ABI >= 3 modules (the event's wall
	// clock and its container's age). A decision depending on either can
	// change for the same event over time, so the host never caches it
	// and no kernel key covers it.
	FieldBitTime         = policymeta.FieldBitTime
	FieldBitContainerAge = policymeta.FieldBitContainerAge

	// FieldBitRequireCompleteCapture is a policy-level declaration bit in the
	// fields-read mask. When a non-unknown mask carries it, the host gate
	// verifies that every capturable field in that mask was captured in full
	// before evaluating. It is a declaration of NEED, never a guest claim that
	// its inputs were actually complete (the host derives that itself).
	FieldBitRequireCompleteCapture = policymeta.FieldBitRequireCompleteCapture

	// FieldsUnknown means the decision may depend on any part of the event.
	FieldsUnknown = policymeta.FieldsUnknown
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

	// Process-context capture fields (ABI v4 JSON / declaration vocabulary).
	// They are kept out of fieldsForEvent until codegen emits host callbacks
	// for them, but their bits are available for declarations and the gate.
	"ppid":        FieldBitPPID,
	"parent_comm": FieldBitParentComm,
	"cgroup_id":   FieldBitCgroupID,

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
// mask of fields any rule for that event type references, plus
// FieldBitTime/FieldBitContainerAge for rules with a temporal block that
// reads the clock or container age. The default action and rule order are
// constants of the policy, so these inputs fully determine the decision.
//
// A policy with RequireCompleteCapture ORs FieldBitRequireCompleteCapture into
// every event's mask. That bit is a policy-level request for a host-side
// quality gate; it is carried through the same warmor_fields_read declaration
// export and never asserts that the inputs were actually captured well.
func FieldsRead(policy *Policy) map[int]uint32 {
	out := make(map[int]uint32, len(eventTypeIDs))
	for _, et := range eventTypeIDs {
		var m uint32
		if policy != nil && policy.RequireCompleteCapture {
			m |= FieldBitRequireCompleteCapture
		}
		for _, r := range rulesForEvent(policy, et.name) {
			for _, list := range [][]Condition{r.Conditions.All, r.Conditions.Any, r.Conditions.Not} {
				for _, c := range list {
					m |= FieldBit(c.Field)
				}
			}
			m |= temporalFields(r.Temporal)
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
