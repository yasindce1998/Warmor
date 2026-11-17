package policymeta

import (
	"sort"

	"github.com/yasindce1998/warmor/pkg/api"
)

// Shared declaration vocabulary. Compiler aliases these exact constants/types
// so its build-section writer can import policymeta without an import cycle.
// New field bits require a contract update; unknown bits never imply finite
// dependency coverage on an older reader.
//
// TRUST DIRECTION. Every bit here is a *worker observation* of what a policy
// says it needs. None of them is evidence that an event actually carried a
// complete value. The host gate (enforcer decision path) derives completeness
// solely from kernel telemetry on the raw api.Event, never from a guest export
// and never from an observation in this package. Declarations may only make
// the gate stricter: they name the inputs a policy needs; they can never
// assert that those inputs were captured well.
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
	FieldBitTime
	FieldBitContainerAge
	// Process-context fields captured by the live sensor (ABI v4 JSON). Their
	// absence in a trusted live event is observable capture loss, so the gate
	// can require them just like it requires an untruncated path.
	FieldBitPPID
	FieldBitParentComm
	FieldBitCgroupID
	// FieldBitRequireCompleteCapture is a policy-level declaration bit, not an
	// event field. A non-unknown fields-read mask carrying this bit means the
	// policy requires complete capture for every capturable field it reads.
	// It is still a worker observation of the policy's NEED: the host never
	// interprets it (or any export) as proof that the inputs were complete.
	FieldBitRequireCompleteCapture
	FieldsUnknown uint32 = 0xFFFFFFFF
)

// CaptureFields is the set of field bits whose captured value can be truncated
// or absent in a live event. Temporal context (wall clock, container age) is
// derived by the host and the require-complete bit is a policy flag, so neither
// belongs here. The host gate intersects a declaration with this mask to learn
// which inputs it must verify before allowing evaluation.
const CaptureFields = FieldBitPID | FieldBitUID | FieldBitGID | FieldBitComm |
	FieldBitPath | FieldBitArgs | FieldBitFlags | FieldBitOperation |
	FieldBitProtocol | FieldBitRemoteAddr | FieldBitRemotePort | FieldBitLocalPort |
	FieldBitPPID | FieldBitParentComm | FieldBitCgroupID

// captureFieldNames maps the field paths used by sensor truncation telemetry
// and streaming.InputIssue to field bits. "filename"/"path" and
// "process.args"/"args" are aliases used by different producers.
var captureFieldNames = map[string]uint32{
	"pid":          FieldBitPID,
	"uid":          FieldBitUID,
	"gid":          FieldBitGID,
	"comm":         FieldBitComm,
	"path":         FieldBitPath,
	"filename":     FieldBitPath,
	"process.path": FieldBitPath,
	"args":         FieldBitArgs,
	"process.args": FieldBitArgs,
	"flags":        FieldBitFlags,
	"operation":    FieldBitOperation,
	"protocol":     FieldBitProtocol,
	"remote_addr":  FieldBitRemoteAddr,
	"remote_port":  FieldBitRemotePort,
	"local_port":   FieldBitLocalPort,
	"ppid":         FieldBitPPID,
	"parent_comm":  FieldBitParentComm,
	"cgroup_id":    FieldBitCgroupID,
}

// RequiredCaptureFields returns the capturable fields a declaration requires
// to be complete. A declaration that did not opt in, or declared FieldsUnknown,
// requires nothing: existing policies keep their current (ungated) behavior.
func RequiredCaptureFields(declared uint32) uint32 {
	if declared == FieldsUnknown || declared&FieldBitRequireCompleteCapture == 0 {
		return 0
	}
	return declared & CaptureFields
}

// CaptureFieldNames lists the capturable field paths set in mask, sorted, for
// log messages and diagnostics. It never interprets the mask as a claim of
// completeness; it only names fields.
func CaptureFieldNames(mask uint32) []string {
	var names []string
	for name, bit := range captureFieldNames {
		if mask&bit != 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// IncompleteCaptureFields is the HOST-SIDE quality mask for an event. It is
// computed from kernel telemetry on the raw event only; no guest export or
// worker observation is consulted, so a module cannot claim its own inputs
// were complete.
//
// TruncatedFields is explicit sensor telemetry and is trusted as-is. A zero or
// absent parent/cgroup is only treated as loss when KernelTimestampNS is
// nonzero (a trusted live kernel sensor); replay/synthetic events and wall-time
// fixtures are never falsely marked incomplete by an unset optional field.
func IncompleteCaptureFields(event *api.Event) uint32 {
	if event == nil {
		return 0
	}
	var mask uint32
	for _, name := range event.TruncatedFields {
		if bit := captureFieldNames[name]; bit != 0 {
			mask |= bit
		}
	}
	if event.KernelTimestampNS != 0 {
		if event.PPID == 0 {
			mask |= FieldBitPPID
		}
		if event.ParentComm == "" {
			mask |= FieldBitParentComm
		}
		if event.CgroupID == 0 {
			mask |= FieldBitCgroupID
		}
	}
	return mask & CaptureFields
}

// FieldQualityStates is the per-field capture state carried to ABI v6 guests
// in JSON. States are "truncated" (a partial value is present) or "unknown"
// (the sensor supplied no value); only non-ok fields are returned.
//
// This is informational carriage, deliberately narrower than the authoritative
// gate mask in IncompleteCaptureFields: it only reports states derivable from
// explicit sensor truncation telemetry or from fields already in the decision
// cache key (parent_comm, cgroup_id). It omits ppid's zero-derived state and
// the trusted-timestamp distinction so a v6 guest cannot distinguish two
// events the host's cache treats identically. The gate and the host callback
// always use the full, host-only, timestamp-guarded mask.
func FieldQualityStates(event *api.Event) map[string]string {
	states := make(map[string]string)
	if event == nil {
		return states
	}
	for _, name := range event.TruncatedFields {
		if _, ok := captureFieldNames[name]; ok {
			states[name] = string(api.CaptureStateTruncated)
		}
	}
	if event.ParentComm == "" {
		states["parent_comm"] = string(api.CaptureStateUnknown)
	}
	if event.CgroupID == 0 {
		states["cgroup_id"] = string(api.CaptureStateUnknown)
	}
	return states
}

// StaticRule contains lossless kernel-key candidates. Action 0/1 and audit
// remain separate; RuleKey deliberately excludes the verdict for duplicate
// detection. No truncated/hash-only key is represented by this type.
type StaticRule struct {
	Event   string
	Action  uint8
	Audit   bool
	Pattern string
	Port    uint16
}
