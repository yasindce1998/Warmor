package ebpf

// Wire-protocol constants shared with the BPF side (see warmor_lsm.h and
// the event_type byte in every emitted event). They are plain protocol
// values, not Linux functionality, so they are defined without a build
// tag: the enforcer and the Windows/macOS policy maps key on them too.

const (
	EventTypeExec    uint8 = 0
	EventTypeFile    uint8 = 1
	EventTypeNetwork uint8 = 2
	EventTypeBind    uint8 = 3
	EventTypeListen  uint8 = 4
	EventTypePtrace  uint8 = 5
	EventTypeMount   uint8 = 6
	// EventTypeIntegrity marks an exec lsm_integrity refused (or, in audit
	// mode, would refuse) because the file's SHA-256 is not allowlisted.
	EventTypeIntegrity uint8 = 7

	ActionAllow uint8 = 0
	ActionDeny  uint8 = 1
)

// Default-deny value bytes (DEFAULT_DENY_MODE_* in warmor_lsm.h). Zero is
// not a valid value, so a missing key reads unambiguously as "not marked".
const (
	DefaultDenyModeDeny  uint8 = 1
	DefaultDenyModeAudit uint8 = 2
)
