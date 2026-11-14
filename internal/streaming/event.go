package streaming

import (
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

// Missing/1 denotes legacy summaries; version 2 preserves evaluator inputs.
const EventSchemaVersion = 2

// SecurityEvent is the unified, enriched event structure emitted by the
// streaming pipeline. It carries both the raw syscall data and the policy
// decision, suitable for SIEM ingestion, fleet aggregation, and A/B analysis.
type SecurityEvent struct {
	SchemaVersion int `json:"schema_version,omitempty"`
	// PolicyInput is authoritative for replay; summary keys are for SIEMs.
	PolicyInput *api.Event `json:"policy_input,omitempty"`
	// Redactors must edit PolicyInput too and append an issue. Field paths are
	// relative to policy_input, e.g. process.args. Never silently erase evidence.
	InputIssues []InputIssue `json:"input_issues,omitempty"`
	ID          string       `json:"id"`
	Timestamp   time.Time    `json:"timestamp"`
	Hostname    string       `json:"hostname"`

	// Source context
	EventType string `json:"event_type"` // exec, file, network, bind, listen, ptrace, mount
	CgroupID  uint64 `json:"cgroup_id,omitempty"`
	PID       uint32 `json:"pid"`
	PPID      uint32 `json:"ppid,omitempty"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	Comm      string `json:"comm"`
	// ContainerStart is when the event's container started, if the
	// enforcer determined it (only for policies that read container age).
	// warmor-simulate replays it so temporal age rules see the same age.
	ContainerStart time.Time `json:"container_start,omitzero"`

	// Event-specific payload
	Filename    string `json:"filename,omitempty"`
	RemoteAddr  string `json:"remote_addr,omitempty"`
	RemotePort  uint16 `json:"remote_port,omitempty"`
	LocalPort   uint16 `json:"local_port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	MountType   string `json:"mount_type,omitempty"`
	MountSource string `json:"mount_source,omitempty"`
	PtraceComm  string `json:"ptrace_target_comm,omitempty"`
	// PtraceTargetCgroup is the cgroup id of the traced process.
	PtraceTargetCgroup uint64 `json:"ptrace_target_cgroup,omitempty"`
	// IntegrityViolation marks an exec whose SHA-256 was not allowlisted.
	IntegrityViolation bool `json:"integrity_violation,omitempty"`
	// KernelEnforced is set when the kernel refused the operation itself.
	KernelEnforced bool `json:"kernel_enforced,omitempty"`

	// Policy decision
	Decision             string `json:"decision"` // allow, deny, log
	Reason               string `json:"reason,omitempty"`
	PolicyRule           string `json:"policy_rule,omitempty"`
	Cached               bool   `json:"cached"`
	Enforced             bool   `json:"enforced"`
	EnforcementAttempted bool   `json:"enforcement_attempted,omitempty"`
	EnforcementError     string `json:"enforcement_error,omitempty"`
	AuditOnly            bool   `json:"audit_only,omitempty"`
	LatencyUS            int64  `json:"latency_us"`

	// Lineage (populated when process tracker is active)
	Lineage []LineageEntry `json:"lineage,omitempty"`

	// Labels for fleet/A/B context
	Labels map[string]string `json:"labels,omitempty"`
}

type InputIssue struct {
	Field string `json:"field"`
	State string `json:"state"` // unknown, truncated, redacted
}

// SummaryForExport removes the full evaluator snapshot without mutating the
// recording. General-purpose stdout/webhook exports opt in to sensitive inputs;
// private file recordings and the simulator store retain them for replay.
func (e *SecurityEvent) SummaryForExport() *SecurityEvent {
	if e == nil || e.PolicyInput == nil {
		return e
	}
	copy := *e
	copy.PolicyInput = nil
	copy.InputIssues = append(append([]InputIssue(nil), e.InputIssues...), InputIssue{"policy_input", "redacted"})
	return &copy
}

// LineageEntry represents one ancestor in the process tree.
type LineageEntry struct {
	PID      uint32 `json:"pid"`
	Comm     string `json:"comm"`
	Filename string `json:"filename,omitempty"`
}
