package controlplane

import (
	"time"

	"github.com/yasindce1998/warmor/internal/drift"
	"github.com/yasindce1998/warmor/internal/telemetry"
)

// The following aliases expose the wire types embedded in heartbeats and
// assignments without requiring an external implementation to import this
// module's internal packages. They are aliases, not copies: the reference
// server and stock agents use exactly the same Go types.
type (
	BehaviorFingerprint = drift.BehaviorFingerprint
	TelemetrySession    = telemetry.Session
	TelemetryRevision   = telemetry.Revision
	TelemetryAssignment = telemetry.Assignment
	TelemetrySnapshot   = telemetry.Snapshot
)

// Policy represents a versioned WASM policy with targeting rules.
type Policy struct {
	ID      string `json:"id" yaml:"id"`
	Name    string `json:"name" yaml:"name"`
	Version int64  `json:"version" yaml:"version"`
	// ActiveVersion is the version served to agents outside of an active
	// rollout. It trails Version while a newer upload is staged or rolling out.
	ActiveVersion int64             `json:"active_version" yaml:"active_version"`
	WASMPath      string            `json:"wasm_path" yaml:"wasm_path"`
	WASMHash      string            `json:"wasm_hash" yaml:"wasm_hash"`
	Selector      map[string]string `json:"selector" yaml:"selector"`
	AuditMode     bool              `json:"audit_mode" yaml:"audit_mode"`
	Priority      int               `json:"priority" yaml:"priority"`
	CreatedAt     time.Time         `json:"created_at" yaml:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at" yaml:"updated_at"`
	Description   string            `json:"description,omitempty" yaml:"description,omitempty"`
	// Signed reports whether the latest uploaded version carries a detached
	// ed25519 signature.
	Signed bool `json:"signed" yaml:"signed"`
}

// Agent represents a registered warmor agent with its labels and status.
type Agent struct {
	ID                 string            `json:"id"`
	Hostname           string            `json:"hostname"`
	Labels             map[string]string `json:"labels"`
	PolicyVersion      int64             `json:"policy_version"`
	PolicyID           string            `json:"policy_id,omitempty"`
	PolicyHash         string            `json:"policy_hash,omitempty"`
	ActivationError    string            `json:"activation_error,omitempty"`
	DeploymentSequence uint64            `json:"deployment_sequence,omitempty"`
	EnvelopeHash       string            `json:"envelope_hash,omitempty"`
	LastHeartbeat      time.Time         `json:"last_heartbeat"`
	Status             AgentStatus       `json:"status"`
}

// AgentStatus is the lifecycle state of a registered agent.
type AgentStatus string

const (
	AgentStatusActive       AgentStatus = "active"
	AgentStatusStale        AgentStatus = "stale"
	AgentStatusDisconnected AgentStatus = "disconnected"
)

// RegisterRequest is sent by an agent to register or re-register.
type RegisterRequest struct {
	ID       string            `json:"id"`
	Hostname string            `json:"hostname"`
	Labels   map[string]string `json:"labels"`
}

// HeartbeatRequest is sent periodically by agents.
type HeartbeatRequest struct {
	AgentID            string `json:"agent_id"`
	PolicyVersion      int64  `json:"policy_version"`
	PolicyID           string `json:"policy_id,omitempty"`
	PolicyHash         string `json:"policy_hash,omitempty"`
	ActivationError    string `json:"activation_error,omitempty"`
	DeploymentSequence uint64 `json:"deployment_sequence,omitempty"`
	EnvelopeHash       string `json:"envelope_hash,omitempty"`
	// Fingerprint is the agent's behavioral fingerprint for fleet drift
	// detection. Optional: agents without --drift send plain heartbeats. A
	// control plane must trust the authenticated request identity, not
	// Fingerprint.AgentID.
	Fingerprint *BehaviorFingerprint `json:"fingerprint,omitempty"`
	// Telemetry is optional evidence, never a substitute for the activation
	// acknowledgement above. Legacy agents contribute no canary evidence.
	Telemetry *TelemetrySnapshot `json:"telemetry,omitempty"`
}

// PolicyAssignment is returned to an agent with its applicable policy.
type PolicyAssignment struct {
	Envelope           []byte `json:"envelope,omitempty"`
	DeploymentSequence uint64 `json:"deployment_sequence,omitempty"`
	PolicyID           string `json:"policy_id"`
	Version            int64  `json:"version"`
	WASMHash           string `json:"wasm_hash"`
	WASMPath           string `json:"wasm_path"`
	WASMData           []byte `json:"wasm_data,omitempty"`
	// Signature is the raw ed25519 signature over the WASM bytes, filled in
	// by the agent from HeaderPolicySignature of the WASM download. Empty
	// when the policy is unsigned.
	Signature []byte               `json:"-"`
	Telemetry *TelemetryAssignment `json:"telemetry,omitempty"`
}

// Rollout represents a gradual policy rollout configuration.
type Rollout struct {
	ID            string     `json:"id"`
	PolicyID      string     `json:"policy_id"`
	TargetVersion int64      `json:"target_version"`
	Percentage    int        `json:"percentage"`
	StartedAt     time.Time  `json:"started_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	Status        string     `json:"status"`
}
