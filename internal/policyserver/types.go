package policyserver

import "time"

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
}

// Agent represents a registered warmor agent with its labels and status.
type Agent struct {
	ID            string            `json:"id"`
	Hostname      string            `json:"hostname"`
	Labels        map[string]string `json:"labels"`
	PolicyVersion int64             `json:"policy_version"`
	LastHeartbeat time.Time         `json:"last_heartbeat"`
	Status        AgentStatus       `json:"status"`
}

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
	AgentID       string `json:"agent_id"`
	PolicyVersion int64  `json:"policy_version"`
}

// PolicyAssignment is returned to an agent with its applicable policy.
type PolicyAssignment struct {
	PolicyID string `json:"policy_id"`
	Version  int64  `json:"version"`
	WASMHash string `json:"wasm_hash"`
	WASMPath string `json:"wasm_path"`
	WASMData []byte `json:"wasm_data,omitempty"`
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
