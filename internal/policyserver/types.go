package policyserver

import "github.com/yasindce1998/warmor/pkg/controlplane"

// The wire types are defined once in the public control-plane contract so a
// hosted implementation can share them without importing this internal
// package. These aliases keep the in-tree server and agent unchanged.
type (
	Policy           = controlplane.Policy
	Agent            = controlplane.Agent
	AgentStatus      = controlplane.AgentStatus
	RegisterRequest  = controlplane.RegisterRequest
	HeartbeatRequest = controlplane.HeartbeatRequest
	PolicyAssignment = controlplane.PolicyAssignment
	Rollout          = controlplane.Rollout
)

const (
	AgentStatusActive       = controlplane.AgentStatusActive
	AgentStatusStale        = controlplane.AgentStatusStale
	AgentStatusDisconnected = controlplane.AgentStatusDisconnected

	// SignatureHeader carries the base64 ed25519 signature of a policy version
	// on its /api/v1/policy/wasm response.
	SignatureHeader = controlplane.HeaderPolicySignature

	// RevisionIdentityHeader marks full-identity conditional assignment support.
	RevisionIdentityHeader = controlplane.HeaderRevisionIdentity
)
