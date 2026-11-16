package controlplane

import "github.com/yasindce1998/warmor/internal/crypto/assignment"

// ProtocolVersion is the version of the agent-facing control-plane protocol
// defined by this package. It covers the /api/v1/* agent routes, their wire
// types and the headers/query parameters below. It does not cover the WASM
// policy ABI, which is versioned separately inside the policy module.
//
// Servers advertise it in HeaderProtocolVersion; agents declare the version
// they implement in HeaderAgentProtocol. An unknown version is ignored, not
// treated as an error, so old agents and new control planes interoperate.
const ProtocolVersion = 1

// ProtocolVersionString is the wire representation of ProtocolVersion.
const ProtocolVersionString = "1"

// APIPrefix is the common prefix of every control-plane route.
const APIPrefix = "/api/v1"

// Agent-facing routes. A hosted control plane must serve these with the same
// methods and semantics; see docs/control-plane-protocol.md.
const (
	RouteRegister           = APIPrefix + "/register"
	RouteHeartbeat          = APIPrefix + "/heartbeat"
	RoutePolicy             = APIPrefix + "/policy"
	RoutePolicyWASM         = APIPrefix + "/policy/wasm"
	RouteDeployment         = APIPrefix + "/deployment"
	RouteTelemetrySession   = APIPrefix + "/telemetry/session"
	RouteContainersBind     = APIPrefix + "/containers/bind"
	RouteContainersPrefix   = APIPrefix + "/containers/"
	RouteAdminTelemetry     = APIPrefix + "/admin/telemetry"
	RouteAdminPolicies      = APIPrefix + "/admin/policies"
	RouteAdminPolicyPrefix  = APIPrefix + "/admin/policies/"
	RouteAdminDeployments   = APIPrefix + "/admin/deployments"
	RouteAdminAgents        = APIPrefix + "/admin/agents"
	RouteAdminRollouts      = APIPrefix + "/admin/rollouts"
	RouteAdminRolloutPrefix = APIPrefix + "/admin/rollouts/"
	RouteAdminDrift         = APIPrefix + "/admin/drift"
)

// Query parameters used by agent requests.
const (
	QueryAgentID        = "agent_id"
	QueryIfVersion      = "if_version"
	QueryIfPolicyID     = "if_policy_id"
	QueryIfHash         = "if_hash"
	QueryPolicyID       = "policy_id"
	QueryVersion        = "version"
	QueryIfSequence     = "if_sequence"
	QueryIfEnvelopeHash = "if_envelope_hash"
	QueryRolloutID      = "rollout_id"
)

// HTTP headers that carry protocol semantics.
const (
	// HeaderProtocolVersion is sent by the server on every agent-facing
	// response and declares the protocol version the server implements.
	HeaderProtocolVersion = "X-Warmor-Protocol-Version"

	// HeaderAgentProtocol is sent by the agent on every request and declares
	// the protocol version the agent implements. Servers must not reject a
	// request because of a value they do not recognise; they may log it.
	HeaderAgentProtocol = "X-Warmor-Agent-Protocol"

	// HeaderPolicySignature carries the base64 Ed25519 signature of the WASM
	// bytes returned by RoutePolicyWASM.
	HeaderPolicySignature = "X-Warmor-Policy-Signature"

	// HeaderRevisionIdentity marks full-identity conditional assignment.
	// Without it a 304 from RoutePolicy must not be trusted as a full
	// version/policy/hash acknowledgement.
	HeaderRevisionIdentity = "X-Warmor-Revision-Identity"

	// HeaderSignedAssignment marks the signed deployment protocol and is
	// required on RouteDeployment responses.
	HeaderSignedAssignment = assignment.ProtocolHeader

	// HeaderTelemetryEpoch and HeaderTelemetrySession carry the authorized
	// telemetry lease issued by RouteTelemetrySession.
	HeaderTelemetryEpoch   = "X-Warmor-Telemetry-Epoch"
	HeaderTelemetrySession = "X-Warmor-Telemetry-Session"
)

// Size limits that are part of the wire contract. A server that rejects a
// larger body or serves a larger module breaks stock agents.
const (
	MaxAgentRequestBodyBytes = 1 << 20
	MaxWASMDownloadSize      = 64 * 1024 * 1024
	MaxSignedBundleBytes     = assignment.MaxBundleBytes
)
