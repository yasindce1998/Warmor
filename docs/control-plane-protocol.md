# Control-plane protocol

This document defines the contract between a `warmor-daemon` agent and a policy
control plane — either the in-tree `warmor-server` or a hosted implementation
such as `warmor-saas`. The Go definition of the contract is
[`pkg/controlplane`](../pkg/controlplane), and its executable form is
[`pkg/controlplane/conformance`](../pkg/controlplane/conformance).

The contract covers the HTTP protocol and its JSON wire types. It does **not**
cover the WASM policy ABI, the policy DSL, the OCI bundle format, or the
enforcement behaviour of the daemon; those are versioned separately.

## Versioning and compatibility

- The protocol version is `1` (`controlplane.ProtocolVersion`). Servers
  advertise it in `X-Warmor-Protocol-Version` on every agent-facing response;
  agents declare what they implement in `X-Warmor-Agent-Protocol` on every
  request.
- The version headers are **advisory**. A server must not reject a request
  because of an unrecognised agent version, and an agent must keep working
  when it does not recognise a server version. They exist for observability
  and for planning deprecations.
- Within version 1, changes must be **additive and backwards compatible**:
  - New JSON fields must be optional on decode and must not change the meaning
    of existing fields.
  - New headers and query parameters must be optional; an old agent ignores
    them.
  - A new endpoint is fine; changing an existing endpoint's method, status
    code, required parameter or payload semantics is not.
  - A WASM module served under an assignment must keep matching the
    `wasm_hash` in that assignment.
- A breaking change requires a new protocol version (v2), normally a new URL
  prefix (`/api/v2`), while `/api/v1` keeps working for at least **two
  releases or 90 days**, whichever is longer.
- Because the agent is shipped in this repo and the hosted control plane in a
  different one, protocol changes land engine-first: change this repo (types,
  constants, conformance suite), release it, then update the SaaS dependency.
  Never change the SaaS side of the wire first.

## Agent-facing endpoints

All routes are under `/api/v1`. Auth is mTLS client certificate or a bearer
token with the agent role; container-runtime routes use the runtime role.
Admin routes require an admin token.

| Route | Method | Purpose |
|---|---|---|
| `/api/v1/register` | POST | Register/re-register an agent with labels. Body: `RegisterRequest`. Returns `Agent`. |
| `/api/v1/heartbeat` | POST | Activation acknowledgement, optional drift fingerprint and telemetry snapshot. Body: `HeartbeatRequest`. |
| `/api/v1/policy` | GET | Poll the assigned policy. Requires `agent_id`; accepts `if_version`, `if_policy_id`, `if_hash`. Returns `PolicyAssignment` or `304`. |
| `/api/v1/policy/wasm` | GET | Download the WASM module. Requires `policy_id`, optionally `version`. Returns bytes plus signature header. |
| `/api/v1/deployment` | GET | Signed-assignment deployment. Requires `if_sequence`, `if_envelope_hash`. Requires signed-assignment protocol header. |
| `/api/v1/telemetry/session` | POST | Issue a telemetry epoch/session lease. |
| `/api/v1/containers/bind`, `/api/v1/containers/{id}` | POST/DELETE | Container-runtime policy bindings. |

Common status codes: `200` success, `201` created (admin), `304` not modified
(policy poll), `400` invalid/missing input, `401/403` authentication and
authorisation, `404` unknown agent/policy, `405` wrong method, `409` stale or
conflicting activation, `503` server unavailable.

## Headers and query parameters

Published as Go constants in
[`pkg/controlplane/protocol.go`](../pkg/controlplane/protocol.go):

| Name | Direction | Meaning |
|---|---|---|
| `X-Warmor-Protocol-Version` | server → agent | Advertised protocol version. |
| `X-Warmor-Agent-Protocol` | agent → server | Agent's implemented version (advisory). |
| `X-Warmor-Policy-Signature` | server → agent | Base64 Ed25519 signature of the WASM bytes. |
| `X-Warmor-Revision-Identity` | server → agent | `1` means a `304` is a full version/policy/hash acknowledgement. Without it agents must not trust a `304`. |
| `X-Warmor-Signed-Assignment` | server → agent | Signed deployment protocol marker. |
| `X-Warmor-Telemetry-Epoch`, `X-Warmor-Telemetry-Session` | server → agent | Telemetry lease identifiers. |

Query parameters: `agent_id`, `if_version`, `if_policy_id`, `if_hash`,
`policy_id`, `version`, `if_sequence`, `if_envelope_hash`, `rollout_id`.

Size limits are part of the contract: agent request bodies ≤ 1 MiB, WASM
downloads ≤ 64 MiB, signed bundles ≤ 90 MiB.

## Implementing a control plane (e.g. `warmor-saas`)

1. Depend on a pinned release of `github.com/yasindce1998/warmor` and import
   `pkg/controlplane`. Do not import `internal/...` and do not copy the wire
   types — aliases for the drift and telemetry payload types are published so
   external modules can name and construct them.
2. Serve the agent-facing routes above with the same auth model. Derive tenant
   identity from the authenticated credential; never accept a tenant ID from
   an agent request. Agent IDs are unique per tenant.
3. Run the conformance suite from one of your Go tests:

   ```go
   func TestAgentContract(t *testing.T) {
       conformance.Run(t, conformance.Config{
           BaseURL:  server.URL,
           AgentID:  "conformance-agent",
           Token:    agentToken, // optional
           PolicyID: "preprovisioned-policy",
       })
   }
   ```

   Provision a policy assigned to that agent before calling `Run`. Passing
   means a stock agent can register, poll, conditionally poll, download WASM
   and heartbeat against your implementation.
4. Fail CI when conformance fails or when the pinned engine version changes
   the contract constants without an announced migration.

The in-tree reference implementation is
[`internal/policyserver/conformance_test.go`](../internal/policyserver/conformance_test.go).
The external-consumer compile check is
[`tests/controlplane-consumer`](../tests/controlplane-consumer).

## Change checklist

When changing anything in this contract:

- [ ] Update `pkg/controlplane` (types/constants) — the single source of truth.
- [ ] Update `pkg/controlplane/conformance` with a positive and, where useful,
      a negative check.
- [ ] Keep `internal/policyserver` on the public constants/types (it uses
      aliases; no copy should be reintroduced).
- [ ] Confirm `go test ./...` and `go test ./...` in
      `tests/controlplane-consumer` pass.
- [ ] If the change is breaking, introduce a new version and follow the
      deprecation window above.
