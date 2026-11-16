# ADR 0001: Separate `warmor-saas` control plane from the Warmor engine

- **Status:** Proposed
- **Date:** 2026-11-16
- **Deciders:** TBD
- **Related:** [PRD](../PRD.md) (Phases 7–9; open question "Multi-tenant Support"), [Feature Status](../STATUS.md), [Policy Server State](../POLICY_SERVER_STATE.md), [signed policy assignments](../SIGNED_POLICY_ASSIGNMENTS.md), [control-plane protocol](../control-plane-protocol.md)

## Context

Warmor is pre-stable, MIT-licensed, and split into an enforcement engine (eBPF/LSM hooks, WASM evaluator, policy compiler, daemon) and a **single-tenant reference control plane** (`warmor-server` plus `internal/policyserver`). Those server-side primitives already exist:

- Agent-facing HTTP API: `/api/v1/register`, `/api/v1/heartbeat`, `/api/v1/policy`, `/api/v1/policy/wasm`, `/api/v1/deployment`, `/api/v1/telemetry/session`, `/api/v1/containers/bind`, `/api/v1/containers/{id}`.
- Admin API under `/api/v1/admin/{policies,agents,rollouts,drift,telemetry,deployments}`, JWT-authenticated with role checks (`requireAgent`, `requireRuntime`, `requireAdmin`) and mTLS support.
- Versioned policies, activation envelopes/sequences, percentage rollouts, signed OCI bundles and detached Ed25519 signatures, telemetry and drift collection.

A hosted SaaS needs additional concerns that do **not** belong in this repo: tenant identity and isolation, billing/subscriptions, quotas, a hosted web UI, multi-tenant persistence, audit logs, and cloud ops.

Two technical constraints shape the boundary:

1. **Go `internal/` rule.** Almost all reusable code here (`internal/policyserver`, `internal/crypto`, `internal/telemetry`, `internal/drift`, …) lives under `github.com/yasindce1998/warmor/internal/...` and **cannot be imported by a separate module**. The public surface used to be just `pkg/api` (event types); this ADR adds `pkg/controlplane`.
2. **Multi-tenancy is not solved here.** The PRD lists "Should warmor support multiple isolated policy contexts?" as an open question; the docs warn against broad multi-tenant Kubernetes claims until namespace/workload isolation passes, and the CRD path is explicitly single-tenant. The current server is file-backed and assumes one fleet.

## Decision

1. **Keep two repositories with one shared contract, not two copies of the engine.** `warmor` stays the open-source engine, agent, and single-tenant reference server. `warmor-saas` is a separate Go module that **depends on** `github.com/yasindce1998/warmor` at a pinned version.
2. **No forking, no copy-pasting of engine code.** The daemon, eBPF programs, WASM host, compiler, and policy-server handlers are never duplicated in `warmor-saas`. Divergence here is the main failure mode.
3. **The contract is the wire protocol, not Go internals.** The SaaS control plane serves the **same agent-facing `/api/v1/*` endpoints and wire types**, so an unmodified `warmor-daemon` can be pointed at either server. It reuses the public types, constants, and conformance suite from `pkg/controlplane`.
4. **A small public surface is published here.** `pkg/controlplane` contains wire types, route/header/query constants, protocol version, and a conformance suite. `internal/policyserver` uses aliases and constants from it, so there is one source of truth. Implementation details stay in `internal/`.
5. **Tenant identity is established by the SaaS auth layer only.** A JWT claim or mTLS certificate maps to a `tenant_id`; the ID is **never** accepted from an agent request body, label, or header. Every query is scoped by that server-derived tenant. Agent IDs are unique **per tenant**, not globally.
6. **State ownership is split.** `warmor-server` keeps its file-backed store for local/single-tenant use. `warmor-saas` owns multi-tenant persistence (its own database, per-tenant scoping/keys, migrations, backups). It does not reuse the engine's JSON store.
7. **Protocol changes flow engine-first, with versioning.** Any change to the agent protocol or WASM ABI lands here first, is covered by the conformance suite, and is rolled to SaaS with a compatibility window. See [control-plane protocol](../control-plane-protocol.md) for the versioning and deprecation policy.
8. **Commercial differentiation lives only in SaaS.** Because the engine is MIT, the moat is the hosted service, UX, intelligence data, and operations — not proprietary changes to the engine. Paid-only features require a separate license decision, not changes to this repo's license.

## Ownership boundary (normative)

| Concern | Owner | Notes |
|---|---|---|
| eBPF/LSM hooks, WASM host, compiler, daemon, Rust policy crates | `warmor` | Engine only; never copied |
| Agent wire protocol, `/api/v1/*` routes, wire types, conformance suite | `warmor` (definition) / `warmor-saas` (production implementation) | Single source of truth in `pkg/controlplane` |
| Single-tenant reference server, local dev, protocol conformance | `warmor` | `warmor-server` |
| Multi-tenant control plane, tenant isolation, auth, keys | `warmor-saas` | Tenant from authenticated identity only |
| Policy storage, rollouts, activation, telemetry ingestion at fleet scale | `warmor-saas` | Reuse semantics, not the file store |
| Billing, subscriptions, quotas, web UI, audit, cloud ops | `warmor-saas` | Never added to this repo |
| Multi-tenancy kernel/K8s isolation | `warmor` (prerequisite) | Must land before SaaS claims workload isolation |

## Consequences

**Positive**
- Independent release cadence, dependencies, and review culture for the cloud product.
- One engine to maintain; agent and enforcement fixes propagate to SaaS via a version bump.
- Clear audit boundary for security reviews: tenant isolation is entirely in one codebase.
- MIT stays intact; no cloud/accounting code pollutes the OSS project.

**Negative / costs**
- Cross-repo coordination: protocol changes require two PRs and a compatibility window.
- Deliberate duplication of the **server implementation** (not the engine): the reference server and SaaS control plane both implement `/api/v1/*`. Mitigated by shared public types and a shared conformance suite.
- Published public types are a compatibility commitment; changes need deprecation cycles.
- A pre-stable engine means the SaaS inherits moving APIs — stabilize the protocol before billing depends on it.

## Alternatives considered

- **Single monorepo / same repo, new directory.** Rejected: mixes cloud and engine concerns, slows OSS contributions, and couples release cycles.
- **Fork Warmor into `warmor-saas`.** Rejected: two divergent engines, double security maintenance, and kernel/WASM fixes would have to be ported forever.
- **SaaS as a thin wrapper around embedded `warmor-server` per tenant.** Deferred: the current server is file-backed and single-fleet; embedding N instances needs a public `Store`/`ServerConfig` seam that does not exist yet. Revisit once multi-tenancy lands in the engine.
- **No OSS repo — make everything proprietary.** Rejected: loses the open-source distribution and community that the project is built around.

## Follow-ups / exit criteria

- [x] Publish `pkg/controlplane` wire types, route/header/query constants and protocol version.
- [x] Publish the conformance suite and run it against the reference server in CI (`internal/policyserver/conformance_test.go`). The SaaS implementation must run the same suite in its own CI.
- [x] Establish protocol version negotiation / deprecation policy — [control-plane protocol](../control-plane-protocol.md).
- [x] Prove an external Go module can consume the contract without importing `internal/` — [`tests/controlplane-consumer`](../../tests/controlplane-consumer), wired into CI.
- [x] Concrete [`warmor-saas` repository layout](warmor-saas-repo-layout.md).
- [ ] Decide tenant-aware agent identity (JWT claim vs mTLS SAN) and document it in the SaaS repo.
- [ ] Resolve engine-side multi-tenancy and workload-isolation gaps from `STATUS.md` before claiming tenant isolation in SaaS. This is the remaining engine-side prerequisite, not covered by the contract work.

## Compliance checklist for PRs touching the boundary

- [ ] No engine code copied into SaaS; dependency is a pinned `warmor` version.
- [ ] Agent-facing routes/types changed in this repo first, with conformance test updated.
- [ ] No breaking change to an existing agent without a versioned path and compatibility window.
- [ ] Tenant ID never read from agent-supplied data.
- [ ] No billing/UI/cloud-only code added to this repo.
