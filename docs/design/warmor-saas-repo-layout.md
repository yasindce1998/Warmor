# Proposed `warmor-saas` repository layout

Companion to [ADR 0001](adr-0001-warmor-saas-boundary.md). This is a **proposal for the new repository**, kept here because the engine-side contract is defined in this repo. Copy it into `warmor-saas/docs/` when that repo is created.

The engine-side prerequisites now exist: [`pkg/controlplane`](../../pkg/controlplane) (wire types, route/header/query constants, protocol version) and [`pkg/controlplane/conformance`](../../pkg/controlplane/conformance) (executable agent contract).

## Guiding rules

1. `warmor` is a **dependency**, never a template. Pin it in `go.mod`.
2. The SaaS serves the **agent-facing `/api/v1/*` protocol** unchanged so stock `warmor-daemon` works against it.
3. `tenant_id` is derived from authenticated identity and injected into every request context; nothing agent-supplied can select a tenant.
4. No eBPF, WASM, compiler, daemon, or Rust policy code here. No `warmor-server` copy here.
5. Wire types and route constants come from `github.com/yasindce1998/warmor/pkg/controlplane`, not from copied structs.

## Repository tree

```
warmor-saas/
├── cmd/
│   ├── controlplane/        # multi-tenant HTTP API: agent endpoints + admin API
│   │                        #   serves /api/v1/register .../policy .../heartbeat
│   │                        #   etc. with tenant scoping from auth context
│   ├── api/                 # customer-facing REST/GraphQL API (UI + integrations)
│   ├── billing-worker/      # usage metering, invoicing, subscription lifecycle
│   ├── ingest-worker/       # telemetry/event ingestion from agents (buffered)
│   ├── audit-worker/        # immutable tenant audit log exporter
│   └── migrate/             # schema migration runner
│
├── internal/
│   ├── tenant/              # Tenant type, context injection, resolver, limits
│   │                        #   tenant.FromContext(ctx), tenant.Require(ctx)
│   ├── auth/                # JWT verification, mTLS SAN parsing, API keys
│   │                        #   maps credentials -> tenant_id + role; issues agent tokens
│   ├── controlplane/        # SaaS implementation of the /api/v1/* agent protocol
│   │                        #   handlers for register, heartbeat, policy, deployment,
│   │                        #   telemetry, containers; per-tenant policy store & rollouts
│   │                        #   MUST pass warmor/pkg/controlplane/conformance
│   ├── policy/              # policy CRUD, versioning, signing keys, OCI bundle hosting
│   ├── rollout/             # percentage rollouts, canary analysis wired to decisions
│   ├── telemetry/           # event/telemetry storage, retention, per-tenant isolation
│   ├── fleet/               # agent registry, heartbeats, drift, status, quotas
│   ├── billing/             # plans, subscriptions, metering, usage limits, invoices
│   ├── audit/               # append-only audit events, export, retention
│   ├── webhook/             # customer webhooks, SIEM forwarding
│   ├── store/               # Postgres repositories, every query tenant-scoped
│   │                        #   queries take tenantID as first argument (no globals)
│   ├── config/              # env/flag config, secrets loading
│   └── metrics/             # SaaS Prometheus metrics (tenant label policy defined here)
│
├── pkg/                     # public SDK for customers (only deliberate exports)
│   ├── client/              # Go client for the customer API
│   └── contract/            # re-exports warmor/pkg/controlplane wire types for SDK users
│
├── web/                     # web dashboard (framework of choice)
│   ├── src/
│   ├── e2e/                 # Playwright tests
│   └── README.md
│
├── migrations/              # SQL schema migrations (tenant_id on tenant-owned tables)
├── deploy/
│   ├── helm/                # Helm chart for the SaaS services (NOT the engine chart)
│   ├── terraform/           # cloud infra (DB, queues, object storage, secrets)
│   └── compose/             # local development stack
│
├── docs/
│   ├── architecture.md      # SaaS architecture, links back to the engine ADR
│   ├── tenancy.md           # tenant isolation model and threat model
│   ├── protocol.md          # agent protocol compatibility, version negotiation
│   ├── operations.md        # runbooks, on-call, backups
│   └── adr/                 # SaaS-local ADRs; ADR 0001 remains in the engine repo
│
├── test/
│   ├── conformance/         # calls conformance.Run against internal/controlplane
│   ├── e2e/                 # agent -> SaaS control plane -> policy delivery tests
│   └── fixtures/            # sample tenants, agents, policies
│
├── .github/workflows/       # CI: build, conformance, migration, e2e, image publish
├── go.mod                   # module github.com/yasindce1998/warmor-saas
├── Makefile
└── README.md
```

## `go.mod` shape

```go
module github.com/yasindce1998/warmor-saas

go 1.26.0

require github.com/yasindce1998/warmor vX.Y.Z // pinned engine/contract release
```

Notes:

- Consume `warmor/pkg/controlplane` (wire types, route/header constants, conformance suite) from the pinned version; see [`tests/controlplane-consumer`](../../tests/controlplane-consumer) for a working example from a separate module.
- **Do not** try to import `github.com/yasindce1998/warmor/internal/...` — Go forbids it across module paths. If a needed piece is stuck in `internal/`, propose promoting it to this repo's `pkg/`, don't copy it.
- If the SaaS ever needs the engine's agent client, publish it from `pkg/` too; do not vendor a second copy.

## What is deliberately absent

| Not here | Why |
|---|---|
| `bpf/`, `internal/ebpf`, `internal/wasm`, `internal/compiler` | Engine's job; built and released in `warmor` |
| `warmor-daemon`, `warmor-compile`, Rust `policies/` | Distributed from the engine repo |
| A copy of `internal/policyserver` | SaaS implements the protocol against the published contract |
| The engine's Helm chart | Different deployment target; SaaS chart lives in `deploy/helm/` |
| MIT-only assumption for commercial features | Requires a separate licensing decision in the ADR series |

## CI gates specific to this split

1. **Conformance:** run `conformance.Run` against `internal/controlplane` — proves stock agents work.
2. **Tenancy tests:** every store method must fail without a tenant in context; requests with agent-supplied tenant IDs are rejected.
3. **Compatibility:** bumping the pinned `warmor` version runs agent-protocol e2e against the previous agent release.
4. **Contract drift:** a job comparing route constants/headers in the pinned engine version to the SaaS implementation, failing on unannounced divergence.
5. **Migration safety:** schema migrations must be additive/backwards-compatible during rollout windows.

## Suggested creation order

1. Create `warmor-saas` with `go.mod`, `internal/tenant`, `internal/auth`, `internal/controlplane`, and `test/conformance` only. Get a stock agent registering and receiving a policy.
2. Add `internal/store`, `migrations/`, and per-tenant policy CRUD.
3. Add `web/`, `internal/billing`, `internal/audit`, then ops infra.

Keep steps 1–2 free of billing and UI: the risky part is the tenant boundary and protocol compatibility, not the dashboard.
