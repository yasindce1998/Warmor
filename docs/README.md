# Documentation index

This is the canonical index for Warmor's documentation. For the current feature
status, see [STATUS.md](STATUS.md); for a high-level overview, start with the
[project README](../README.md).

## Start here

| Document | Purpose |
|---|---|
| [Project README](../README.md) | What Warmor is, quick start, headline features and toolchain |
| [Getting Started](../GETTING_STARTED.md) | Install prerequisites, compile a first policy, run the daemon in audit mode |
| [Build Guide](../BUILD.md) | Building from source, make targets, cross-compilation |
| [Feature Status](STATUS.md) | Per-feature snapshot: shipped / partial / library-only / experimental / missing |

## Architecture and contracts

| Document | Purpose |
|---|---|
| [System design](architecture.md) | Data-flow diagrams, components, defaults and phase progress |
| [Control-plane protocol](control-plane-protocol.md) | Agent↔control-plane v1 routes, headers, wire types, conformance suite |
| [Security posture](SECURITY_POSTURE.md) | Fail-open/fail-closed analysis and enforcement postures |
| [Termination safety](PROCESS_TERMINATION_SAFETY.md) | Why a DENY is not prevention; pidfd targeting and lifetime checks |
| [BPF / kernel compatibility](BPF_COMPATIBILITY.md) | Supported kernels, BTF, LSM requirements and CI matrix |
| [Policy tooling and replay contracts](POLICY_TOOL_CONTRACTS.md) | Recording format, redaction and what replay can prove |
| [Streaming reliability](streaming-reliability.md) | Best-effort delivery, bounded queues and shutdown semantics |

## Author and tool policies

| Document | Purpose |
|---|---|
| [Policy authoring](policy-authoring.md) | YAML DSL reference: structure, operators, validation |
| [Rust WASM examples](rust-policy-examples.md) | Rust policy crates, JSON/binary ABI and authoring guide |
| [Temporal policies](temporal-policies.md) | `temporal:` blocks, age/time windows and limits |
| [Policy toolchain](policy-toolchain.md) | Tools from raw inputs to a signed, deployed artifact |
| [Learning mode](learning-mode.md) | `warmor-learn`: synthesizing a policy from recorded events |

## Operate

| Document | Purpose |
|---|---|
| [Operations guide](operations.md) | systemd, fleet management, mTLS, monitoring, Kubernetes |
| [Dashboard access](dashboard.md) | SSE dashboard authentication, bind address and reverse proxy |
| [Durable policy-server state](POLICY_SERVER_STATE.md) | Snapshot format, limits, backup/restore, embedded API |
| [Signed assignments](SIGNED_POLICY_ASSIGNMENTS.md) | Opt-in signed deployment, anti-replay and operator contract |
| [Canary rollout](canary-rollout.md) | Percentage rollouts; library-only auto-rollback analyzer |
| [WarmorPolicy CRD](crd-usage.md) | CRD fields and usage |
| [Performance](PERFORMANCE.md) | Benchmark methodology, raw results and caveats |

## Platforms and roadmap

| Document | Purpose |
|---|---|
| [Linux](PLATFORM_LINUX.md) | eBPF hooks, tracepoints, flags and capabilities |
| [Windows](PLATFORM_WINDOWS.md) | ETW and eBPF-for-Windows paths, event fields, limits |
| [Windows hardening plan](windows-hardening-plan.md) | Forward plan for Windows enforcement |
| [macOS](PLATFORM_MACOS.md) | ESF setup, event types and detection-only status |
| [PRD and roadmap](PRD.md) | Product requirements, phase tracking and roadmap |
| [Production-readiness plan](PRODUCTION_READINESS_PLAN.md) | Historical assessment and required release gates |
| [Production-readiness checklist](PRODUCTION_READINESS_CHECKLIST.md) | Open/closed ledger against current source |

## Security intelligence

| Document | Purpose |
|---|---|
| [Escape detection](escape-detection.md) | Container breakout patterns, flags and limits |
| [Supply-chain integrity](supply-chain-integrity.md) | IMA exec hashing, integrity DB scan/verify |

## Releases and validation

| Document | Purpose |
|---|---|
| [Releasing](RELEASING.md) | Normative release workflow and integrity rules |
| [Release support](RELEASE_SUPPORT.md) | Per-platform release contents; also consumed by release automation |
| [Validation history](VALIDATION_HISTORY.md) | Dated release-gate and dependency-validation evidence |

## Design and history

Live design contracts:

| Document | Purpose |
|---|---|
| [Kernel default-deny](design/kernel-default-deny.md) | Allowlist eligibility and safety ordering for kernel preload |
| [Kernel generations](design/kernel-generations.md) | Map-in-map generation pointer design |
| [Generation activation](design/generation-activation.md) | Commit model and recovery for atomic activation |
| [Generation daemon VM gate](design/generation-daemon-vm.md) | Whole-daemon VM outcome gate for generations |
| [Policy activation](design/policy-activation.md) | Revision identity, activation and recovery semantics |
| [Authenticated node receipts](design/authenticated-node-receipts.md) | Opt-in node self-reports and trust boundary |
| [Canary telemetry](design/canary-acknowledged-telemetry.md) | Report-only telemetry aggregates for canary gates |
| [Fleet drift](design/fleet-drift.md) | Drift collector and server comparator design |
| [Intelligence chain](design/intelligence-chain.md) | Attack graph, blast radius, dashboard and SIEM wiring |
| [WarmorPolicy controller](design/warmorpolicy-controller.md) | Controller design, publication, receipts and probes |
| [Node workload coordinator](design/node-workload-coordinator.md) | Coordinator library boundary |
| [Workload identity](design/workload-identity.md) | Identity/selection preparation boundary |
| [Compiler artifact publication](design/compiler-artifact-publication.md) | How verified WASM artifacts are published |
| [Supervised policy host](design/supervised-policy-host.md) | Opt-in supervised WASM backend contract |
| [Supervised host activation](design/supervised-host-activation.md) | Current-main host integration and flags |
| [Supervised host deployment](design/supervised-host-deployment.md) | Installing and pinning the host binary |
| [Host declarations](design/policyhost-declarations.md) | Shared metadata contract for the supervised host |
| [WASM compilation isolation](design/wasm-compilation-isolation.md) | Why default compilation isolation is not implemented |
| [ABI v4 process context](design/abi-v4-process-context.md) | argv, parent comm and PPID transport |
| [SaaS boundary ADR](design/adr-0001-warmor-saas-boundary.md) | Rationale for a separate hosted control plane |
| [SaaS repository layout](design/warmor-saas-repo-layout.md) | Proposed layout for the new repository |

Frozen integration and review records are consolidated in
[integration history](design/integration-history.md). One earlier node-receipt
review remains separate:
[original receipt reconciliation](design/node-receipts-integration-review.md).
Other frozen records under `docs/design/` are retained as audit evidence for
the supervised-host lineage:
[evaluator integration](design/supervised-evaluator-integration.md),
[evaluator/main](design/supervised-evaluator-main.md),
[evaluator shutdown](design/supervised-evaluator-shutdown.md),
[host outcomes integration](design/supervised-host-outcomes-integration.md) and
[signed/main refresh](design/supervised-host-signed-main.md).
