# Warmor Feature Status

**Source snapshot:** merged `main` at [`ce1d5ab`](https://github.com/yasindce1998/Warmor/commit/ce1d5abd5a5ad8d78829c3001ff5eb8228964a57), checked 2026-11-14.

This page distinguishes merged implementation from pending work and deployment
evidence. **Warmor is not production-ready; no release is cleared by this status
update.** “Shipped” below means reachable in this source snapshot, not proof of a
published artifact, deployed fleet, or completed production release gate. The
[readiness plan](PRODUCTION_READINESS_PLAN.md) preserves the original assessment
and acceptance gates; its dated findings must not be read as current status.

## Readiness snapshot — 2026-11-14

- [PR #41](https://github.com/yasindce1998/Warmor/pull/41) is now merged: kernel
  policy matching uses **exact structured path/endpoint keys**, not hash-only
  identities. All 36 reported checks at reviewed head `1ea758e` completed with
  34 successes and two intentionally skipped publication jobs; no release ran.
  The [current-head disposable-VM job](https://github.com/yasindce1998/Warmor/actions/runs/43618178948/job/132517792957)
  passed (CI merge checkout `6e7b0f0` onto `98d2b90`; retained log
  `.worktrees/pr41-vm-1ea758e.log`). PASS evidence covers idle-reader close,
  exact collisions/default-deny/scope/EPERM, audit non-refusal, truncation,
  IPv6/mapped endpoints, load/attach, and real-daemon baseline, rejected-reload
  last-known-good, audit survival, UID 65534 SIGKILL and clean stop. This is
  evidence for the merged #41 content, **not** full multi-node/workload isolation,
  later generation/Host integrations or production readiness. The earlier
  [`5aa4556` VM success](https://github.com/yasindce1998/Warmor/actions/runs/43615301413/job/132508919164)
  is historical branch evidence, not a substitute for the reviewed-head run.
- Reload drains userspace event handling and guards stale cache/map writes, but
  the legacy kernel map rebuild is **not generation-atomic**. Default-deny misses
  may allow during rebuilding; rollback can leave degraded kernel state.
- CRs report **Published, not Applied**; `Applied=Unknown`, `Ready=False` awaits
  authenticated node acknowledgement. All non-nil selectors, including `{}`, stay
  **Pending**. Library identity/manifest work does not enable workload routing.
- **Resolved since `98d2b90`:** the earlier merged regression had
  [`manifest.SupportedCompilerVersion`](../internal/workload/manifest/manifest.go)
  pinned to `"6"` while [`compiler.Version`](../internal/compiler/schema.go) was
  `"7"`, rejecting manifest construction. #41 includes reviewed compatibility
  change `5a0bf5a` and real compiled-composition regressions; both versions are
  now **7**. This is **no longer a current-main blocker**. Manifest preparation
  still does not enable daemon/kernel workload routing.
- **Remote protection / release blocker:** read-only GitHub API checks on
  2026-11-14, while main was `98d2b90`, returned `protected: false` for
  [`branches/main`](https://api.github.com/repos/yasindce1998/Warmor/branches/main)
  and `[]` for [repository rulesets](https://api.github.com/repos/yasindce1998/Warmor/rulesets).
  Merged release workflow checks do not configure repository protection. No
  protection was changed and no release or CI run was triggered for this update.

### Merged readiness milestones (all dated 2026-11-14)

This is the merged subset of PRs #28–50, not a declaration that their larger
readiness work packages are complete. Evidence details live in the linked PRs
and focused documents, not in a new measurement or test run for this page.

| Merged PRs | Milestone | Remaining boundary |
|---|---|---|
| [#28](https://github.com/yasindce1998/Warmor/pull/28), [#29](https://github.com/yasindce1998/Warmor/pull/29), [#50](https://github.com/yasindce1998/Warmor/pull/50) | Strict policy semantics, bounded YAML expansion/document framing, ABI 5 argv/operation transport, audit safeguards, credential-bound agent APIs | Missing/truncated sensor input and real-node posture validation remain |
| [#30](https://github.com/yasindce1998/Warmor/pull/30), [#31](https://github.com/yasindce1998/Warmor/pull/31), [#32](https://github.com/yasindce1998/Warmor/pull/32) | Dashboard HTTP safety, verified pidfd targeting/outcomes, isolated bounded sink delivery | Termination is asynchronous; accepted SIGKILL is not syscall prevention; sinks are not lossless |
| [#33](https://github.com/yasindce1998/Warmor/pull/33), [#45](https://github.com/yasindce1998/Warmor/pull/45) | Guest initialization/allocator/preflight limits; separate supervised WASM-host API and command | Daemon still uses in-process evaluator; hard compilation isolation is not a completed release gate |
| [#34](https://github.com/yasindce1998/Warmor/pull/34), [#37](https://github.com/yasindce1998/Warmor/pull/37) | Bounded canary library, intelligence lifecycle and rolling drift | Automatic rollback unwired; daemon drift remains local-only |
| [#35](https://github.com/yasindce1998/Warmor/pull/35), [#44](https://github.com/yasindce1998/Warmor/pull/44), [#46](https://github.com/yasindce1998/Warmor/pull/46) | CRI identity preparation, node-local coordinator and bounded selection/composition libraries | Not wired into daemon/controller/kernel routing; compiler 6/7 compatibility regression resolved by #41 |
| [#36](https://github.com/yasindce1998/Warmor/pull/36), [#42](https://github.com/yasindce1998/Warmor/pull/42) | Dependency remediation; tested, digest-verified release artifact publication gates | Not a current vulnerability clearance or release approval; remote protection still absent |
| [#38](https://github.com/yasindce1998/Warmor/pull/38), [#49](https://github.com/yasindce1998/Warmor/pull/49) | Durable fleet state, drained activation and revision acknowledgement; explicit opt-in signed assignments with replay protection | Legacy kernel rebuild; local single-writer storage; signed mode is standalone, not combined with kernel generations or supervised Host |
| [#39](https://github.com/yasindce1998/Warmor/pull/39), [#40](https://github.com/yasindce1998/Warmor/pull/40) | Private recording/tool contracts; controller last-known-good publication and Kubernetes runtime safety | Incomplete capture is not replay equivalence; publication/local readiness is not per-node applied proof |
| [#41](https://github.com/yasindce1998/Warmor/pull/41) | Exact scoped kernel keys, truthful audit/refusal encoding, idle-reader shutdown, real-daemon VM outcome gate; compiler-7 manifest compatibility | Reviewed head `1ea758e` and current-head VM evidence above; private recording fixture `54d9ea5` retained. Literal path identity is not inode/content/mount-namespace identity; no generation-atomic or multi-node isolation claim |
| [#43](https://github.com/yasindce1998/Warmor/pull/43) | Historical readiness progress checkpoint | Superseded for current merged/open status by this snapshot |

**Not shipped in this snapshot:** acknowledged canary telemetry
[#47](https://github.com/yasindce1998/Warmor/pull/47),
shared policy-host declaration metadata [#48](https://github.com/yasindce1998/Warmor/pull/48),
generation-atomic activation [#51](https://github.com/yasindce1998/Warmor/pull/51),
compiler subprocess cleanup/output bounds [#52](https://github.com/yasindce1998/Warmor/pull/52),
and supervised enforcer Host integration [#53](https://github.com/yasindce1998/Warmor/pull/53).
Authenticated node application receipts and capture-quality accounting are also
unmerged work. Neither pending branch code nor a successful job on another
commit closes a main release gate.

## Status legend

| Status | Meaning |
|--------|---------|
| **Shipped** | Reachable from a binary built from this merged source snapshot, with tests; not release/deployment certification |
| **Partial** | Reachable and works, with real gaps listed in "Known gaps" |
| **Library-only** | Go package exists and has unit tests, but no binary, flag or config value reaches it. It is not wired into the daemon or server. |
| **Experimental** | Code is reachable, but it has not been built or exercised end to end in CI, or its enforcement is known to be incomplete |
| **Missing** | Documented somewhere in the past but no code on `main` |

---

## 1. Linux enforcement core

| Feature | Status | What works today | Known gaps |
|---------|--------|------------------|------------|
| Tracepoint monitoring (execve, openat, connect) | Partial | `warmor-daemon` loads the tracepoint programs and streams events to userspace. The exec tracepoint also captures argv (≤16 args, 63 bytes each) and the parent's comm and PID | Missing/truncated input, ring/queue loss and tracepoint/LSM duplicate context remain coverage limits; complete capture-quality accounting is not merged |
| LSM-BPF hooks (`bprm_check_security`, `file_open`, `socket_connect`, `socket_bind`, `socket_listen`, `ptrace_access_check`, `sb_mount`) | Partial | All 7 attach when `CONFIG_BPF_LSM=y` and `bpf` is in the active LSM list. CI tests the attach in a VM on longterm/stable kernels. With `--lsm-enforce`, a hook returns `-EPERM` **only when the kernel policy map already has a deny entry** for that key. With `--default-deny` (exec/connect only), an **allowlist policy** (`default_action: deny` + exact `eq` rules) is preloaded into the map at startup and a map miss is refused too — see [design/kernel-default-deny.md](design/kernel-default-deny.md) | On a map miss the hook **allows** the operation and emits an event, unless the domain is default-deny marked (opt-in, eligibility-gated). The policy map is not preloaded for non-allowlist policies. If the event ring is full the event is dropped and counted (`warmor_lsm_events_dropped_total`); with `--on-event-loss=deny` an unknown exec/connect is then refused. |
| LSM event delivery (`--lsm-ringbuf-size`, `--on-event-loss`) | Partial | 4 MiB ring by default, batched reader wakeups and per-hook LSM ring-drop counters | Sustained overload still drops events; LSM counters do not account for every tracepoint/userspace/sink loss. October VM delivery/latency results below are historical, not a current lossless guarantee |
| Kernel policy map population (WASM to BPF feedback) | Partial | Exact structured cgroup/path or endpoint keys; tracepoint-origin exec/connect feedback requires complete shared inputs and declarations covered by the key. Sync outcomes are counted, failures rate-limit logged, reload clears/rebuilds state and fences stale persistence | Literal path is not inode/content/mount-namespace identity. Policy-derived paths >127 bytes, unknown cgroups, basename file events, non-connect events and unknown/temporal dependencies do not sync. The 65,536-entry LRU's keys alone cost 18 MiB before values/overhead. LSM-origin decisions are not synced; other hooks do not gain general blocking from this path. Kernel rebuilds remain non-atomic; deploy matching BPF objects/userspace together |
| Userspace deny (all event types) | Partial | Non-audit DENY requests verified process termination. Linux uses pidfds, monotonic event/process lifetime checks and no numeric-PID fallback; attempted/succeeded/failed/refused outcomes are separate. Already kernel-denied LSM events skip duplicate termination | Detect-then-kill happens **after** the operation began/completed. Missing identity, stale events, namespace mismatch, unavailable pidfds or insufficient capabilities can refuse/fail termination; a deny decision is not proof of a kill. See [termination safety](PROCESS_TERMINATION_SAFETY.md) |
| `--audit` mode | Shipped | Overrides kernel and userspace enforcement, including integrity enforce mode and static-rule preloads; Windows uses ETW instead of blocking eBPF hooks. The Helm chart defaults to audit | Standalone CLI still defaults to userspace enforcement unless `--audit` is passed |
| `--lsm-enforce`, `--require-lsm`, `--no-lsm` | Shipped | `--lsm-enforce` enables blocking when LSM loads; `--require-lsm` refuses startup if LSM cannot load; `--no-lsm` skips LSM and conflicts with `--require-lsm` | `--require-lsm` alone does **not** enable blocking. Without `--require-lsm`, unavailable LSM can degrade to tracepoints; without `--lsm-enforce`, loaded LSM policy hooks are audit-only. Global audit overrides blocking. Signed required-default-deny additionally requires both flags and eligible domains |
| `sendto` / `recvfrom` hooks | Missing | None | No such hooks exist |
| Decision cache (userspace) | Partial | 10,000 entries, 5-minute TTL, O(1) LRU; input-aware keys, declared PID elision and temporal bypass. Undeclared ABI ≥3 policies conservatively bypass caching | Guest dependency declarations remain a trust boundary; no workload-generation routing. Do not apply October undeclared-policy hit-rate results to today's cache behavior |
| Hot reload (SIGHUP/file watcher) | Partial | Fresh candidate loads before draining old event handling/actions; failed load preserves the old evaluator. Successful activation resets cache/kernel state and retires old runtime after drain. YAML is compiled by content, not shadowed by sibling WASM | Legacy kernel rebuild has an allow-on-miss window and nontransactional rollback; queued kernel observations have no generation tag. Signed-assignment mode refuses generic reload/SIGHUP/watchers and uses its own activation owner |
| Fail-closed on WASM error | Shipped | An evaluation error, an exceeded `--eval-timeout` (default 50 ms) or the 16 MiB per-instance memory cap is treated as DENY | None known |
| `--log-level` | Shipped | Daemon forwards the setting; enforcer validates and honors it | None known |
| Process lineage | Partial | A tracker and enricher exist and run. The exec tracepoint reports the parent's PID, so Linux ancestry works and `parent_comm` reaches ABI v4 policies | Ancestry is unknown on Windows/macOS events (ETW reports PPID but not into the tracker; macOS reports neither). LSM-origin exec events carry no parent/argv. |
| Cgroup filter (`--cgroup-filter`, `auto`) | Partial | Exact cgroup filtering and periodic pod/descendant reconciliation; discovery/reader failures withdraw local readiness | Auto includes Warmor/system pods, has discovery lag and is not a selector or workload-identity guarantee. Real-node cgroup/CNI/capability validation remains |

## 2. Policy engine and toolchain

| Feature | Status | What works today | Known gaps |
|---------|--------|------------------|------------|
| YAML DSL + `warmor-compile` | Shipped | Strict unknown-key, variable, rule-name, operator/type and numeric-range validation. YAML argv reads captured space-joined argv, not the executable path; network operation reads the actual event operation. Invalid WASM actions fail closed and are not cached/synced | Needs `cargo` and the wasm32 target. Newly compiled argv/network-operation rules require ABI 5 agents. Missing/truncated sensor inputs remain a coverage limitation; see the authoring guide |
| YAML policy passed directly to `warmor-daemon --policy x.yaml` | Partial | The daemon compiles the YAML at load time | Needs `cargo` and the wasm32 target **on the enforcing host**. The distroless container image has neither. Pass a precompiled `.wasm` instead. |
| `examples/policies/*.yaml` | Shipped | 7 example policies, all validate | CI validates every YAML policy with `warmor-compile --validate` and fails on an invalid one. |
| `policies/yaml-example/**` | Shipped | 53 categorized YAML policies, all pass `warmor-compile --validate` | Not tested against live events in CI |
| Rust policy crates (`policies/*`) | Shipped | All 10 crates build for `wasm32-unknown-unknown`, use the JSON ABI (`evaluate_syscall`), and have real-host contract tests (`TestPolicyCrates`), including ABI 4 process context and ABI 3 time context. Wrong export signatures are rejected | `bytes_sent`/`bytes_recv` are unavailable (no sendto/recvfrom hooks). Undeclared ABI ≥3 modules conservatively bypass caching/kernel feedback. Local tests may skip absent crate artifacts; the release gate requires them |
| `warmor-learn` | Partial | Reads ndjson/stdin, including `--follow`, and emits compiler-valid path/endpoint allowlist proposals; rejects unsupported hooks and incomplete target evidence | Offline proposal only, not semantic equivalence or a safe-to-deploy allowlist. See [tool contracts](POLICY_TOOL_CONTRACTS.md) |
| `warmor-simulate` | Partial | Replays `events-*.ndjson` against YAML/WASM; schema v2 private recordings preserve policy input and historical outcomes; legacy/redacted evidence and evaluation errors are reported separately | Replay never signals processes or proves live enforcement/capture completeness. Daemon has no event-store sink; use `--event-sink file:` with the expected filename. `--since` accepts durations and days |
| `warmor-policy-gen` | Shipped | Generates a policy from ndjson audit logs | None known |
| `warmor-sbom-policy` | Shipped | Generates a policy from SPDX/CycloneDX SBOMs | None known |
| `warmor-policy-diff`, `warmor-policy-merge` | Partial | Compiler-validated inputs/output; diff reports defaults, variables, order and rule changes | Structural diff is not equivalence; fingerprint-based `union`/`intersection`/`deny-wins` are editing strategies, not Boolean decision composition |
| `warmor-policy-bundle` | Shipped | OCI push/pull of policy bundles, Ed25519 `--keygen`, `--sign-key`, `--verify-key` | Signature verification only happens in `--pull --verify-key` |
| Policy signature verification in the daemon | Shipped | `--verify-key` checks detached Ed25519 signatures over exact WASM bytes at startup/reload/download; invalid signatures retain the old policy | This mode alone has no assignment authorization or replay protection; YAML is refused. Separate signed-assignment opt-in is described below |
| Signed deployment assignments (`--signed-assignments`, PR #49) | Partial, opt-in | Separate artifact/assignment trust, exact audience/scope, fresh trust/time checks, immutable revisions and durable replay marks. Signed root `assignment.json` in `agentstore` is the **sole publication/startup authority**, replacing legacy `current`/`previous` commits | Merged standalone daemon/relay path only, **not** generation-atomic or supervised Host integration and not evidence of a deployed production fleet. Requires independently provisioned declaration-digest pins and clock-health input; generic reload is refused. See [operator contract](SIGNED_POLICY_ASSIGNMENTS.md) |
| Supervised whole-WASM policy host (PR #45) | Experimental API + dedicated command | Optional Linux API and `warmor-policy-host` executable enforce child limits, descriptor sanitization and kill/reap deadlines | No daemon flag/backend wiring in merged main; default decoding/compilation/evaluation remains in-process. Shared declaration metadata (#48), enforcer integration (#53), packaging and stronger isolation gates are not shipped. See [contract](design/supervised-policy-host.md) |
| Temporal constraints in YAML (`temporal:`) | Shipped | `max_container_age`, `min_container_age`, `time_of_day` (UTC, midnight wrap), `days_of_week`, compiled into the WASM policy; the rule acts outside the window. See [Temporal Policies](temporal-policies.md) | Container age is Linux-only and needs a container cgroup and `hostPID`; unknown age fails closed, so age rules also act on host processes. Event types with temporal rules bypass the decision cache and the kernel fast path. Not allowed on `allow` rules. |

### Current defaults and resource boundaries (source, not measurements)

- [`internal/enforcer/enforcer.go`](../internal/enforcer/enforcer.go) creates
  `runtime.NumCPU()` in-process WASM instances at startup **and reload**, while
  event handling remains serial; no daemon pool-size flag or cgroup-memory-aware
  sizing is shipped. The default is not a single instance or `GOMAXPROCS`.
- [`internal/wasm/runtime.go`](../internal/wasm/runtime.go) limits each instance
  to 256 × 64 KiB pages (**16 MiB**), not total daemon RSS. Guest initialization
  defaults to **5 s per initialization entry point** (load/probe, pool build or
  replacement), not one total daemon-startup deadline; evaluations default to
  **50 ms** (`--eval-timeout`). Module input
  is capped at **64 MiB**. Preflight/context checks do **not** impose hard
  host-side compilation CPU/RSS/wall-time isolation on the default backend.
- [Helm defaults](../deploy/helm/warmor/values.yaml): daemon requests
  **100m CPU / 128Mi**, limits **500m / 256Mi**; controller requests
  **100m / 256Mi**, limits **500m / 1Gi**, cache volume limit **1Gi**. These
  are configured budgets, not evidence that the CPU-sized instance pool fits or
  meets performance targets. Fleet-store and controller publication budgets are
  separate from the WASM runtime cap; see their linked operator contracts.

## 3. Event streaming and observability

| Feature | Status | What works today | Known gaps |
|---------|--------|------------------|------------|
| Event sinks `stdout`, `file:<path>` (with rotation), `webhook:<url>` | Partial | Independent bounded delivery queues; network deadlines/retry budgets; private file recordings; stdout/webhook omit full policy input by default | Queue/retry/shutdown losses are counted best effort, not durable audit delivery. Slow filesystem/stdout and cooperative custom sinks remain limits. See [reliability](streaming-reliability.md) and [privacy](POLICY_TOOL_CONTRACTS.md) |
| SIEM / CEF syslog sink | Partial | `--event-sink syslog:[udp\|tcp://]host:port` (bare address = UDP), CEF formatting and optional MITRE labels | Bounded best-effort delivery, no durable spool or delivery guarantee |
| Prometheus `/metrics` and `/health` on `--metrics-port` | Shipped | `warmor_events_total`, `warmor_cache_*`, `warmor_evaluation_latency_microseconds`, `warmor_policy_info`, `warmor_events_processing_errors_total`, `warmor_audit_denied_total`, plus the LSM-decision, policy-load, heartbeat, agent, WASM-exec and loader-status metrics, and the intelligence gauges (`warmor_attack_graph_*`, `warmor_blast_radius_*`, with `--attack-graph`). The policy server serves its own `warmor_drift_*` gauges on `--metrics-port`. | None known |
| Daemon/controller `/ready` | Partial | Daemon readiness checks the active event loop, capture and configured scope health; controller readiness requires recent successful local reconciliation | Local health is **not** exact-digest node acknowledgement, workload admission control, or proof of prevention. Metrics endpoints need network protection |
| Grafana dashboards / docker-compose monitoring stack | Shipped | Dashboards and alert rules are provisioned and reference updated metrics | None known |
| SSE web dashboard (`/dashboard`) | Shipped | `--dashboard-port <port>` serves `/dashboard` (live policy evaluations over SSE, embedded UI) on its own HTTP server (no write timeout, so streams survive) | Shows policy evaluations only; attack graph and blast radius are exposed as metrics, not in the dashboard UI. Defaults to loopback; optional token-backed Basic auth and explicit `--dashboard-bind` for remote access. Use a TLS/authenticating reverse proxy; see [dashboard access](dashboard.md) |
| Windows Event Viewer | Partial | Service lifecycle messages (`warmor-daemon service install`) | Policy events are not written to Event Viewer |

## 4. Fleet management

| Feature | Status | What works today | Known gaps |
|---------|--------|------------------|------------|
| `warmor-server` REST API and durable state | Partial | Agent/admin APIs, manual rollouts and durable revisions/assignments/registrations; production CLI requires authenticated TLS and `--state-file` unless explicit `--insecure`. Runtime binding ownership follows authenticated identity | Local single-writer snapshot, not HA; full snapshot rewritten on each heartbeat. Embedded defaults can remain ephemeral; drift/canary counters are not durable. See [state/recovery](POLICY_SERVER_STATE.md) |
| mTLS, JWT (HMAC and EdDSA libraries; server uses HMAC) | Shipped | Agent requests require ID matching JWT subject or certificate CommonName; downloads are assignment-limited; cross-runtime binding mutation is refused; admins retain cross-agent access | Migrate generic/shared credentials. Registration labels are still agent-reported, not attested runtime scope |
| Daemon policy download and activation | Partial | Full `(policy ID, version, digest)` comparison; failed activation is retried without advancing active identity. POSIX immutable module/signature revisions preserve a bootable last-known-good pair. Acknowledgement follows drained activation and durable publication | Heartbeat identity is authenticated **self-report**, not an attested node application receipt. Windows `--server` is explicitly refused. Kernel activation is not generation-atomic; revision GC is not implemented. Fallback seed remains incompatible with `--verify-key` |
| Percentage rollouts (A/B, consistent hashing) | Shipped | Create, ramp, complete and abort through the admin API (`warmorctl`'s Rollouts tab is view-only) | Ramping is manual |
| Canary auto-rollback (deny-rate analyzer) | Library-only | `CanaryAnalyzer` exists with tests | Nothing feeds it decisions and nothing calls it. **There is no automatic rollback.** |
| Drift observations / z-score comparison | Partial: local collection ships | `--drift` collects bounded host event-type+comm rates over a rolling ten-minute window. Periodic maintenance expires idle state independently of attack graphs and heartbeats. The daemon omits fingerprints without real workload identity; `--drift-image-key` is deprecated and ignored. Server comparator, authenticated `/api/v1/admin/drift`, and unlabelled `warmor_drift_*` totals remain available for identified integrations. See [design and migration](design/fleet-drift.md) | Daemon fleet submission is withheld pending runtime-backed identity and per-workload collection; no policy-hash fallback. Server fingerprints are in memory and lost on restart |
| `warmorctl` TUI | Shipped | Tabs for dashboard, agents, policies, rollouts and certs. The Certs tab generates a CA, certs and a signing key (keys `g` and `s`). | There is no non-interactive `warmorctl certs generate` or `warmorctl agents list` subcommand |
| `warmor-server policy sign` | Missing | None | Use `warmor-policy-bundle --sign-key` |
| `warmor-daemon --verify-policy-sig --signing-pub` | Missing | Use `--verify-key` | Never existed under these names |

## 5. Container runtime and Kubernetes

| Feature | Status | What works today | Known gaps |
|---------|--------|------------------|------------|
| Helm chart `deploy/helm/warmor` | Partial; audit-first smoke path | Baked WASM, runtime init validation, policy watcher, chart schema/posture checks, probes, image digest overrides and Linux/amd64 scheduling. Default `auditMode: true`, `cgroupFilter: auto`; enforcement requires explicit node-wide confirmation. kind script checks install/readiness/metrics and CR **Published** | kind is installation/reconciliation evidence, not BPF-LSM workload isolation or verified termination. Real-node CNI/capability/namespace/architecture tests remain. Auto includes system/Warmor pods; hostNetwork policy is CNI-dependent. Webhook enablement is rejected until a handler exists |
| `WarmorPolicy` controller (`controller.enabled`) | Partial: publication only | Validates/compiles accepted unscoped CRs into one node-wide artifact, verifies actual bytes/build identity and publishes artifact plus accepted-source journal together. Invalid edits retain prior accepted contributions across restart; deletion removes them. Reports Validated/Compiled/**Published**, with desired/published digests | **Not every-node enforcement:** `Applied=Unknown`, CR `Ready=False`, no active-digest/node-count assertion; legacy `Active` no longer emitted. All non-nil selectors stay **Pending**, retaining any old accepted unscoped source. Off by default, single writer/no leader election, unsigned mutable ConfigMap. All-namespace mode remains single-tenant/admin-only. Apply updated CRD separately before upgrade. See [controller contract](design/warmorpolicy-controller.md) |
| `deploy/kubernetes/warmor-daemonset.yaml` | Experimental | A raw (non-Helm) DaemonSet for server-managed agents: real daemon flags, mTLS certs from a secret, policies persisted under `/var/lib/warmor` and bootstrapped from the image's baked policy via `--policy-fallback` | Not exercised by CI (the Helm chart is the tested path); the mTLS secret and a reachable `warmor-server` must exist first |
| `warmor-oci-hook` (CRI-O / OCI hook) | Experimental | Posts start/stop bindings to the policy server | Not the verified CRI coordinator or a workload-routing path; stored bindings do not enable per-container enforcement. Use only within its documented trust/development limits |
| Per-container policy, containerd integration (`--containerd-socket`, `--per-container-policy`) | Missing | `internal/container` (runtime detection, containerd monitor) is library-only | No flags exist |
| Verified workload identity/coordinator/selection preparation | Library-only | `internal/workload` and coordinator provide immutable verified views and bounded CRI/Pod lifecycle adapters; manifest defines explicit baseline/unknown/host composition, with compiler-7 compatibility restored by #41 | No daemon/controller/enforcer/kernel wiring or event-time lifetime producer. Runtime PID/exclusive-cgroup ownership assumptions require independent validation; selectors remain Pending. See [coordinator boundaries](design/node-workload-coordinator.md) |

## 6. Security intelligence features

| Feature | Status | What works today | Known gaps |
|---------|--------|------------------|------------|
| Supply-chain integrity (`warmor-integrity-scan`, `--integrity-db/--integrity-mode`) | Shipped | Offline scan/verify (`--all` for the whole rootfs). In-kernel exec check: a sleepable LSM program hashes each exec with IMA and refuses unlisted SHA-256s (enforce) or reports them (audit) | VM-tested on IMA-enabled 6.1 and 6.18 kernels built in CI (`ci/kernel/`). Needs `CONFIG_IMA` and IMA hash SHA-256 (checked at startup). Does not cover mmap'd libraries or interpreted scripts passed as arguments. Global allowlist; restart to update. |
| Container escape detection | Shipped | `--escape-detect=alert\|deny`: 7 patterns on real hook data (mount source, ptrace target cgroup, runtime socket connects), scoped to container cgroups; `warmor_escape_alerts_total` | Detection is after the fact (deny terminates the process). Relative-path `/proc/*/ns` opens and non-standard runtime socket paths are not matched. |
| Temporal policies | Shipped | YAML `temporal:` blocks are evaluated inside the compiled WASM policy with the event's time and container age (from the cgroup's oldest process) | See the policy engine row above and [Temporal Policies](temporal-policies.md#limits) |
| Attack graph (MITRE ATT&CK) | Partial | `--attack-graph` correlates events and exports bounded graphs/gauges; idle pruning and capacity eviction bound retained state | Runtime exit/removal identity is not wired; PID/cgroup reuse before expiry remains ambiguous. Bounds/TTL are not authoritative runtime inventory. See [lifecycle contract](../internal/attackgraph/LIFECYCLE.md) |
| Blast radius | Shipped (metrics) | `--attack-graph` also feeds the container-relationship graph; `warmor_blast_radius_reachable{cgroup}` per container | Remote/volume resolution is not implemented, so edges (and the metric) are mostly 0 until container runtime integration lands |
| Pattern matcher helpers (glob/regex) | Library-only | `internal/patterns` | Not wired |
| Network filter (`NetFilter`) | Library-only | `internal/enforcer/netfilter.go` | There are no flags to configure it |
| Process sandbox (`ApplySandbox`) | Library-only | `internal/enforcer/sandbox*.go` | Nothing calls it |

## 7. Other platforms

| Platform | Status | What works today | Known gaps |
|----------|--------|------------------|------------|
| Windows (ETW) | Experimental (beta) | ETW consumer for process, network and file events, tested on a real Windows CI runner. Denials are detect-then-`TerminateProcess` (PID reuse checked). Runs as a Windows service. | Termination happens after the fact |
| Windows (eBPF-for-Windows) | Experimental | Programs and loader are written against the official SDK | The native programs and driver have **never been built or run in CI**. Kernel blocking is unverified. |
| macOS (ESF) | Experimental (detection only) | The ESF client subscribes to AUTH and NOTIFY events | **Every AUTH event is answered ALLOW**, so nothing is blocked. The cgo ESF code is not validated in CI. New macOS releases are tools-only and omit the daemon; older cgo-disabled daemons cannot start ESF. |

## 8. Historical performance — not remeasured for this snapshot

Measured 2026-10-15 on the then-current implementation, with the harness described in
[PERFORMANCE.md](PERFORMANCE.md) (methodology, raw output, caveats). One
otherwise idle laptop under WSL2; kernel numbers are from a nested
KVM VM, not bare metal. "Declared" policies export `warmor_fields_read`
(every compiled YAML policy); "undeclared" ones do not (the test fixture and
every Rust crate under `policies/`).
Cache, activation, runtime and sink behavior have since changed. These retained
numbers are **not measurements of `ce1d5ab`**, a current pod-limit benchmark, or
proof of a production budget. No performance tests were run for this docs update.

| Metric | Design target | Historical result (2026-10-15) |
|--------|---------------|------------------|
| P95 evaluation latency | <100 µs | Hit: 1.2–1.3 µs. Miss: 32 µs (YAML), 38 µs (fixture), 55 µs (Rust `advanced` crate) |
| Kernel fast path (BPF map hit) | <1 µs | BPF program run time 0.07–0.11 µs (connect), 0.34–0.82 µs (exec); connect syscall +0.07 µs. Sending an event costs 0.4–1.6 µs; events reach userspace in batches, up to 5 ms later. `file_open` always sends one |
| Decision cache hit rate | >90% | 95.4% declared, 0% undeclared, on a synthetic stream of short-lived processes |
| Daemon memory | <50 MB | Not met: 60–104 MB RSS declared, 105–128 MB undeclared (in-process harness, lineage tracker full) |
| CPU overhead | <5% | 10k events/s: 11% of one core (0.8% of 14 threads) declared, 83% of one core for the undeclared fixture; the undeclared Rust crate did not keep up (9.2k achieved) |
| Throughput | 100k events/s | 175k events/s declared; 41k (fixture) and 24k (Rust crate) undeclared |

## 9. Remaining release gates

The [readiness plan's required gates](PRODUCTION_READINESS_PLAN.md#required-release-gates)
remain the acceptance criteria, not a claim that no hardening has started. In
particular: configure and verify missing remote protection; review and validate
pending generation/Host work against the existing gates without losing exact-key,
outcome or standalone signed activation guarantees; prove real workload routing
and authenticated application receipts; complete capture/loss, rollback, soak,
multi-node and native-platform validation.
Existing CI formatting, VM attach/IMA and release artifact checks are useful
partial gates, not proof that these remaining gates passed.
