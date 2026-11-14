# Warmor Feature Status

**Applies to:** current `main` (audited 2026-10-14, re-verified 2026-10-29)

This is the reference for what Warmor ships today. If another document
disagrees with this page, this page is correct and the other document is a bug.
Fixes for many of the gaps below are in progress on separate branches. Each one
updates this page when it merges.

## Status legend

| Status | Meaning |
|--------|---------|
| **Shipped** | Reachable from a shipped binary, works as described, covered by tests |
| **Partial** | Reachable and works, with real gaps listed in "Known gaps" |
| **Library-only** | Go package exists and has unit tests, but no binary, flag or config value reaches it. It is not wired into the daemon or server. |
| **Experimental** | Code is reachable, but it has not been built or exercised end to end in CI, or its enforcement is known to be incomplete |
| **Missing** | Documented somewhere in the past but no code on `main` |

---

## 1. Linux enforcement core

| Feature | Status | What works today | Known gaps |
|---------|--------|------------------|------------|
| Tracepoint monitoring (execve, openat, connect) | Shipped | `warmor-daemon` loads the tracepoint programs and streams events to userspace. The exec tracepoint also captures argv (≤16 args, 63 bytes each) and the parent's comm and PID | None that change correctness |
| LSM-BPF hooks (`bprm_check_security`, `file_open`, `socket_connect`, `socket_bind`, `socket_listen`, `ptrace_access_check`, `sb_mount`) | Partial | All 7 attach when `CONFIG_BPF_LSM=y` and `bpf` is in the active LSM list. CI tests the attach in a VM on longterm/stable kernels. With `--lsm-enforce`, a hook returns `-EPERM` **only when the kernel policy map already has a deny entry** for that key. With `--default-deny` (exec/connect only), an **allowlist policy** (`default_action: deny` + exact `eq` rules) is preloaded into the map at startup and a map miss is refused too — see [design/kernel-default-deny.md](design/kernel-default-deny.md) | On a map miss the hook **allows** the operation and emits an event, unless the domain is default-deny marked (opt-in, eligibility-gated). The policy map is not preloaded for non-allowlist policies. If the event ring is full the event is dropped and counted (`warmor_lsm_events_dropped_total`); with `--on-event-loss=deny` an unknown exec/connect is then refused. |
| LSM event delivery (`--lsm-ringbuf-size`, `--on-event-loss`) | Shipped | 4 MiB ring by default; the reader is woken in batches. Back-to-back connects and opens deliver every event in VM benchmarks. Every dropped event is counted per hook, logged and alerted. | Events reach userspace up to 5 ms after the syscall. A sustained flood beyond the reader's speed still drops events (counted); `file_open` sends an event for every open on the host. |
| Kernel policy map population (WASM to BPF feedback) | Partial | After the WASM policy decides, the daemon writes the decision into the kernel map for **exec (exact path)** and **connect (remote address and port)** events | `file_open`, `socket_bind`, `socket_listen`, `ptrace_access_check` and `sb_mount` never receive kernel entries, so **they never block in the kernel**. Only tracepoint-origin events are synced; LSM-origin events are not. The map is an LRU_HASH (65536 entries) and sync errors are discarded. The map is not cleared on policy reload. The key is cgroup + path or endpoint, so a decision that depended on uid or args applies to every caller. |
| Userspace deny (all event types) | Shipped | When WASM returns DENY and `--audit` is not set, the daemon sends `SIGKILL` to the process | This happens **after** the operation has started or completed (detect-then-kill), not before. Kernel-denied LSM events are re-evaluated and can be acted on twice. |
| `--audit` mode | Shipped | Overrides kernel and userspace enforcement, including integrity enforce mode and static-rule preloads; Windows uses ETW instead of blocking eBPF hooks. The Helm chart defaults to audit | Standalone CLI still defaults to userspace enforcement unless `--audit` is passed |
| `--lsm-enforce`, `--require-lsm`, `--no-lsm` | Shipped | Turn kernel blocking on, fail closed if LSM can't load, or skip LSM | Without `--lsm-enforce` the LSM programs run in audit-only mode |
| `sendto` / `recvfrom` hooks | Missing | None | No such hooks exist |
| Decision cache (userspace) | Partial | 10,000 entries, 5-minute TTL, true O(1) LRU. For policies that declare their fields-read (every compiled YAML policy), the PID is omitted from the key for event types that don't read it; temporal decisions are never cached | Undeclared policies (every Rust crate under `policies/`) always key on PID, so short-lived processes always miss |
| Hot reload (SIGHUP) | Partial | The WASM module is swapped without a restart. A reloaded `.yaml` is always recompiled from its own content (cached by content hash); a sibling `.wasm` never shadows it | The kernel map keeps entries from the old policy |
| Fail-closed on WASM error | Shipped | An evaluation error, an exceeded `--eval-timeout` (default 50 ms) or the 16 MiB per-instance memory cap is treated as DENY | None known |
| `--log-level` | Missing (flag ignored) | The flag is accepted | The enforcer hardcodes `info` |
| Process lineage | Partial | A tracker and enricher exist and run. The exec tracepoint reports the parent's PID, so Linux ancestry works and `parent_comm` reaches ABI v4 policies | Ancestry is unknown on Windows/macOS events (ETW reports PPID but not into the tracker; macOS reports neither). LSM-origin exec events carry no parent/argv. |
| Cgroup filter (`--cgroup-filter`, `auto`) | Shipped | Restricts the LSM programs to the given cgroups | None |

## 2. Policy engine and toolchain

| Feature | Status | What works today | Known gaps |
|---------|--------|------------------|------------|
| YAML DSL + `warmor-compile` | Shipped | Strict unknown-key, variable, rule-name, operator/type and numeric-range validation. YAML argv reads captured space-joined argv, not the executable path; network operation reads the actual event operation. Invalid WASM actions fail closed and are not cached/synced | Needs `cargo` and the wasm32 target. Newly compiled argv/network-operation rules require ABI 5 agents. Missing/truncated sensor inputs remain a coverage limitation; see the authoring guide |
| YAML policy passed directly to `warmor-daemon --policy x.yaml` | Partial | The daemon compiles the YAML at load time | Needs `cargo` and the wasm32 target **on the enforcing host**. The distroless container image has neither. Pass a precompiled `.wasm` instead. |
| `examples/policies/*.yaml` | Shipped | 7 example policies, all validate | CI validates every YAML policy with `warmor-compile --validate` and fails on an invalid one. |
| `policies/yaml-example/**` | Shipped | 53 categorized YAML policies, all pass `warmor-compile --validate` | Not tested against live events in CI |
| Rust policy crates (`policies/*`) | Shipped | All 10 crates build for `wasm32-unknown-unknown`, use the JSON ABI (`evaluate_syscall`), and are run through the real host in CI (`TestPolicyCrates`), including rules on `args`, `parent_comm`, `cgroup_id` and `direction` (ABI version 4) and time context (version 3, `temporal-access`). A module exporting the wrong signature is rejected at load | `bytes_sent`/`bytes_recv` are not sent (no sendto/recvfrom hooks exist yet). Crates do not export `warmor_fields_read`, so their decisions stay PID-keyed in the cache — an arg-dependent decision for a same-PID re-exec can be served stale. |
| `warmor-learn` | Shipped | Reads the ndjson event log written by `--event-sink file:<path>` (or stdin), with `--follow`, and synthesizes a YAML allowlist policy | Learning mode is offline only. The enforcer's `LearningMode` option has no flag. |
| `warmor-simulate` | Shipped | Replays `events-*.ndjson` files in a directory against a `.yaml` or `.wasm` policy | The daemon has no event-store sink. Point `--event-sink file:` at a filename matching `events-*.ndjson` instead. `--since` accepts Go durations and days (`7d`, `1d12h`). |
| `warmor-policy-gen` | Shipped | Generates a policy from ndjson audit logs | None known |
| `warmor-sbom-policy` | Shipped | Generates a policy from SPDX/CycloneDX SBOMs | None known |
| `warmor-policy-diff`, `warmor-policy-merge` | Shipped | Compare and merge YAML policies (`--strategy union\|intersection\|deny-wins`) | None known |
| `warmor-policy-bundle` | Shipped | OCI push/pull of policy bundles, Ed25519 `--keygen`, `--sign-key`, `--verify-key` | Signature verification only happens in `--pull --verify-key` |
| Policy signature verification in the daemon | Shipped | `--verify-key` checks a detached ed25519 `<policy>.sig` over the exact bytes at startup, on every reload and on every server download (verified before writing); fails closed | Rollback to an older module signed with the same key is not prevented. YAML policies are refused with a key set (they are compiled on the node). |
| Temporal constraints in YAML (`temporal:`) | Shipped | `max_container_age`, `min_container_age`, `time_of_day` (UTC, midnight wrap), `days_of_week`, compiled into the WASM policy; the rule acts outside the window. See [Temporal Policies](temporal-policies.md) | Container age is Linux-only and needs a container cgroup and `hostPID`; unknown age fails closed, so age rules also act on host processes. Event types with temporal rules bypass the decision cache and the kernel fast path. Not allowed on `allow` rules. |

## 3. Event streaming and observability

| Feature | Status | What works today | Known gaps |
|---------|--------|------------------|------------|
| Event sinks `stdout`, `file:<path>` (with rotation), `webhook:<url>` | Shipped | `--event-sink`, `--event-file-max`, `--webhook-header`, `--event-labels` | None |
| SIEM / CEF syslog sink | Shipped | `--event-sink syslog:[udp\|tcp://]host:port` (bare `syslog:host:port` = UDP); CEF-formatted events, optionally labeled with MITRE techniques via `--attack-graph` | None |
| Prometheus `/metrics` and `/health` on `--metrics-port` | Shipped | `warmor_events_total`, `warmor_cache_*`, `warmor_evaluation_latency_microseconds`, `warmor_policy_info`, `warmor_events_processing_errors_total`, `warmor_audit_denied_total`, plus the LSM-decision, policy-load, heartbeat, agent, WASM-exec and loader-status metrics, and the intelligence gauges (`warmor_attack_graph_*`, `warmor_blast_radius_*`, with `--attack-graph`). The policy server serves its own `warmor_drift_*` gauges on `--metrics-port`. | None known |
| Grafana dashboards / docker-compose monitoring stack | Shipped | Dashboards and alert rules are provisioned and reference updated metrics | None known |
| SSE web dashboard (`/dashboard`) | Shipped | `--dashboard-port <port>` serves `/dashboard` (live policy evaluations over SSE, embedded UI) on its own HTTP server (no write timeout, so streams survive) | Shows policy evaluations only; attack graph and blast radius are exposed as metrics, not in the dashboard UI. Defaults to loopback; optional token-backed Basic auth and explicit `--dashboard-bind` for remote access. Use a TLS/authenticating reverse proxy; see [dashboard access](dashboard.md) |
| Windows Event Viewer | Partial | Service lifecycle messages (`warmor-daemon service install`) | Policy events are not written to Event Viewer |

## 4. Fleet management

| Feature | Status | What works today | Known gaps |
|---------|--------|------------------|------------|
| `warmor-server` REST API | Shipped | `/api/v1/register`, `/api/v1/heartbeat`, `/api/v1/policy`, `/api/v1/policy/wasm` (agents). `/api/v1/admin/policies[/{id}]`, `/api/v1/admin/agents`, `/api/v1/admin/rollouts[/{id}]`, `/api/v1/admin/drift` (admin JWT). | None |
| mTLS, JWT (HMAC and EdDSA libraries; server uses HMAC) | Shipped | Agent registration, heartbeat and assignment requests require an ID matching the JWT subject or certificate CommonName; downloads are limited to the current assignment. Admin JWTs retain cross-agent access | Existing generic/shared credentials must migrate to per-agent identities. Registration labels are still agent-reported; runtime binding ownership is not enforced yet |
| Daemon policy download from server | Shipped | `--server` with `--poll-interval`; the downloaded WASM replaces `--policy`. `--policy-fallback <path>` seeds a missing `--policy` file (e.g. the policy baked into a container image) so a fresh node can start and register before the first download; the seed never overrides an existing policy and cannot be combined with `--verify-key` | With `--verify-key`, downloads are verified in memory before being written; a bad signature keeps the old policy |
| Percentage rollouts (A/B, consistent hashing) | Shipped | Create, ramp, complete and abort through the admin API (`warmorctl`'s Rollouts tab is view-only) | Ramping is manual |
| Canary auto-rollback (deny-rate analyzer) | Library-only | `CanaryAnalyzer` exists with tests | Nothing feeds it decisions and nothing calls it. **There is no automatic rollback.** |
| Drift observations / z-score comparison | Partial: local collection ships | `--drift` collects bounded host event-type+comm rates over a rolling ten-minute window. Periodic maintenance expires idle state independently of attack graphs and heartbeats. The daemon omits fingerprints without real workload identity; `--drift-image-key` is deprecated and ignored. Server comparator, authenticated `/api/v1/admin/drift`, and unlabelled `warmor_drift_*` totals remain available for identified integrations. See [design and migration](design/fleet-drift.md) | Daemon fleet submission is withheld pending runtime-backed identity and per-workload collection; no policy-hash fallback. Server fingerprints are in memory and lost on restart |
| `warmorctl` TUI | Shipped | Tabs for dashboard, agents, policies, rollouts and certs. The Certs tab generates a CA, certs and a signing key (keys `g` and `s`). | There is no non-interactive `warmorctl certs generate` or `warmorctl agents list` subcommand |
| `warmor-server policy sign` | Missing | None | Use `warmor-policy-bundle --sign-key` |
| `warmor-daemon --verify-policy-sig --signing-pub` | Missing | Use `--verify-key` | Never existed under these names |

## 5. Container runtime and Kubernetes

| Feature | Status | What works today | Known gaps |
|---------|--------|------------------|------------|
| Helm chart `deploy/helm/warmor` | Working (observe-only in kind; e2e-tested) | Installs and the daemon runs: the image bakes in a compiled policy (`/etc/warmor/policy.wasm`), the initContainer validates it in a real WASM runtime, and metrics/health endpoints serve. `--audit`, `--lsm-enforce`, `--require-lsm` and `--cgroup-filter` pass through via `daemon.*` values; custom policies load via `policy.existingConfigMap` (a ConfigMap with a `policy.wasm` key). A kind e2e test in CI (`scripts/kind-e2e.sh`) verifies install → Ready → policy loaded → metrics, then the controller phase (below) verifies apply CR → Active → ConfigMap → hot reload | Kind nodes (and most hosted K8s) lack `CONFIG_BPF_LSM`, so in-cluster the daemon runs tracepoint-only observe mode; kernel enforcement needs `daemon.lsmEnforce` **and** BPF-LSM nodes. The `ValidatingWebhookConfiguration` (disabled by default; `failurePolicy: Ignore` until a handler ships) has no handler behind it. ConfigMap policy updates hot-reload without a pod restart (the daemon watches the policy file on every platform; SIGHUP still works on Unix) |
| `WarmorPolicy` controller (`controller.enabled`) | Working (e2e-tested) | `kubectl apply` a WarmorPolicy and every node enforces it: the controller validates, merges and compiles the CRs into one effective policy (its image carries the Rust toolchain), publishes it in a ConfigMap the DaemonSet mounts, and agents hot-reload via the policy watcher — no restarts. Per-CR `status.phase` (Active/Error/Pending) with a Ready condition; an invalid CR is reported on itself and excluded, never blocking the fleet; with no CRs the baked cluster default is synced. See `docs/design/warmorpolicy-controller.md` | Off by default. CRs in the release namespace only (opt-in `controller.watchAllNamespaces` merges every namespace — single-tenant clusters only). `spec.selector` is held Pending until per-workload policies ship. Controller-mode policies are unsigned, so agents must not use `--verify-key` in this mode. On a fresh install agents crash-loop briefly until the controller's first sync. Controller image ~900 MB (Rust toolchain) |
| `deploy/kubernetes/warmor-daemonset.yaml` | Experimental | A raw (non-Helm) DaemonSet for server-managed agents: real daemon flags, mTLS certs from a secret, policies persisted under `/var/lib/warmor` and bootstrapped from the image's baked policy via `--policy-fallback` | Not exercised by CI (the Helm chart is the tested path); the mTLS secret and a reachable `warmor-server` must exist first |
| `warmor-oci-hook` (CRI-O / OCI hook) | Experimental | Posts container start/stop to `warmor-server /api/v1/containers/bind` | No auth and no TLS (default `http://`), so it works only against `warmor-server --insecure`. The stored bindings are **never consumed**. |
| Per-container policy, containerd integration (`--containerd-socket`, `--per-container-policy`) | Missing | `internal/container` (runtime detection, containerd monitor) is library-only | No flags exist |

## 6. Security intelligence features

| Feature | Status | What works today | Known gaps |
|---------|--------|------------------|------------|
| Supply-chain integrity (`warmor-integrity-scan`, `--integrity-db/--integrity-mode`) | Shipped | Offline scan/verify (`--all` for the whole rootfs). In-kernel exec check: a sleepable LSM program hashes each exec with IMA and refuses unlisted SHA-256s (enforce) or reports them (audit) | VM-tested on IMA-enabled 6.1 and 6.18 kernels built in CI (`ci/kernel/`). Needs `CONFIG_IMA` and IMA hash SHA-256 (checked at startup). Does not cover mmap'd libraries or interpreted scripts passed as arguments. Global allowlist; restart to update. |
| Container escape detection | Shipped | `--escape-detect=alert\|deny`: 7 patterns on real hook data (mount source, ptrace target cgroup, runtime socket connects), scoped to container cgroups; `warmor_escape_alerts_total` | Detection is after the fact (deny terminates the process). Relative-path `/proc/*/ns` opens and non-standard runtime socket paths are not matched. |
| Temporal policies | Shipped | YAML `temporal:` blocks are evaluated inside the compiled WASM policy with the event's time and container age (from the cgroup's oldest process) | See the policy engine row above and [Temporal Policies](temporal-policies.md#limits) |
| Attack graph (MITRE ATT&CK) | Shipped | `--attack-graph`: pipeline enrichers correlate events to technique IDs (`mitre_techniques`/`mitre_tactic` labels on every streamed event) and build per-container kill-chain graphs; `warmor_attack_graph_*` gauges | Container entries are kept after exit (no cgroup-removal → `Graph.Remove` wiring). See [intelligence-chain design](design/intelligence-chain.md) |
| Blast radius | Shipped (metrics) | `--attack-graph` also feeds the container-relationship graph; `warmor_blast_radius_reachable{cgroup}` per container | Remote/volume resolution is not implemented, so edges (and the metric) are mostly 0 until container runtime integration lands |
| Pattern matcher helpers (glob/regex) | Library-only | `internal/patterns` | Not wired |
| Network filter (`NetFilter`) | Library-only | `internal/enforcer/netfilter.go` | There are no flags to configure it |
| Process sandbox (`ApplySandbox`) | Library-only | `internal/enforcer/sandbox*.go` | Nothing calls it |

## 7. Other platforms

| Platform | Status | What works today | Known gaps |
|----------|--------|------------------|------------|
| Windows (ETW) | Experimental (beta) | ETW consumer for process, network and file events, tested on a real Windows CI runner. Denials are detect-then-`TerminateProcess` (PID reuse checked). Runs as a Windows service. | Termination happens after the fact |
| Windows (eBPF-for-Windows) | Experimental | Programs and loader are written against the official SDK | The native programs and driver have **never been built or run in CI**. Kernel blocking is unverified. |
| macOS (ESF) | Experimental (detection only) | The ESF client subscribes to AUTH and NOTIFY events | **Every AUTH event is answered ALLOW**, so nothing is blocked. The cgo ESF code is never compiled in CI (`CGO_ENABLED=0`). Release binaries are built with `CGO_ENABLED=0`, so the released macOS `warmor-daemon` cannot start a platform at all. |

## 8. Performance

Measured 2026-10-15 with the harness described in
[PERFORMANCE.md](PERFORMANCE.md) (methodology, raw output, caveats). One
otherwise idle laptop under WSL2; kernel numbers are from a nested
KVM VM, not bare metal. "Declared" policies export `warmor_fields_read`
(every compiled YAML policy); "undeclared" ones do not (the test fixture and
every Rust crate under `policies/`).

| Metric | Design target | Measured on main |
|--------|---------------|------------------|
| P95 evaluation latency | <100 µs | Hit: 1.2–1.3 µs. Miss: 32 µs (YAML), 38 µs (fixture), 55 µs (Rust `advanced` crate) |
| Kernel fast path (BPF map hit) | <1 µs | BPF program run time 0.07–0.11 µs (connect), 0.34–0.82 µs (exec); connect syscall +0.07 µs. Sending an event costs 0.4–1.6 µs; events reach userspace in batches, up to 5 ms later. `file_open` always sends one |
| Decision cache hit rate | >90% | 95.4% declared, 0% undeclared, on a synthetic stream of short-lived processes |
| Daemon memory | <50 MB | Not met: 60–104 MB RSS declared, 105–128 MB undeclared (in-process harness, lineage tracker full) |
| CPU overhead | <5% | 10k events/s: 11% of one core (0.8% of 14 threads) declared, 83% of one core for the undeclared fixture; the undeclared Rust crate did not keep up (9.2k achieved) |
| Throughput | 100k events/s | 175k events/s declared; 41k (fixture) and 24k (Rust crate) undeclared |

## 9. Hardening backlog (not started on main)

These are planned and none are implemented yet:

- Documented fail-open/fail-closed semantics with a flag
- Kill switch
- BPF pinning across restarts
- LTS kernel matrix (5.15 / 6.1 / 6.6)
- `gofmt` check in CI
