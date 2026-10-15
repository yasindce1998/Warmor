# Warmor Feature Status

**Applies to:** current `main` (audited 2026-10-14)

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
| Tracepoint monitoring (execve, openat, connect) | Shipped | `warmor-daemon` loads the tracepoint programs and streams events to userspace | None that change correctness |
| LSM-BPF hooks (`bprm_check_security`, `file_open`, `socket_connect`, `socket_bind`, `socket_listen`, `ptrace_access_check`, `sb_mount`) | Partial | All 7 attach when `CONFIG_BPF_LSM=y` and `bpf` is in the active LSM list. CI tests the attach in a VM on longterm/stable kernels. With `--lsm-enforce`, a hook returns `-EPERM` **only when the kernel policy map already has a deny entry** for that key | On a map miss the hook **allows** the operation and emits an event. The policy map has no default-deny mode and is not preloaded from the compiled policy. |
| Kernel policy map population (WASM to BPF feedback) | Partial | After the WASM policy decides, the daemon writes the decision into the kernel map for **exec (exact path)** and **connect (remote address and port)** events | `file_open`, `socket_bind`, `socket_listen`, `ptrace_access_check` and `sb_mount` never receive kernel entries, so **they never block in the kernel**. Only tracepoint-origin events are synced; LSM-origin events are not. The map is a plain HASH (65536 entries, no eviction) and sync errors are discarded. The map is not cleared on policy reload. The key is cgroup + path or endpoint, so a decision that depended on uid or args applies to every caller. |
| Userspace deny (all event types) | Shipped | When WASM returns DENY and `--audit` is not set, the daemon sends `SIGKILL` to the process | This happens **after** the operation has started or completed (detect-then-kill), not before. Kernel-denied LSM events are re-evaluated and can be acted on twice. |
| `--audit` mode | Shipped | Deny decisions are logged, nothing is killed, and kernel entries are written as audit-only | None |
| `--lsm-enforce`, `--require-lsm`, `--no-lsm` | Shipped | Turn kernel blocking on, fail closed if LSM can't load, or skip LSM | Without `--lsm-enforce` the LSM programs run in audit-only mode |
| `sendto` / `recvfrom` hooks | Missing | None | No such hooks exist |
| Decision cache (userspace) | Partial | 10,000 entries with a 5-minute TTL | The key includes the PID, so repeat events from new processes always miss. Eviction is O(n) oldest-expiry, not LRU. |
| Hot reload (SIGHUP) | Partial | The WASM module is swapped without a restart | The kernel map keeps entries from the old policy. Reloading a `.yaml` loads a stale sibling `.wasm` if one exists. |
| Fail-closed on WASM error | Partial | An evaluation error is treated as DENY | There is no WASM memory or time limit, so a looping policy hangs the event loop |
| `--log-level` | Missing (flag ignored) | The flag is accepted | The enforcer hardcodes `info` |
| Process lineage | Partial | A tracker and enricher exist and run | Events carry no PPID (the tracker is fed `ppid=0`), so ancestry is empty |
| Cgroup filter (`--cgroup-filter`, `auto`) | Shipped | Restricts the LSM programs to the given cgroups | None |

## 2. Policy engine and toolchain

| Feature | Status | What works today | Known gaps |
|---------|--------|------------------|------------|
| YAML DSL + `warmor-compile` | Shipped | YAML is compiled to Rust and then to `wasm32-unknown-unknown` WASM. `--validate` and `--rust-only` work. | Needs `cargo` and `rustup target add wasm32-unknown-unknown` at compile time. Unknown rule keys are **silently ignored** (a misspelt `temporal:` key is not caught); the `temporal:` block itself is parsed strictly. |
| YAML policy passed directly to `warmor-daemon --policy x.yaml` | Partial | The daemon compiles the YAML at load time | Needs `cargo` and the wasm32 target **on the enforcing host**. The distroless container image has neither. Pass a precompiled `.wasm` instead. |
| `examples/policies/*.yaml` | Shipped | 7 example policies, all validate | CI validates every YAML policy with `warmor-compile --validate` and fails on an invalid one. |
| `policies/yaml-example/**` | Shipped | 53 categorized YAML policies, all pass `warmor-compile --validate` | Not tested against live events in CI |
| Rust policy crates (`policies/*`) | Shipped | All 10 crates build for `wasm32-unknown-unknown`, use the JSON ABI (`evaluate_syscall`), and are run through the real host in CI (`TestPolicyCrates`) | The host does not send `args`, `parent_comm` or `cgroup_id`, so crate rules on those fields never fire. Time context (`wall_clock_unix`, `container_age_ms`) is sent to ABI version 3 modules; `temporal-access` uses it. A module exporting the wrong signature is rejected at load. |
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
| SIEM / CEF syslog sink | Library-only | Sink code exists | No `--event-sink syslog:` spec reaches it |
| Prometheus `/metrics` and `/health` on `--metrics-port` | Partial | `warmor_events_total`, `warmor_cache_*`, `warmor_evaluation_latency_microseconds`, `warmor_policy_info`, `warmor_events_processing_errors_total`, `warmor_audit_denied_total` | The second metric set in `internal/metrics/exporter.go` (LSM decisions, policy loads, heartbeats) is registered but never updated, so Grafana panels built on it are empty. The alert rule for eBPF loader failure references a metric that does not exist. |
| Grafana dashboards / docker-compose monitoring stack | Partial | Dashboards and alert rules are provisioned | Some panels and alerts depend on the never-updated metrics above |
| SSE web dashboard (`/dashboard`, `warmor-dashboard`) | Library-only | `internal/dashboard` exists | There is no `warmor-dashboard` binary and no route serves it |
| Windows Event Viewer | Partial | Service lifecycle messages (`warmor-daemon service install`) | Policy events are not written to Event Viewer |

## 4. Fleet management

| Feature | Status | What works today | Known gaps |
|---------|--------|------------------|------------|
| `warmor-server` REST API | Shipped | `/api/v1/register`, `/api/v1/heartbeat`, `/api/v1/policy`, `/api/v1/policy/wasm` (agents). `/api/v1/admin/policies[/{id}]`, `/api/v1/admin/agents`, `/api/v1/admin/rollouts[/{id}]` (admin JWT). | None |
| mTLS, JWT (HMAC and EdDSA) | Shipped | `warmor-server --ca-cert/--tls-cert/--tls-key/--jwt-secret`. The daemon uses `--server/--tls-ca/--tls-cert/--tls-key/--server-token`. | None |
| Daemon policy download from server | Shipped | `--server` with `--poll-interval`; the downloaded WASM replaces `--policy` | With `--verify-key`, downloads are verified in memory before being written; a bad signature keeps the old policy |
| Percentage rollouts (A/B, consistent hashing) | Shipped | Create, ramp, complete and abort through the admin API or `warmorctl` | Ramping is manual |
| Canary auto-rollback (deny-rate analyzer) | Library-only | `CanaryAnalyzer` exists with tests | Nothing feeds it decisions and nothing calls it. **There is no automatic rollback.** |
| Drift detection (z-score fleet fingerprinting) | Library-only | `internal/drift` | Not wired into server or agents |
| `warmorctl` TUI | Shipped | Tabs for dashboard, agents, policies, rollouts and certs. The Certs tab generates a CA, certs and a signing key (keys `g` and `s`). | There is no non-interactive `warmorctl certs generate` or `warmorctl agents list` subcommand |
| `warmor-server policy sign` | Missing | None | Use `warmor-policy-bundle --sign-key` |
| `warmor-daemon --verify-policy-sig --signing-pub` | Missing | Use `--verify-key` | Never existed under these names |

## 5. Container runtime and Kubernetes

| Feature | Status | What works today | Known gaps |
|---------|--------|------------------|------------|
| Helm chart `deploy/helm/warmor` | Experimental (broken on main) | Templates render | The initContainer's `--validate-policy` check passes, but it only checks the YAML schema. The chart has no `lsmEnforce` value and never passes `--lsm-enforce`. `--set config.*` does nothing. The policy ConfigMap is YAML, which needs `cargo` at runtime that the distroless image lacks, and writes `.wasm` next to a read-only mount. The `ValidatingWebhookConfiguration` (`failurePolicy: Fail`) has no handler behind it. The `ebpf.pinPrograms`, `logging.siem` and `policySync` values are unused. There is no kind e2e test in CI. |
| `WarmorPolicy` CRD | Missing (schema only) | The CRD installs | There is no controller, so resources are stored and never applied |
| `deploy/kubernetes/warmor-daemonset.yaml` | Experimental | None | Configures the daemon through environment variables it does not read, and relies on the default `--policy` path, which is not in the image |
| `warmor-oci-hook` (CRI-O / OCI hook) | Experimental | Posts container start/stop to `warmor-server /api/v1/containers/bind` | No auth and no TLS (default `http://`), so it works only against `warmor-server --insecure`. The stored bindings are **never consumed**. |
| Per-container policy, containerd integration (`--containerd-socket`, `--per-container-policy`) | Missing | `internal/container` (runtime detection, containerd monitor) is library-only | No flags exist |

## 6. Security intelligence features

| Feature | Status | What works today | Known gaps |
|---------|--------|------------------|------------|
| Supply-chain integrity (`warmor-integrity-scan`, `--integrity-db/--integrity-mode`) | Shipped | Offline scan/verify (`--all` for the whole rootfs). In-kernel exec check: a sleepable LSM program hashes each exec with IMA and refuses unlisted SHA-256s (enforce) or reports them (audit) | VM-tested on IMA-enabled 6.1 and 6.18 kernels built in CI (`ci/kernel/`). Needs `CONFIG_IMA` and IMA hash SHA-256 (checked at startup). Does not cover mmap'd libraries or interpreted scripts passed as arguments. Global allowlist; restart to update. |
| Container escape detection | Shipped | `--escape-detect=alert\|deny`: 7 patterns on real hook data (mount source, ptrace target cgroup, runtime socket connects), scoped to container cgroups; `warmor_escape_alerts_total` | Detection is after the fact (deny terminates the process). Relative-path `/proc/*/ns` opens and non-standard runtime socket paths are not matched. |
| Temporal policies | Shipped | YAML `temporal:` blocks are evaluated inside the compiled WASM policy with the event's time and container age (from the cgroup's oldest process) | See the policy engine row above and [Temporal Policies](temporal-policies.md#limits) |
| Attack graph (MITRE ATT&CK) | Library-only | `internal/attackgraph` | Not wired |
| Blast radius | Library-only | `internal/blastradius` | Not wired |
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

None of these numbers have been measured. They are **design targets**, not
results. A benchmark harness is in progress.

| Metric | Design target | Measured on main |
|--------|---------------|------------------|
| P95 evaluation latency | <100 µs | Not measured |
| Kernel fast path (BPF map hit) | <1 µs | Not measured |
| Decision cache hit rate | >90% | Not measured (the PID in the cache key makes this unlikely) |
| Daemon memory | <50 MB | Not measured |
| CPU overhead | <5% | Not measured |
| Throughput | 100k events/s | Not measured |

## 9. Hardening backlog (not started on main)

These are planned and none are implemented yet:

- Documented fail-open/fail-closed semantics with a flag
- Kill switch
- BPF pinning across restarts
- LTS kernel matrix (5.15 / 6.1 / 6.6)
- `gofmt` check in CI
