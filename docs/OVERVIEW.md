# warmor Project Status

**Version:** pre-stable (latest release v0.3.0)
**Last Updated:** 2026-10-14
**Status:** Linux enforcement core works with known gaps. Several later-phase features exist only as libraries. Windows and macOS are experimental.

> The canonical, row-by-row reference is **[Feature Status](STATUS.md)**. This
> page summarizes it by development phase.

---

## Platform Support

| Platform | Status | Technology | Enforcement on `main` |
|----------|--------|------------|-------------|
| **Linux** | Most mature | eBPF tracepoints + LSM-BPF | Kernel `EPERM` for exec/connect decisions already cached in the policy map (`--lsm-enforce`). Everything else is detect-then-`SIGKILL`. |
| **Windows** | Experimental beta | ETW (+ eBPF-for-Windows, unverified) | ETW: detect, then `TerminateProcess`. The eBPF-for-Windows programs have never been built or run in CI. |
| **macOS** | Experimental, detection only | ESF | None. Every AUTH event is answered ALLOW, and the cgo ESF code is not compiled in CI. |

---

## Development Phases

### Phase 1: Linux PoC with WASM Integration — Done
- Go daemon with cilium/ebpf integration
- Wazero WASM runtime, JSON policy ABI
- Tracepoint hooks: execve, openat, connect
- Sample Rust policies, hot reload via SIGHUP

### Phase 2: Enforcement & Decision Making — Done, with gaps
- ALLOW/DENY/LOG actions. DENY is `SIGKILL` of the process.
- Decision cache: 10k entries, 5-minute TTL. It is not a true LRU, and the PID in the key limits hit rate. Hit rate has not been measured.
- Glob pattern matching in the YAML DSL
- Structured logging (zerolog) and Prometheus metrics. `--log-level` is ignored.

### Phase 3: Multi-Syscall Support — Partial
- Type-safe events (ProcessEvent, FileEvent, NetworkEvent)
- Policy testing framework (`internal/testing`)
- There are **no** `sendto`/`recvfrom` hooks
- CPU overhead has not been measured

### Phase 4: Cross-Platform Support — Partial
- Platform abstraction layer (Linux/Windows/macOS)
- Windows: ETW monitoring, tested in CI. The eBPF-for-Windows backend is unverified.
- macOS: ESF client written. AUTH events are always allowed, and the code is not compiled in CI.

### Phase 5: Production Readiness — Partial
- YAML policy DSL with the `warmor-compile` CLI (YAML → Rust → WASM). It needs `cargo` and `wasm32-unknown-unknown`.
- The Kubernetes Helm chart exists but **does not start on `main`**: there is no LSM enforce value, and the YAML policy needs `cargo` in a distroless image.
- Grafana dashboards. Some panels depend on metrics that are never updated.

### Phase 6: LSM-BPF Kernel Enforcement — Partial
- 7 LSM hooks attach: bprm_check_security, file_open, socket_connect, socket_bind, socket_listen, ptrace_access_check, sb_mount. Attach is tested in a VM in CI.
- `BPF_MAP_TYPE_HASH` policy map with FNV-1a keys and cgroup-aware two-tier lookup
- The WASM→BPF feedback loop writes kernel entries **only for exec and connect**. File, bind, listen, ptrace and mount never block in the kernel.
- A map miss is allowed. There is no default-deny mode and no preloading from the compiled policy.
- `--lsm-enforce`, `--require-lsm`, `--no-lsm`, with graceful fallback to tracepoints

### Phase 7: Advanced Features — Partial
- Central policy server (`warmor-server`) with agent registration, heartbeats, versioned policies and percentage rollouts: **shipped**
- Process lineage tracking: partial (events carry no PPID)
- Network filtering, process sandboxing, SIEM (CEF syslog) sink: **library-only**

### Phase 8: Production Infrastructure — Partial
- mTLS (Ed25519) and JWT (HMAC-SHA256 and EdDSA) between agents, runtimes and server: **shipped**
- Signed policies: **shipped**. OCI bundles via `warmor-policy-bundle`, and detached `<policy>.sig` files that `warmor-daemon --verify-key` checks at startup, on reload and on every server download.
- `warmorctl` Bubble Tea TUI (dashboard, agents, policies, rollouts, certs): **shipped**, interactive only
- CRI-O OCI hook: **experimental** (no auth/TLS, bindings unused). containerd integration and per-container policy: **missing**.
- Prometheus metrics: partial (exporter metrics never updated). Grafana and alert rules: partial (one alert references a nonexistent metric).

### Phase 9: Security Intelligence — Mostly library-only
- **Live Policy Synthesis** (`warmor-learn`) — shipped, offline from recorded events
- **Policy Simulator** (`warmor-simulate`) — shipped. The daemon has no event-store sink, and the diff is broken for daemon-recorded events (decision case mismatch).
- **Supply Chain Integrity** (`warmor-integrity-scan`) — offline scan and verify only. No runtime or kernel enforcement.
- **Container Escape Detection** — library only
- **Canary auto-rollback** — library only (manual rollouts are shipped)
- **Drift Detection** — library only
- **Temporal Policies** — library only. The YAML `temporal:` key is silently ignored.
- **Attack Graph** — library only
- **Blast Radius** — library only

---

## Infrastructure

### Windows Service
- `warmor-daemon service install/uninstall` registers the "Warmor Security Enforcer" service
- Service lifecycle messages go to the Windows Event Viewer. Policy events do not.

### Real-Time Dashboard
- `internal/dashboard` (SSE, ring buffer, embedded HTML) is **library-only**. No `/dashboard` route and no `warmor-dashboard` binary exist.

### CI & Coverage
- Linux unit tests with a 40% coverage gate. The LSM attach integration test runs in a VM (longterm and stable kernels).
- Windows CI runs on a real runner and exercises ETW
- macOS CI builds and tests with `CGO_ENABLED=0`, so ESF is not compiled
- No Rust policy crate is built in CI. The example-policy validation step ignores failures.

---

## Key Metrics

These are **design targets, not measurements**. None has been benchmarked on `main`. A benchmark harness is in progress.

| Metric | Target | Measured |
|--------|--------|----------|
| P95 Latency | <100us | Not measured |
| Cache Hit Rate | >90% | Not measured |
| Memory Usage | <50MB | Not measured |
| CPU Overhead | <5% | Not measured |
| Platforms | 3 | 1 enforcing (Linux); 2 experimental |

---

## Documentation

- **[Feature Status](STATUS.md)** — What ships on `main`, feature by feature
- **[Quick Start](quick-start.md)** — Get warmor running on a Linux host
- **[Architecture](architecture.md)** — System design and components
- **[PRD](PRD.md)** — Product requirements, phase tracking, future roadmap
- **[Linux Guide](PLATFORM_LINUX.md)** — eBPF platform
- **[Windows Guide](PLATFORM_WINDOWS.md)** — Experimental ETW/eBPF platform
- **[macOS Guide](PLATFORM_MACOS.md)** — Experimental ESF platform (detection only)
- **[Security Posture](SECURITY_POSTURE.md)** — Fail-open vs fail-closed behavior
- **[BPF Compatibility](BPF_COMPATIBILITY.md)** — Kernel version matrix

### Phase 9: Security Intelligence
- **[Learning Mode](learning-mode.md)** — Shipped: policy synthesis from recorded events
- **[Policy Simulator](policy-simulator.md)** — Shipped: replay events against candidate policies
- **[Supply Chain Integrity](supply-chain-integrity.md)** — Partial: offline binary hash scan/verify
- **[Escape Detection](escape-detection.md)** — Library only
- **[Canary Rollout](canary-rollout.md)** — Manual rollouts shipped; auto-rollback library only
- **[Drift Detection](drift-detection.md)** — Library only
- **[Temporal Policies](temporal-policies.md)** — Library only
- **[Attack Graph](attack-graph.md)** — Library only
- **[Blast Radius](blast-radius.md)** — Library only
