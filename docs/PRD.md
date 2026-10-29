# Product Requirements Document (PRD): warmor

**Project Name:** warmor (WebAssembly + Armor)  
**Tagline:** Cross-platform, Wasm-powered system-level security enforcer  
**Date:** 2026-10-14
**Status:** Phases 1-2 done; phases 3-8 partial; phase 9 mostly library-only. Per-feature reference: [Feature Status](STATUS.md)

---

## Executive Summary

**warmor** is a security enforcement platform that solves the "Policy Portability Problem" by using WebAssembly (WASM) as the policy execution engine and platform-specific hooks (eBPF, ESF, KMD) as the enforcement mechanism. This architecture enables write-once-run-anywhere security policies that work identically across Linux, Windows, and macOS.

### The Core Innovation

Traditional security enforcers (AppArmor, SELinux, eBPF) are:
- **Platform-specific:** Policies written for Linux don't work on Windows
- **Risky:** Kernel-level code bugs can crash systems
- **Static:** Require recompilation or complex restarts to update rules

**warmor** decouples the "Brain" (policy logic in WASM) from the "Hands" (OS-specific syscall interception), creating a portable, safe, and dynamically updatable security enforcement system.

---

## Implementation Status Overview

### Phase Completion

Status as of current `main`. "Partial" means the phase's headline features are reachable from a binary but with gaps listed in [STATUS.md](STATUS.md).

| Phase | Status | What is actually done | Platform |
|-------|--------|----------|----------|
| **Phase 1** | Done | eBPF + WASM integration; execve/openat/connect tracepoints; SIGHUP reload | Linux |
| **Phase 2** | Done, with gaps | ALLOW/DENY/LOG (DENY = `SIGKILL`); decision cache (not LRU, PID in key); Prometheus metrics. `--log-level` is ignored. | Linux |
| **Phase 3** | Partial | Type-safe process/file/network events. **No** `sendto`/`recvfrom` hooks. Overhead measured in [PERFORMANCE.md](PERFORMANCE.md). | Linux |
| **Phase 4** | Partial | Platform abstraction. Windows ETW (detect-then-terminate) works and is tested in CI. eBPF-for-Windows has never been built or run in CI. macOS ESF answers every AUTH event ALLOW and is not compiled in CI. | Linux/Windows/macOS |
| **Phase 5** | Partial | YAML DSL and `warmor-compile` work. The Helm chart does **not** start (no LSM enforce value, YAML policy needs `cargo` in a distroless image). | Linux |
| **Phase 6** | Partial | 7 LSM hooks attach (tested in a VM in CI). Kernel blocking happens only on a policy-map hit, and only exec and connect entries are ever written. A miss is allowed. | Linux |
| **Phase 7** | Partial | Policy server with registration, heartbeats, versioned policies and percentage rollouts. Lineage is partial (no PPID). NetFilter, sandbox and SIEM syslog sink are library-only. | All |
| **Phase 8** | Partial | mTLS/JWT, signed OCI bundles (`warmor-policy-bundle`), daemon signature verification (`--verify-key`) and the `warmorctl` TUI work. The OCI hook is experimental (no auth, bindings unused). containerd and per-container policy are missing. | All |
| **Phase 9** | Mostly library-only | `warmor-learn` and `warmor-simulate` ship. Escape detection and YAML temporal policies ship; in-kernel integrity is experimental (unverified on an IMA kernel in CI). Drift, attack graph, blast radius and canary auto-rollback are library-only (not wired into any binary). | Linux |

### Key Metrics

Measured 2026-10-15 on one laptop; see [PERFORMANCE.md](PERFORMANCE.md) for the method and caveats. Targets are in parentheses.

- **Performance:** P95 1.2–1.3μs on a cache hit; 32μs (YAML policy) to 55μs (Rust crate) on a miss (target <100μs P95)
- **Cache Hit Rate:** 95.4% for policies that declare the fields they read (every YAML policy), 0% for those that do not (target >90%)
- **Memory Usage:** 60–128MB RSS, not met (target <50MB per instance)
- **Platform Support:** Linux enforcing; Windows and macOS experimental
- **Event types:** process, file and network on all platforms; bind, listen, ptrace and mount via LSM on Linux

### Current Implementation Highlights

**Code Status:**
- 30 internal packages. 6 of them (`attackgraph`, `blastradius`, `dashboard`, `drift`, `patterns`, `testing`) are imported by no binary.
- 15 binaries under `cmd/` (13 released tools plus `test-ebpf` and `test-wasm`)
- 10 Rust policy crates. 8 compile; on `main` all of them deny some or all events due to ABI/field mismatches (see [STATUS.md](STATUS.md#2-policy-engine-and-toolchain)).
- 60 YAML example policies: 53 in `policies/yaml-example/` (all validate) and 7 in `examples/policies/` (all validate; CI fails on an invalid policy)
- Tests: Go unit tests with a 40% coverage gate on Linux; LSM attach integration tests in a VM; Windows ETW smoke tests on a real runner

**Documentation:**
- Build guide, Getting Started, Architecture docs, [Feature Status](STATUS.md)
- Platform-specific guides (Linux, Windows, macOS)
- API types and event structures documented

---

## 1. Problem Statement

### 1.1 Current Pain Points

**Fragmentation:**
- Security policies are tightly coupled to specific operating systems
- A policy written for Linux eBPF cannot run on Windows or macOS
- Organizations with hybrid environments must maintain multiple policy implementations
- Cross-platform security teams need different expertise for each OS

**Risk & Safety:**
- Writing kernel-level security logic in C is dangerous
- A bug in an eBPF program can crash the entire system
- Kernel modules introduce security vulnerabilities
- Testing kernel code is complex and risky

**Inflexibility:**
- Updating security policies requires recompilation
- Policy changes often require system restarts
- No hot-reloading capability for security rules
- Difficult to A/B test security policies

**Complexity:**
- Each platform requires different tooling and expertise
- Debugging kernel-level code is extremely difficult
- Limited observability into policy decisions
- Hard to audit and verify security logic

### 1.2 Market Gap

There is no existing solution that provides:
- Cross-platform policy execution with identical behavior
- Safe, sandboxed policy logic that can't crash the system
- Hot-reloadable security policies without service interruption
- A unified interface for syscall interception across all major OSes

---

## 2. The Solution: warmor Architecture

### 2.1 High-Level Concept

**warmor** acts as an intelligent middleman between the OS kernel and applications:

1. **Interception Layer ("The Hands"):** Platform-specific hooks catch system calls and OS events
2. **Policy Engine ("The Brain"):** A sandboxed WASM runtime evaluates each event against security policies
3. **Enforcement Layer:** Based on WASM decisions, the system allows, denies, or logs the operation

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
│              (Native apps making syscalls)                   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  Interception Layer (OS-Specific)            │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────┐      │
│  │   eBPF   │    │   ESF    │    │  eBPF-Windows/   │      │
│  │ (Linux)  │    │ (macOS)  │    │      KMD         │      │
│  └──────────┘    └──────────┘    └──────────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              warmor Daemon (User Space)                      │
│  ┌────────────────────────────────────────────────────┐     │
│  │         WASM Runtime (Wasmtime/Wazero)             │     │
│  │  ┌──────────────────────────────────────────────┐  │     │
│  │  │        policy.wasm (The Brain)               │  │     │
│  │  │  - Evaluate syscall context                  │  │     │
│  │  │  - Apply security rules                      │  │     │
│  │  │  - Return: ALLOW / DENY / LOG                │  │     │
│  │  └──────────────────────────────────────────────┘  │     │
│  └────────────────────────────────────────────────────┘     │
│                                                              │
│  ┌────────────────────────────────────────────────────┐     │
│  │         Decision Cache & Performance Layer         │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │  ALLOW/DENY   │
                    │   Decision    │
                    └───────────────┘
```

### 2.2 Key Architectural Principles

**Separation of Concerns:**
- **Policy Logic (WASM):** Platform-independent, safe, portable
- **Enforcement Mechanism (Native):** Platform-specific, high-performance
- **Management Layer (CLI/API):** Unified interface for all platforms

**Safety First:**
- WASM sandbox prevents policy bugs from crashing the system
- Memory-safe execution environment
- Capability-based security model
- No direct kernel access from policy code

**Performance Optimization:**
- Decision caching to reduce WASM invocations
- Shared memory buffers for high-frequency syscalls
- Batching for bulk operations
- Async processing where possible

---

## 3. Target Audience

### 3.1 Primary Users

**DevSecOps Engineers:**
- Need to enforce consistent security policies across hybrid cloud environments
- Manage Linux containers, Windows servers, and macOS developer machines
- Require rapid policy iteration and testing
- Value safety and auditability

**Site Reliability Engineers (SREs):**
- Need to trace and block malicious behavior without risk of system crashes
- Require real-time policy updates during incidents
- Need detailed observability into security decisions
- Value performance and reliability

**Security Teams:**
- Need to implement zero-trust architectures
- Require consistent policy enforcement across all endpoints
- Need audit trails and compliance reporting
- Value portability and maintainability

### 3.2 Use Cases

**Container Security:**
- Enforce egress restrictions on Kubernetes pods
- Block unauthorized file access in containers
- Prevent privilege escalation attempts
- Monitor and control network connections

**Endpoint Protection:**
- Prevent malware execution on developer machines
- Enforce data loss prevention (DLP) policies
- Control USB device access
- Monitor and block suspicious process behavior

**Compliance & Auditing:**
- Enforce regulatory requirements (PCI-DSS, HIPAA, SOC2)
- Generate audit logs for all security decisions
- Implement least-privilege access controls
- Track and report policy violations

**Zero-Trust Architecture:**
- Implement microsegmentation at the process level
- Enforce identity-based access controls
- Monitor and control lateral movement
- Implement defense-in-depth strategies

---

## 4. Functional Requirements

### 4.1 Core Features (MVP)

#### FR1: Multi-Platform Syscall Interception ("The Hands")

**Linux Implementation:**
- Use eBPF (kprobes/tracepoints) to intercept syscalls
- Support for: `execve`, `openat`, `connect`, `sendto`, `recvfrom` (*on `main`: execve, openat and connect tracepoints, plus 7 LSM hooks; no `sendto`/`recvfrom`*)
- Minimal performance overhead (<5% CPU impact) (*target; measured in [PERFORMANCE.md](PERFORMANCE.md): BPF program 0.11–0.34μs on a policy map hit, about +13–20μs per event sent to userspace in a nested VM*)
- Graceful degradation if eBPF is unavailable

**Windows Implementation:**
- Use eBPF-for-Windows or Kernel-Mode Driver (KMD)
- Hook Win32 API calls and NT syscalls
- Support for: Process creation, File I/O, Network operations
- Signed driver for production deployment

**macOS Implementation:**
- Use Endpoint Security Framework (ESF)
- Support for: Process execution, File operations, Network events
- System Extension for macOS 10.15+
- Notarized for distribution

**Common Interface:**
```rust
struct SyscallEvent {
    timestamp: u64,
    pid: u32,
    uid: u32,
    syscall_id: u32,
    process_path: String,
    arguments: Vec<u8>,
    context: HashMap<String, String>,
}
```

#### FR2: WASM Policy Runtime ("The Brain")

**Runtime Selection:**
- Primary: **Wasmtime** (Rust-based, production-ready)
- Alternative: **Wazero** (Pure Go, no CGO dependencies)
- Support for WASI (WebAssembly System Interface)

**Policy ABI (Application Binary Interface):**
```rust
// Host -> WASM
#[no_mangle]
pub extern "C" fn evaluate_syscall(
    event_ptr: *const u8,
    event_len: usize
) -> i32;

// Return values
const ACTION_ALLOW: i32 = 0;
const ACTION_DENY: i32 = 1;
const ACTION_LOG: i32 = 2;
const ACTION_MODIFY: i32 = 3;
```

**Policy Capabilities:**
- Read syscall context (PID, UID, process path, arguments)
- Access to allow/deny lists
- Pattern matching and regex support
- Time-based rules (e.g., "deny after 6 PM")
- Rate limiting and quota enforcement
- Stateful decision making (track previous events)

**Memory Management:**
- Linear memory allocation for event data
- Efficient serialization (MessagePack or Protocol Buffers)
- Memory limits to prevent DoS
- Automatic cleanup after evaluation

#### FR3: Policy Execution & Decision Making

**Decision Flow:**
1. Syscall intercepted by platform-specific hook
2. Event data serialized and passed to WASM runtime
3. WASM policy evaluates event against rules
4. Decision returned to enforcement layer
5. Action executed (allow/deny/log)
6. Metrics and logs recorded

**Decision Types:**
- **ALLOW:** Syscall proceeds normally
- **DENY:** Syscall blocked, error returned to application
- **LOG:** Syscall allowed but logged for audit
- **MODIFY:** Syscall arguments modified before execution (advanced)

**Performance Requirements** (targets; measured values from [PERFORMANCE.md](PERFORMANCE.md) in italics):
- Policy evaluation: <100μs per syscall (P95) (*hit 1.2–1.3μs; miss 32μs YAML, 55μs Rust crate*)
- Decision caching: 90%+ cache hit rate for repeated patterns (*95.4% declared policies, 0% undeclared*)
- Memory usage: <50MB per enforcer instance (*60–128MB, not met*)
- CPU overhead: <5% on average workload (*11% of one core at 10k events/s, declared policy*)

#### FR4: Hot-Reloading & Policy Management

**Hot-Reload Mechanism:**
- Load new `.wasm` file without stopping the enforcer
- Atomic policy swap (no dropped events)
- Rollback capability if new policy fails
- Version tracking and audit trail

**Policy Lifecycle (original design; `warmor-cli` was never built):**

The shipped equivalents are `warmor-compile` (compile and `--validate`), `warmor-server` with `warmorctl` (deploy, versions, rollouts) and `warmor-policy-bundle` (signed OCI distribution). There is no rollback command; abort a rollout or re-activate a policy version instead.

```bash
# Compile policy from source
warmor-cli compile policy.rs -o policy.wasm

# Validate policy before deployment
warmor-cli validate policy.wasm

# Deploy to enforcer(s)
warmor-cli deploy policy.wasm --target production

# Rollback if needed
warmor-cli rollback --version previous
```

**Policy Storage:**
- Local filesystem for standalone deployment
- Centralized policy repository for fleet management
- Version control integration (Git)
- Signed policies for integrity verification

#### FR5: Observability & Monitoring

**Metrics (Prometheus format):**
```
warmor_syscalls_total{action="allow|deny|log", syscall="execve"}
warmor_policy_evaluation_duration_seconds{quantile="0.5|0.95|0.99"}
warmor_cache_hit_ratio
warmor_policy_version{version="1.2.3"}
warmor_errors_total{type="wasm_panic|timeout|invalid_decision"}
```

**Structured Logging:**
```json
{
  "timestamp": "2026-04-29T14:00:00Z",
  "level": "warn",
  "event": "syscall_denied",
  "pid": 1234,
  "uid": 1000,
  "process": "/usr/bin/curl",
  "syscall": "connect",
  "destination": "1.1.1.1:443",
  "policy_version": "1.2.3",
  "reason": "Egress to public IP blocked",
  "duration_us": 45
}
```

**Audit Trail:**
- All policy decisions logged
- Tamper-proof log storage
- Compliance reporting capabilities
- Integration with SIEM systems

### 4.2 Advanced Features (Post-MVP)

#### FR6: Stateful Policy Engine
- Track process lineage (parent-child relationships)
- Maintain session state across multiple syscalls
- Implement rate limiting per process/user
- Detect anomalous behavior patterns

#### FR7: Policy as Code Framework
- DSL for writing policies in high-level language
- Policy testing framework with mock syscalls
- Policy simulation mode (dry-run)
- Policy composition and inheritance

#### FR8: Distributed Policy Management
- Central policy server for fleet management
- Policy distribution via gRPC/HTTP
- A/B testing for policy changes
- Gradual rollout capabilities

#### FR9: Advanced Enforcement
- Network packet filtering integration
- File system encryption enforcement
- Process sandboxing and isolation
- Resource quota enforcement (CPU, memory, I/O)

---

## 5. Non-Functional Requirements

### 5.1 Performance

These are targets. Measured values (2026-10-15, one laptop, see
[PERFORMANCE.md](PERFORMANCE.md)) are in italics; "declared" policies export
their fields-read declaration (every YAML policy), "undeclared" ones do not.

**Latency** (cache miss, i.e. a WASM evaluation; a hit is P95 1.2–1.3μs):
- P50: <50μs per syscall evaluation (*12μs YAML, 15μs fixture, 25μs Rust crate*)
- P95: <100μs per syscall evaluation (*32μs, 38μs, 55μs*)
- P99: <500μs per syscall evaluation (*81μs, 89μs, 115μs*)

**Throughput:**
- Support 100,000+ syscalls/second per enforcer (*175k events/s declared, 24k–41k undeclared, through the single-goroutine event loop*)
- Horizontal scaling via multiple enforcer instances (*not implemented*)
- Efficient batching for bulk operations (*not implemented*)

**Resource Usage:**
- Memory: <100MB per enforcer instance (*60–104MB declared, 105–128MB undeclared*)
- CPU: <5% overhead on typical workload (*not measured on a real workload; synthetic: 11% of one core at 10k events/s declared*)
- Disk: <10MB for enforcer binary + policies (*not measured*)

### 5.2 Reliability

**Availability:**
- 99.9% uptime for enforcer daemon
- Graceful degradation if WASM runtime fails
- Automatic recovery from transient errors

**Fault Tolerance:** *(on `main`: errors fail closed, but there is no evaluation timeout or memory limit and no circuit breaker)*
- Policy evaluation timeout (default: 1s)
- Fallback to default-deny on errors
- Circuit breaker for failing policies
- Health checks and self-healing

### 5.3 Security

**Isolation:**
- WASM sandbox prevents policy code from accessing kernel
- Capability-based security model
- No network access from policy code (unless explicitly granted)
- Memory isolation between policy evaluations

**Integrity:** *(on `main`: bundles can be signed and verified with `warmor-policy-bundle`; the daemon does not verify before loading)*
- Signed WASM policies
- Cryptographic verification before loading
- Tamper-proof audit logs
- Secure communication channels

### 5.4 Compatibility

**Operating Systems:**
- Linux: Kernel 5.7 minimum, 5.8+ recommended (eBPF support; see [BPF_COMPATIBILITY.md](BPF_COMPATIBILITY.md))
- Windows: Windows 10/11, Server 2019+
- macOS: 10.15+ (Endpoint Security Framework)

**Architectures:**
- x86_64 (primary)
- ARM64 (secondary)
- RISC-V (experimental)

**Container Runtimes:**
- Docker
- containerd
- CRI-O
- Kubernetes (via DaemonSet)

---

## 6. Technical Architecture

The full component and data-flow design lives in
[architecture.md](architecture.md). Summary of the planned components:

- **warmor-daemon** (Go) — the core enforcer: platform-specific event hooks,
  embedded Wazero WASM runtime, policy lifecycle (load/reload/rollback),
  decision caching, metrics. Dependencies: `cilium/ebpf`,
  `tetratelabs/wazero`, `prometheus/client_golang`, `rs/zerolog`.
- **policy.wasm** — the policy module (Rust primary): evaluates events and
  returns decisions. See [rust-policy-examples.md](rust-policy-examples.md)
  for the real ABI.
- **warmor-cli** — a planned management tool that was never built; its
  responsibilities are covered by `warmor-compile`, `warmor-server`,
  `warmorctl` and `warmor-policy-bundle`.

Deployment modes: a standalone daemon running as a systemd service on each
host, or a Kubernetes DaemonSet with policies distributed via the policy
server (the Helm chart — not working on `main`, see [STATUS.md](STATUS.md)).

---

## 7. Implementation Roadmap

The original phase-by-phase checklists (Phases 1–9, "Weeks 1–44") have been
superseded by [STATUS.md](STATUS.md), the per-feature, per-phase reference
of what ships on `main` and what is missing, verified against the code. The
phase-completion table at the top of this document is the condensed view.

In short: Phases 1–2 are done (with gaps), Phases 3–8 are partial, and
Phase 9's intelligence features are mostly library-only. The forward-looking
plan continues below.

---

## 7.1 Future Roadmap (Post-Phase 9)

**Before the items below:** finish the open Phase 2-9 gaps listed in [STATUS.md](STATUS.md). That means kernel default-deny and preloaded rules, daemon signature verification, WASM resource limits, wiring the library-only features, a working Helm chart, and fixing the Rust crate ABIs.

Planned enhancements beyond the current release. Tracked here as the single source of truth (formerly `docs/ROADMAP.md`).

### Cloud & Enterprise Integrations
- **Azure Security Center / Defender integration** — forward policy decisions and threat signals for unified SOC visibility.
- **MDM/Intune enterprise policy deployment** — push Warmor policies to endpoints via Microsoft Intune device-management profiles.
- **AWS Security Hub integration** — emit findings in ASFF format for aggregation in Security Hub dashboards.
- **Policy marketplace** — community-shared, signed policy bundles.

### Windows Platform
- **eBPF-for-Windows kernel enforcement** — synchronous blocking on Windows (beyond current ETW monitoring).
- **Hyper-V isolation for Windows containers** — extend container binding and enforcement to Hyper-V isolated containers.
- **AppContainer full sandbox** — restrict policy-violating processes to AppContainer isolation rather than process termination.
- **Windows Defender Application Control (WDAC) interop** — generate supplemental WDAC policies from Warmor learned baselines.

### macOS Platform
- **System Extensions for network filtering** — use the Network Extension framework to enforce network-level policies.
- **Endpoint Security Framework deep file monitoring** — extend ESF hooks beyond process events to file-create, file-rename, and mount operations.

### Linux Platform
- **ARM64 eBPF support** — validate and optimize BPF programs for ARM64 (Graviton, Ampere) kernels.
- **io_uring syscall filtering** — monitor and enforce policies on io_uring submissions to prevent sandbox bypass.
- **Landlock LSM integration** — generate Landlock rulesets from Warmor policies for unprivileged sandboxing.

### Policy Engine
- **OPA/Rego policy language support** — allow writing policies in Rego alongside WASM and YAML.
- **Policy versioning and rollback** — maintain policy history with one-command rollback to previous versions.
- **Multi-cluster policy federation** — synchronize policies across Kubernetes clusters with conflict resolution.

### Observability
- **OpenTelemetry trace export** — emit per-decision traces with full causal chain (process → file → network).
- **Grafana dashboard templates** — ship pre-built Grafana dashboards for common deployment patterns.
- **Slack/PagerDuty alerting** — native alert routing for high-severity denials and anomaly detection.

---

## 8. Success Metrics

### 8.1 Technical Metrics

**Performance** (targets; measured in [PERFORMANCE.md](PERFORMANCE.md)):
- Policy evaluation latency P95 <100μs (*miss: 32μs YAML, 55μs Rust crate; hit: 1.3μs*)
- CPU overhead <5% on typical workload (*not measured on a real workload*)
- Memory usage <100MB per instance (*60–128MB RSS*)
- Cache hit rate >90% (*95.4% declared policies, 0% undeclared*)

**Reliability:**
- 99.9% uptime
- <0.1% policy evaluation failures
- Zero kernel panics caused by warmor
- <1 second recovery time from failures

**Security:**
- Zero CVEs in first 6 months
- 100% of policies cryptographically signed
- Complete audit trail for all decisions
- <1% false positive rate

### 8.2 Business Metrics

**Adoption:**
- 100+ GitHub stars in first 3 months
- 10+ production deployments in first 6 months
- 5+ community-contributed policies
- 3+ conference talks/blog posts

**Community:**
- 20+ contributors
- 50+ closed issues
- Active Discord/Slack community
- Monthly release cadence

---

## 9. Risks & Mitigation

### 9.1 Technical Risks

**Risk: Performance overhead too high**
- Mitigation: Aggressive caching, batching, async processing
- Fallback: Implement sampling mode (evaluate 1 in N syscalls)

**Risk: WASM runtime instability**
- Mitigation: Use battle-tested runtimes (Wasmtime, Wazero)
- Fallback: Implement circuit breaker and graceful degradation

**Risk: Platform-specific hooks unreliable**
- Mitigation: Extensive testing on each platform
- Fallback: Provide alternative hooking mechanisms

**Risk: Policy bugs cause system instability**
- Mitigation: WASM sandbox prevents kernel access
- Fallback: Policy validation and testing framework

### 9.2 Adoption Risks

**Risk: Too complex for users**
- Mitigation: Excellent documentation and examples
- Fallback: Provide pre-built policies for common use cases

**Risk: Competing solutions emerge**
- Mitigation: Focus on unique value prop (cross-platform WASM)
- Fallback: Build strong community and ecosystem

**Risk: Security concerns about WASM**
- Mitigation: Security audit, clear threat model
- Fallback: Provide traditional policy options

---

## 10. Open Questions & Decisions

### Resolved Questions

1. **WASM Runtime Choice:** ✅ **Wazero** (Pure Go, tetratelabs/wazero v1.11.0)
   - Decision: Wazero chosen for simplicity and no CGO dependencies
   - Trade-off: Slight performance difference vs Wasmtime, but easier deployment

2. **Windows Implementation:** ✅ **eBPF-for-Windows first, per-event-type ETW fallback**
   - Decision: ETW for immediate availability, eBPF-for-Windows where a hook exists
   - Status: ETW working and tested in CI; eBPF-for-Windows never built or run in CI

3. **Policy Language:** ✅ **Rust primary, extensible for others**
   - Decision: Rust for type safety and performance, can support Go/C with WASI
   - Status: YAML-generated Rust policies work. Several hand-written example crates have ABI bugs on `main` (see STATUS.md).

4. **Performance Target:** **<100μs P95**
   - Decision: target kept
   - Result: measured (PERFORMANCE.md). Cache hits P95 1.3μs; WASM evaluations P95 32μs for a YAML policy, 55μs for the Rust `advanced` crate

### Remaining Open Questions

1. **Distribution Model:** Should we create commercial offerings or stay open-source only?
2. **Kubernetes Integration:** Priority for native Helm charts and operator pattern?
3. **State Management:** Should Phase 6 support complex stateful policies? How to persist state?
4. **Network Policies:** Should we integrate with iptables/nftables for network-level enforcement?
5. **Container Runtime Integration:** Prioritize containerd/CRI-O over Docker?
6. **Multi-tenant Support:** Should warmor support multiple isolated policy contexts?
7. **Policy Versioning:** Should policies include version metadata for backwards compatibility?

---

## 11. Conclusion & Current Status

**warmor** is pre-stable. The core idea — policy logic in WASM (brain)
decoupled from OS-specific hooks (hands) — is implemented on Linux and
reachable on Windows and macOS through the same runtime. Enforcement
strength differs sharply by platform and event type.
[STATUS.md](STATUS.md) is the authoritative list.

### Next Priorities

1. Kernel default-deny and preloading static rules; sync all key-determined decisions
2. Fix the Rust crate ABIs, build them in CI, and fix the failing example YAML policies
3. Wire the library-only features (integrity runtime, escape, canary analyzer, SIEM sink)
4. Fix the Helm chart and add a kind e2e test

---

**Last Updated:** 2026-10-29
**Status:** See [STATUS.md](STATUS.md)
