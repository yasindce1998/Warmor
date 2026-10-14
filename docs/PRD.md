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
| **Phase 3** | Partial | Type-safe process/file/network events. **No** `sendto`/`recvfrom` hooks. Overhead not measured. | Linux |
| **Phase 4** | Partial | Platform abstraction. Windows ETW (detect-then-terminate) works and is tested in CI. eBPF-for-Windows has never been built or run in CI. macOS ESF answers every AUTH event ALLOW and is not compiled in CI. | Linux/Windows/macOS |
| **Phase 5** | Partial | YAML DSL and `warmor-compile` work. The Helm chart does **not** start (nonexistent `--validate-policy` initContainer flag, no LSM enforce value, YAML policy needs `cargo` in a distroless image). | Linux |
| **Phase 6** | Partial | 7 LSM hooks attach (tested in a VM in CI). Kernel blocking happens only on a policy-map hit, and only exec and connect entries are ever written. A miss is allowed. | Linux |
| **Phase 7** | Partial | Policy server with registration, heartbeats, versioned policies and percentage rollouts. Lineage is partial (no PPID). NetFilter, sandbox and SIEM syslog sink are library-only. | All |
| **Phase 8** | Partial | mTLS/JWT, signed OCI bundles (`warmor-policy-bundle`) and the `warmorctl` TUI work. The daemon does not verify signatures. The OCI hook is experimental (no auth, bindings unused). containerd and per-container policy are missing. Exporter metrics are never updated. | All |
| **Phase 9** | Mostly library-only | `warmor-learn` and `warmor-simulate` ship. Integrity is an offline scan only. Escape, drift, temporal, attack graph, blast radius and canary auto-rollback are library-only (not wired into any binary). | Linux |

### Key Metrics

None of the following has been measured on `main`. They are **design targets**, and a benchmark harness is in progress.

- **Performance:** P95 latency <100μs (target, unmeasured)
- **Cache Hit Rate:** >90% (target, unmeasured)
- **Memory Usage:** <50MB per instance (target, unmeasured)
- **Platform Support:** Linux enforcing; Windows and macOS experimental
- **Event types:** process, file and network on all platforms; bind, listen, ptrace and mount via LSM on Linux

### Current Implementation Highlights

**Code Status:**
- 30 internal packages. 9 of them (`attackgraph`, `blastradius`, `container`, `dashboard`, `drift`, `escape`, `patterns`, `temporal`, `testing`) are imported by no binary.
- 15 binaries under `cmd/` (13 released tools plus `test-ebpf` and `test-wasm`)
- 10 Rust policy crates. 8 compile; on `main` all of them deny some or all events due to ABI/field mismatches (see [STATUS.md](STATUS.md#2-policy-engine-and-toolchain)).
- 59 YAML example policies: 53 in `policies/yaml-example/` (all validate) and 6 in `examples/policies/` (all validate; CI fails on an invalid policy)
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
- Minimal performance overhead (<5% CPU impact)
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

**Performance Requirements:**
- Policy evaluation: <100μs per syscall (P95)
- Decision caching: 90%+ cache hit rate for repeated patterns
- Memory usage: <50MB per enforcer instance
- CPU overhead: <5% on average workload

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

**Latency:**
- P50: <50μs per syscall evaluation
- P95: <100μs per syscall evaluation
- P99: <500μs per syscall evaluation

**Throughput:**
- Support 100,000+ syscalls/second per enforcer
- Horizontal scaling via multiple enforcer instances
- Efficient batching for bulk operations

**Resource Usage:**
- Memory: <100MB per enforcer instance
- CPU: <5% overhead on typical workload
- Disk: <10MB for enforcer binary + policies

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
- Linux: Kernel 5.10+ (eBPF support)
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

---

## 6. Technical Architecture

### 6.1 Component Breakdown

#### warmor-daemon (Core Enforcer)
**Language:** Go (for cross-platform support and eBPF libraries)  
**Responsibilities:**
- Initialize platform-specific syscall hooks
- Embed WASM runtime (Wasmtime via CGO or Wazero)
- Manage policy lifecycle (load, reload, rollback)
- Implement decision caching
- Expose metrics and logging
- Handle graceful shutdown

**Key Dependencies:**
- `cilium/ebpf` (Linux eBPF)
- `tetratelabs/wazero` or `bytecodealliance/wasmtime-go`
- `prometheus/client_golang`
- `rs/zerolog` (structured logging)

#### warmor-cli (Management Tool) — not built

> This tool was never implemented. Its responsibilities are covered by `warmor-compile`, `warmor-server`, `warmorctl` and `warmor-policy-bundle`.

**Language:** Go  
**Responsibilities:**
- Compile policies (invoke `rustc` or `tinygo`)
- Validate WASM modules
- Deploy policies to enforcers
- Query enforcer status
- Manage policy versions

**Commands:**
```bash
warmor-cli compile <source> -o <output.wasm>
warmor-cli validate <policy.wasm>
warmor-cli deploy <policy.wasm> --target <enforcer-url>
warmor-cli status --target <enforcer-url>
warmor-cli logs --target <enforcer-url> --follow
warmor-cli rollback --target <enforcer-url> --version <version>
```

#### policy.wasm (Policy Module)
**Language:** Rust (primary), Go (secondary)  
**Responsibilities:**
- Implement policy evaluation logic
- Parse syscall events
- Return enforcement decisions
- Maintain internal state (if needed)

**Example Policy (Rust):**
```rust
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct SyscallEvent {
    pid: u32,
    uid: u32,
    syscall: String,
    process_path: String,
    arguments: Vec<String>,
}

#[no_mangle]
pub extern "C" fn evaluate_syscall(
    event_ptr: *const u8,
    event_len: usize
) -> i32 {
    let event: SyscallEvent = deserialize(event_ptr, event_len);
    
    // Example: Block root from running bash
    if event.uid == 0 && event.process_path.contains("bash") {
        return ACTION_DENY;
    }
    
    // Example: Block egress to public IPs
    if event.syscall == "connect" {
        if is_public_ip(&event.arguments[0]) {
            return ACTION_DENY;
        }
    }
    
    ACTION_ALLOW
}
```

### 6.2 Data Flow

**Syscall Interception Flow:**
```
1. Application calls open("/etc/passwd", O_RDONLY)
2. Kernel traps to eBPF hook
3. eBPF collects context: PID, UID, path, flags
4. eBPF sends event to warmor-daemon via ring buffer
5. warmor-daemon checks decision cache
6. Cache miss → Serialize event to MessagePack
7. Pass to WASM runtime via linear memory
8. WASM policy evaluates event
9. WASM returns ACTION_DENY
10. warmor-daemon caches decision
11. warmor-daemon signals eBPF to block syscall
12. Application receives EACCES error
13. Event logged and metrics updated
```

**Performance Optimization:**
```
Hot Path (Cache Hit):
  eBPF → Cache Lookup → Return Decision
  Latency: ~10μs

Cold Path (Cache Miss):
  eBPF → Serialize → WASM Eval → Cache Store → Return
  Latency: ~100μs
```

### 6.3 Deployment Architecture

**Standalone Mode:**
```
┌─────────────────────────────┐
│      Host Machine           │
│  ┌───────────────────────┐  │
│  │   warmor-daemon       │  │
│  │   (systemd service)   │  │
│  └───────────────────────┘  │
│            │                │
│            ▼                │
│  ┌───────────────────────┐  │
│  │   Kernel Hooks        │  │
│  │   (eBPF/ESF/KMD)      │  │
│  └───────────────────────┘  │
└─────────────────────────────┘
```

**Kubernetes Mode:**
```
┌─────────────────────────────────────────┐
│           Kubernetes Cluster            │
│  ┌───────────────────────────────────┐  │
│  │      warmor DaemonSet             │  │
│  │  ┌─────────┐  ┌─────────┐        │  │
│  │  │ Node 1  │  │ Node 2  │  ...   │  │
│  │  │ warmor  │  │ warmor  │        │  │
│  │  └─────────┘  └─────────┘        │  │
│  └───────────────────────────────────┘  │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │   Policy ConfigMap                │  │
│  │   (chart ships YAML; see Phase 5) │  │
│  └───────────────────────────────────┘  │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │   Prometheus ServiceMonitor       │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

---

## 7. Implementation Roadmap

### Phase 1: Linux PoC with WASM Integration (Weeks 1-3) — Done
**Goal:** Prove the core concept works on Linux

**Deliverables:**
- [x] Go daemon with `cilium/ebpf` integration
- [x] Embed Wazero WASM runtime (tetratelabs/wazero v1.11.0)
- [x] Implement basic policy ABI (Event types in pkg/api/types.go)
- [x] Hook multiple syscalls (execve, openat, connect)
- [x] Create sample Rust policies (policies/example, advanced, cross-platform, multi)
- [x] Hot-reload capability via SIGHUP signal

**Success Criteria:**
- Policy intercepts and logs process, file, and network events: met
- WASM policy reloadable via signal without daemon restart: met
- Latency <100μs per evaluation: **not measured**

### Phase 2: Enforcement & Decision Making (Weeks 4-6) — Done, with gaps
**Goal:** Move from logging to actual enforcement

**Deliverables:**
- [x] ALLOW/DENY/LOG actions (enforcer/actions.go)
- [x] Decision caching layer (cache/cache.go, 10k entries, 5min TTL; O(n) oldest-expiry eviction, not LRU)
- [x] Policy evaluation framework (wasm/policy.go, wasm/evaluator.go)
- [ ] Pattern matching library glob/regex (patterns/matcher.go): library-only. The YAML DSL supports glob.
- [x] Structured logging with zerolog (logging/logger.go)
- [x] Prometheus metrics exposure on :9090 (metrics/collector.go)

**Success Criteria:**
- Denies unauthorized operations: met, via `SIGKILL` after the event
- >90% cache hit rate: **not measured**; the PID in the cache key makes it unlikely
- JSON metrics and structured logging: met (`--log-level` is ignored)

### Phase 3: Multi-Syscall Support (Weeks 7-9) — Partial
**Goal:** Expand beyond execve to file and network operations

**Deliverables:**
- [x] Hook `openat`, `connect` syscalls
- [ ] Hook `sendto`, `recvfrom`: not implemented
- [x] Type-safe event structures (ProcessEvent, FileEvent, NetworkEvent in pkg/api/types.go)
- [x] Multiple example policies (example, advanced, cross-platform, multi)
- [x] Policy testing framework (testing/framework.go)
- [x] Decision caching

**Success Criteria:**
- Support 3+ syscall types (process, file, network): met
- CPU overhead <5% on typical workloads: **not measured**
- Benchmarking: **not done**; a benchmark harness is in progress

### Phase 4: Cross-Platform Support (Weeks 10-14) — Partial
**Goal:** Extend to Windows and macOS

**Deliverables:**
- [x] Windows implementation, ETW (internal/platform/etw/), tested in CI
- [ ] Windows eBPF-for-Windows (internal/platform/efw/, bpf-windows/): written, never built or run in CI
- [ ] macOS implementation (internal/platform/esf/): written, but AUTH events are always answered ALLOW, and the cgo code is not compiled in CI
- [x] Platform abstraction layer (platform/interface.go, new_linux.go, new_windows.go, new_darwin.go)
- [x] Unified policy format across platforms (same policy.wasm on all 3 OSes)
- [x] Cross-platform CLI tool (cmd/warmor-daemon with platform detection)

**Success Criteria:**
- Same policy.wasm loads on Linux, Windows and macOS: met (same runtime)
- Feature parity across platforms: **not met** (macOS has no enforcement; Windows kernel blocking is unverified)
- Comprehensive platform-specific documentation (PLATFORM_LINUX.md, PLATFORM_WINDOWS.md, PLATFORM_MACOS.md)

### Phase 5: Production Readiness (Weeks 15-18) — Partial
**Goal:** Make warmor production-ready

**Deliverables:**
- [x] Structured logging with zerolog (logging/logger.go)
- [x] Prometheus metrics and health endpoints (metrics/server.go, /metrics, /health, /ready)
- [x] Comprehensive documentation (README.md, BUILD.md, GETTING_STARTED.md, ARCHITECTURE.md, platform guides)
- [x] YAML Policy DSL with warmor-compile CLI
- [x] YAML -> Rust -> WASM compilation pipeline
- [ ] Kubernetes DaemonSet and Helm chart (deploy/helm/warmor/): present but broken on `main` (see below)
- [x] Grafana dashboards (deploy/grafana/); some panels use never-updated metrics
- [x] Codebase hardening pass

**Success Criteria:**
- [x] All events logged with context and timestamps
- [x] Prometheus-compatible metrics exposed on :9090
- [x] Documentation for all 3 platforms
- [ ] Deploy to a Kubernetes cluster via the Helm chart: **not met**. The initContainer runs nonexistent `--validate-policy`, there is no `lsmEnforce` value, and the ConfigMap YAML policy needs `cargo`, which the distroless image lacks.
- [ ] Full observability stack: partial

### Phase 6: LSM-BPF Kernel Enforcement (Weeks 19-22) — Partial
**Goal:** Synchronous kernel-level blocking via LSM-BPF hooks

**Deliverables:**
- [x] LSM-BPF programs for bprm_check_security, file_open, socket_connect, socket_bind, socket_listen, ptrace_access_check, sb_mount
- [x] BPF_MAP_TYPE_HASH policy map with FNV-1a hashed keys (65536 entries)
- [x] Two-tier cgroup-aware lookup (per-container + global fallback)
- [ ] WASM→BPF feedback loop: **exec and connect only** (tracepoint-origin events only). File, bind, listen, ptrace and mount never get kernel entries. The map is not cleared on reload.
- [x] Ring buffer for kernel→userspace event delivery on policy miss
- [x] Go LSM loader with graceful fallback to tracepoint-only mode
- [x] PolicyMapManager for userspace↔BPF map synchronization
- [x] `--lsm-enforce` flag for audit-only vs enforce mode
- [x] Kernel compatibility detection (CONFIG_BPF_LSM, kernel 5.7+, capabilities)

**Success Criteria:** partial. LSM attach is tested in a VM in CI.
- [ ] Denied exec returns EPERM synchronously: only after the first occurrence has been evaluated (and killed) and its decision cached in the map
- [ ] Denied file_open fails immediately: **not met**, no file entries are written (the hook sees only the basename)
- [ ] Denied connect fails at syscall boundary: only after the first occurrence, as for exec
- [x] Policy map feedback: WASM decision appears in BPF map after first evaluation
- [x] Graceful fallback on kernels without CONFIG_BPF_LSM
- [x] No regression in tracepoint-based monitoring
- [ ] P95 kernel fast-path latency <10μs (map lookup only) — requires live benchmarking

### Phase 7: Advanced Features (Weeks 23-28) — Partial
**Goal:** Add enterprise features

**Deliverables:**
- [ ] Stateful policy engine with process lineage tracking: partial (events carry no PPID, so ancestry is empty)
- [x] Central policy management server for fleet management (HTTP API)
- [x] A/B testing / canary rollout framework for policy changes
- [ ] Advanced enforcement (CIDR network filtering, rate limiting, process sandboxing): **library-only**, no flags or callers
- [ ] SIEM integration (CEF over syslog): **library-only**, there is no `--event-sink` spec for it

**Success Criteria:**
- [ ] Stateful policies with parent-child lineage: not met
- [x] Fleet management: agent registration, heartbeat, policy distribution
- [x] Canary rollouts with consistent agent bucketing (manual ramp)
- [ ] 4 built-in sandbox profiles: code exists, unreachable

#### Policy Server API

```bash
warmor-server --addr :8443 --jwt-secret "$WARMOR_JWT_SECRET" --policy-dir ./policies
```

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/register` | agent (cert or JWT) | Register agent |
| POST | `/api/v1/heartbeat` | agent | Agent heartbeat |
| GET | `/api/v1/policy` | agent | Assigned policy metadata |
| GET | `/api/v1/policy/wasm` | agent | Download assigned policy WASM |
| POST | `/api/v1/containers/bind` | runtime (cert or JWT) | Record container to policy binding (stored, not yet consumed) |
| DELETE | `/api/v1/containers/{id}` | runtime | Remove binding |
| GET, POST | `/api/v1/admin/policies` | admin JWT | List / create policies |
| GET, PUT, DELETE | `/api/v1/admin/policies/{id}` | admin JWT | Get / update (`{"wasm_path", "stage"}`) / delete a policy |
| GET | `/api/v1/admin/agents` | admin JWT | List agents |
| GET, POST | `/api/v1/admin/rollouts` | admin JWT | List / create rollouts |
| GET, PUT, DELETE | `/api/v1/admin/rollouts/{id}` | admin JWT | Get / set percentage / abort |

#### A/B Testing & Canary Rollouts

Rollouts use consistent hashing (SHA-256 of `rolloutID:agentID` mod 100) for deterministic bucket assignment:

```bash
AUTH="Authorization: Bearer $ADMIN_TOKEN"
# Create rollout targeting 10% of agents (no label targeting on main)
curl -X POST https://server:8443/api/v1/admin/rollouts -H "$AUTH" \
  -d '{"id": "egress-v2", "policy_id": "network-egress", "target_version": 2, "percentage": 10}'

# Ramp to 50%
curl -X PUT https://server:8443/api/v1/admin/rollouts/egress-v2 -H "$AUTH" -d '{"percentage": 50}'
```

The deny-rate canary analyzer and auto-rollback are library-only on `main`; ramping and aborting are manual. See [canary-rollout.md](canary-rollout.md).

#### Network Filtering (library-only on main)

The intended design is a CIDR blocklist and per-process rate limiting run before WASM evaluation:

```go
NetFilterConfig: &enforcer.NetFilterConfig{
    BlockCIDRs: []string{"169.254.0.0/16", "fc00::/7"},
    RateLimit:  200,
    Window:     time.Minute,
}
```

#### Process Sandboxing (library-only on main: nothing calls `ApplySandbox`)

| Profile | DenyNetwork | ReadOnlyFS | IsolatePID | Blocked Syscalls |
|---------|-------------|------------|------------|------------------|
| `strict` | Yes | Yes | Yes | All caps dropped |
| `network-deny` | Yes | No | No | — |
| `readonly` | No | Yes | No | — |
| `limited` | No | No | No | ptrace, mount, reboot, kexec_load |

```go
sandbox := enforcer.Sandbox()
sandbox.ApplySandbox(pid, "strict")
```

#### SIEM Integration (CEF over Syslog) — library-only on main

The sink exists but no daemon flag selects it. When wired, events would stream in CEF format to syslog collectors (Splunk, QRadar, ArcSight, Elastic):

```
CEF:0|Warmor|warmor-agent|1.0|file_open|file_open_deny|8|src=node-1 dvcpid=4321 duser=1000 cs1=malware cs1Label=comm filePath=/etc/shadow msg=policy violation rt=1705313400000
```

```go
sink, _ := streaming.NewSyslogSink(streaming.SyslogConfig{
    Network: "udp", Addr: "siem.corp:514", Facility: 1,
})
opts := &enforcer.Options{StreamSinks: []streaming.Sink{sink}}
```

| Decision | CEF Severity | Syslog Priority |
|----------|-------------|-----------------|
| deny | 8 (High) | LOG_CRIT |
| log/audit | 4 (Medium) | LOG_NOTICE |
| allow | 1 (Low) | LOG_INFO |

### Phase 8: Production Hardening & Operations (Weeks 29-36) — Partial
**Goal:** Secure the distribution channel, provide operator tooling, add runtime observability, and integrate with container runtimes

**Track A: mTLS & Policy Signing** — mostly done
- [x] Mutual TLS between agent ↔ policy server (ed25519 certificates)
- [x] Policy bundle signing (ed25519 signatures, `warmor-policy-bundle --sign-key`, verified on `--pull --verify-key`)
- [ ] Daemon-side signature verification of loaded or downloaded policies: **missing**
- [x] Admin API authentication (JWT bearer tokens — HMAC-SHA256 & Ed25519)
- [x] Certificate generation (CA, server, agent) with configurable CN/SANs
- [x] TLS configuration in agent + server config structs

**Track B: CLI Tool (`warmorctl`) — Bubble Tea TUI** — Done (interactive only)
- [x] Dashboard view — cluster overview (agents, policies, rollouts)
- [x] Agent list view — hostname, status, version, last heartbeat
- [x] Policy list view — ID, version, browse policies
- [x] Rollout view — progress bars, status coloring, promote/abort
- [x] Certificate management — generate CA/server/agent certs, signing keypairs
- [x] Keyboard navigation (j/k, tab, 1-5 views, r=refresh, g=generate)

**Track C: Runtime Observability** — Partial
- [ ] Prometheus metrics exporter (hook decisions, latency histograms, WASM exec): metrics registered, **never updated**
- [x] `/metrics`, `/health`, `/ready` endpoints with event, cache and latency metrics
- [x] Grafana dashboard JSON templates (overview + LSM hooks + WASM + agents)
- [ ] Prometheus alert rules (high deny rate, latency, events dropped, stale agent): shipped, but most reference never-updated metrics, and `warmor_ebpf_loader_status` does not exist
- [x] Docker Compose monitoring stack (Prometheus + Grafana provisioned)

**Track D: Container Runtime Integration** — Mostly missing
- [ ] containerd shim plugin: library code in `internal/container`, not wired
- [x] CRI-O OCI hook configuration (createRuntime + poststop; both stages pass `--action start`)
- [ ] OCI hook binary (`warmor-oci-hook`): experimental. No auth/TLS, so it only works with `warmor-server --insecure`.
- [ ] Per-container policy scoping via container labels (`io.warmor/policy`): bindings are stored, **never consumed**
- [x] Container binding API endpoints on policy server
- [ ] Runtime auto-detection: library-only
- [ ] Kubernetes DaemonSet manifest: present, but it configures the daemon through env vars that the daemon does not read

**Success Criteria:**
- [ ] Agent ↔ server traffic encrypted with mTLS: met. Unsigned policies rejected: **not met**.
- [x] `warmorctl` TUI covers fleet overview, policies, rollouts, cert generation
- [ ] Prometheus metrics visualized in Grafana: partial
- [ ] New containers automatically get policies based on labels: **not met**

#### mTLS Certificate Authority

```
┌────────────┐         ┌─────────────────┐         ┌──────────────┐
│   CA Key   │──signs──▶│  Server Cert    │         │  Agent Cert  │
│ (ed25519)  │         │  (warmor-server)│         │  (agent-01)  │
└────────────┘         └─────────────────┘         └──────────────┘
                              ▲                           ▲
                              │         mTLS              │
                              └───────────────────────────┘
```

Certificates are generated interactively in the `warmorctl` **Certs** tab (`g` for CA + server/agent certs, `s` for a signing key pair). There is no `warmorctl certs generate` subcommand.

```bash

# Start server with mTLS
warmor-server --addr :8443 --tls-cert ./certs/server.crt --tls-key ./certs/server.key --ca-cert ./certs/ca.crt

# Start agent with mTLS
warmor-daemon --server https://warmor-server:8443 --tls-cert ./certs/agent-01.crt --tls-key ./certs/agent-01.key --tls-ca ./certs/ca.crt
```

#### Policy Signing

Signing is done with `warmor-policy-bundle`. The `warmor-server policy sign` command and the daemon flags `--verify-policy-sig` / `--signing-pub` do **not** exist. The daemon does not verify signatures on `main`.

```bash
warmor-policy-bundle --keygen --sign-key signing.key --verify-key signing.pub
warmor-policy-bundle --push --ref ghcr.io/myorg/warmor-policies/app:v1 --wasm policy.wasm --sign-key signing.key
warmor-policy-bundle --pull --ref ghcr.io/myorg/warmor-policies/app:v1 --wasm out.wasm --verify-key signing.pub  # only place verification happens
```

See [policy-bundle.md](policy-bundle.md) for exact usage.

#### JWT Authentication

| Algorithm | Use Case | Key Type |
|-----------|----------|----------|
| HMAC-SHA256 | Shared-secret environments | `[]byte` |
| EdDSA (Ed25519) | Zero-trust environments | `ed25519.PrivateKey` |

#### warmorctl TUI

```bash
warmorctl                              # Launch interactive TUI
warmorctl --server https://server:8443 --token "$WARMOR_TOKEN" --ca-cert ca.crt --client-cert admin.crt --client-key admin.key
```

| Tab | Description |
|-----|-------------|
| Dashboard | Agent, policy and active-rollout counts; recent agents |
| Agents | Connected agents with heartbeat status, labels, assigned policy |
| Policies | CRUD operations on fleet policies |
| Rollouts | A/B testing rollout management with percentage ramps |
| Certs | Generate a CA + server/agent certificates, or a signing key pair |

Key bindings: `Tab`/`Shift+Tab` switch tabs, `j`/`k` navigate, `Enter` select, `q` quit.

Source: `cmd/warmorctl/` — main.go, app.go, dashboard.go, agents.go, policies.go, rollouts.go, certs.go, api.go

#### Prometheus Metrics

Exported on `:9090/metrics`:

Updated by the daemon:

| Metric | Type |
|--------|------|
| `warmor_events_total{action}` | Counter |
| `warmor_cache_hits_total`, `warmor_cache_misses_total` | Counter |
| `warmor_cache_size` | Gauge |
| `warmor_evaluation_latency_microseconds` | Histogram |
| `warmor_policy_info` | Gauge |
| `warmor_events_processing_errors_total`, `warmor_audit_denied_total` | Counter |

Registered but **never updated** on `main` (`internal/metrics/exporter.go`): `warmor_lsm_decisions_total`, `warmor_lsm_decision_duration_seconds`, `warmor_policy_loads_total`, agent heartbeat/registration, WASM exec duration/errors, events processed/dropped and map-entry metrics.

#### Grafana & Alerting

Dashboard at `deploy/grafana/warmor-dashboard.json` (auto-provisioned):
- Row 1: Event rates (allow/deny/audit) per hook type
- Row 2: Decision latency P50/P95/P99
- Row 3: Policy load success/failure, cache hit ratio
- Row 4: Agent fleet health

Alert rules in `deploy/prometheus/alerts.yml` are built on the never-updated exporter metrics (`warmor_lsm_decisions_total`, `warmor_policy_loads_total`, `warmor_agent_last_heartbeat_timestamp`, ...), so they never fire on `main`. The Helm `PrometheusRule` uses `warmor_events_total` and `warmor_events_processing_errors_total`, which work, plus `warmor_ebpf_loader_status`, which does not exist.

```bash
# Local monitoring stack
cd deploy/ && docker compose -f docker-compose.monitoring.yml up -d
# Prometheus: http://localhost:9091 | Grafana: http://localhost:3000 (admin/warmor)
```

#### Container Runtime Integration

```bash
# CRI-O (install OCI hook; experimental, works only against warmor-server --insecure)
sudo cp deploy/crio/warmor-hook.json /etc/containers/oci/hooks.d/
```

The `--containerd-socket` and `--per-container-policy` flags do **not** exist. Per-container policy scoping via `io.warmor/policy` labels is **not implemented**: the hook records bindings on the server, but nothing resolves `cgroup_id → container_id → policy`.

Source: `internal/container/` — detector.go, containerd_monitor.go, containerd_shim.go, policy_scope.go

#### Kubernetes Deployment

**Not working on `main`.** The Helm chart's initContainer runs nonexistent `warmor-daemon --validate-policy`, so pods stay in `Init`. The chart also has no `lsmEnforce`, `containerRuntime`, `perContainerPolicy` or `tls.*` values. The ConfigMap YAML policy needs `cargo` in a distroless image, the ValidatingWebhook has no handler, and the `WarmorPolicy` CRD has no controller. See [STATUS.md](STATUS.md#5-container-runtime-and-kubernetes).

### Phase 9: Security Intelligence (Weeks 37-44) — Mostly library-only
**Goal:** Move from static policy enforcement to autonomous security intelligence — learn, simulate, detect, and adapt.

**Deliverables:**
- [x] Learning mode — synthesize allowlist policies from recorded events (`warmor-learn`, `internal/learner/`). Offline only; no in-daemon learning flag.
- [x] Policy simulator — replay recorded events against candidate policies (`warmor-simulate`, `internal/simulator/`). The daemon has no event-store sink, and the new-denials diff is empty for daemon-recorded events (decision case mismatch).
- [ ] Supply-chain integrity — offline SHA-256 scan/verify only (`warmor-integrity-scan`). **No in-kernel or runtime enforcement.**
- [ ] Container escape detection (`internal/escape/`) — library-only
- [ ] Drift detection (`internal/drift/`) — library-only
- [ ] Canary auto-rollback (`internal/policyserver/` canary analyzer) — library-only; manual rollouts ship
- [ ] Temporal policies (`internal/temporal/`) — library-only; the YAML `temporal:` key is silently ignored
- [ ] Attack graph (`internal/attackgraph/`) — library-only
- [ ] Blast radius (`internal/blastradius/`) — library-only

**Success Criteria:**
- [x] Policy generation from observed behavior
- [x] Pre-deployment impact analysis via historical replay (decision breakdown)
- [ ] In-kernel binary integrity enforcement: not met
- [ ] Events mapped to MITRE ATT&CK in a running system: not met
- [ ] Automatic policy rollback on anomalous canary behavior: not met

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

**Performance:**
- Policy evaluation latency P95 <100μs
- CPU overhead <5% on typical workload
- Memory usage <100MB per instance
- Cache hit rate >90%

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

4. **Performance Target:** **<100μs P95 (target, unmeasured)**
   - Decision: target kept
   - Result: not yet benchmarked; a benchmark harness is in progress

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

**warmor** is pre-stable. The core idea, policy logic in WASM (brain) decoupled from OS-specific hooks (hands), is implemented on Linux and reachable on Windows and macOS through the same runtime. Enforcement strength differs sharply by platform and by event type. [Feature Status](STATUS.md) is the authoritative list.

### Achievements to Date

- Linux daemon with tracepoints and 7 LSM hooks, WASM evaluation and detect-then-`SIGKILL` enforcement. Kernel `EPERM` covers cached exec/connect denies.
- YAML → WASM compiler and a policy toolchain: learn, simulate, policy-gen, sbom-policy, diff, merge, signed OCI bundles
- Policy server with mTLS/JWT, versioned policies and percentage rollouts, plus the `warmorctl` TUI
- Windows ETW backend tested in CI

### Current Implementation Status

**Linux (most mature):**
- Tracepoint and LSM-BPF event capture for process, file, network, bind, listen, ptrace and mount
- Kernel blocking only on a policy-map hit; only exec and connect entries are written
- Everything else: userspace deny → `SIGKILL`
- Latency not yet measured

**Windows (experimental beta):**
- ETW monitoring with detect-then-`TerminateProcess`, tested in CI
- eBPF-for-Windows programs written but never built or run in CI

**macOS (experimental, detection only):**
- ESF client subscribes to events; every AUTH event is answered ALLOW
- cgo code not compiled in CI, and release binaries are built without cgo

### Next Priorities

1. Kernel default-deny and preloading static rules; sync all key-determined decisions
2. WASM memory/time limits; daemon-side policy signature verification
3. Fix the Rust crate ABIs, build them in CI, and fix the failing example YAML policies
4. Wire the library-only features (integrity runtime, escape, temporal, canary analyzer, SIEM sink)
5. Fix the Helm chart and add a kind e2e test
6. Benchmark harness to measure the performance targets

### Key Differentiators (design goals)

- **Portability:** the same policy.wasm loads on 3 OSes
- **Safety:** WASM sandbox isolates policy code (resource limits still to come)
- **Flexibility:** hot-reload policies without downtime

---

**Last Updated:** 2026-10-14
**Status:** See [STATUS.md](STATUS.md)  
**Next Review:** After Future Roadmap (§7.1) scoping