# warmor Architecture

**Version:** 2.0.0-beta  
**Last Updated:** 2026-06-27  
**Status:** Phase 9 Complete — Windows Service, Event Viewer, SSE Dashboard, Coverage Gating

---

## Overview

**warmor** (WebAssembly + Armor) is a cross-platform security enforcer that solves the "Policy Portability Problem" by using **WebAssembly (WASM) as the policy execution engine** and **platform-specific hooks as the enforcement mechanism**.

### The Core Innovation

Traditional security enforcers are platform-specific:
- Linux policies (eBPF, AppArmor, SELinux) don't work on Windows
- Windows policies don't work on macOS
- Each platform requires different expertise and tooling

**warmor decouples the "Brain" from the "Hands":**
- **WASM = Brain:** Portable policy logic that runs identically everywhere
- **Platform Hooks = Hands:** OS-specific syscall interception (eBPF, ESF, ETW)
- **Result:** Write-once-run-anywhere security policies

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
│              (Native apps making syscalls)                   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│           Interception Layer (Platform-Specific)             │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────┐      │
│  │   eBPF   │    │   ESF    │    │  eBPF-Windows/   │      │
│  │ (Linux)  │    │ (macOS)  │    │      ETW         │      │
│  │  PROD    │    │   BETA   │    │      BETA        │      │
│  └──────────┘    └──────────┘    └──────────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              warmor Daemon (User Space)                      │
│  ┌────────────────────────────────────────────────────┐     │
│  │         WASM Runtime (Wazero)                      │     │
│  │  ┌──────────────────────────────────────────────┐  │     │
│  │  │        policy.wasm (The Brain)               │  │     │
│  │  │  - Evaluate event context                    │  │     │
│  │  │  - Apply security rules                      │  │     │
│  │  │  - Return: ALLOW / DENY / LOG                │  │     │
│  │  └──────────────────────────────────────────────┘  │     │
│  └────────────────────────────────────────────────────┘     │
│  ┌────────────────────────────────────────────────────┐     │
│  │         Platform Abstraction Layer                 │     │
│  │  - Unified event interface                         │     │
│  │  - Platform detection                              │     │
│  │  - Capability reporting                            │     │
│  └────────────────────────────────────────────────────┘     │
│  ┌────────────────────────────────────────────────────┐     │
│  │         Observability & Caching                    │     │
│  │  - Prometheus metrics                              │     │
│  │  - Structured logging (+ Event Viewer on Windows)  │     │
│  │  - LRU decision cache                              │     │
│  │  - Real-time SSE dashboard                         │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

---

## Platform Support Matrix

| Platform | Status | Technology | Enforcement | Latency (P95) | Throughput |
|----------|--------|------------|-------------|---------|------------|
| **Linux** | ✅ Production | eBPF | ✅ Yes | <100μs | 100k+/sec |
| **Windows** | 🚧 Beta | ETW + eBPF-for-Windows | ✅ Yes (eBPF mode) | <100μs | 100k+/sec |
| **macOS** | 🚧 Beta | ESF | ✅ Yes (AUTH events) | <100μs | 100k+/sec |

---

## Component Architecture

### 1. Platform Abstraction Layer

**Purpose:** Provide a unified interface for all platforms while hiding platform-specific implementation details.

**Interface:**
```go
type Platform interface {
    Name() string
    Load(ctx context.Context) error
    Start(ctx context.Context, eventChan chan<- *api.Event) error
    Stop() error
    Close() error
    Capabilities() Capabilities
    PolicyMap() any
}

type Capabilities struct {
    ProcessMonitoring bool
    FileMonitoring    bool
    NetworkMonitoring bool
    Enforcement       bool
    LSMEnforcement    bool
}
```

**Implementations:**
- `LinuxPlatform` - eBPF-based monitoring (production)
- `WindowsPlatform` - ETW + eBPF-for-Windows (beta)
- `DarwinPlatform` - ESF-based monitoring (beta)

### 2. Event Processing Pipeline

```
Platform Hook → Raw Event → Parse → api.Event → WASM Policy → Decision → Action
```

**Event Types:**
```go
type Event struct {
    Type      EventType
    PID       uint32
    UID       uint32
    GID       uint32
    Comm      string
    Filename  string
    Timestamp int64
    Process   *ProcessEvent
    File      *FileEvent
    Network   *NetworkEvent
}
```

### 3. WASM Policy Engine

**Runtime:** Wazero (pure Go, no CGO dependencies)

**Policy Interface:**
```rust
#[no_mangle]
pub extern "C" fn evaluate_syscall(event_ptr: *const u8, event_len: usize) -> i32 {
    // Parse event
    // Apply rules
    // Return ACTION_ALLOW, ACTION_DENY, or ACTION_LOG
}
```

**Features:**
- Sandboxed execution (cannot crash daemon)
- Hot reload support
- <100μs evaluation latency
- Memory-safe (WASM sandbox)

### 4. Decision Cache

**Implementation:** LRU cache with TTL

**Key Format:** `{type}:{pid}:{uid}:{filename_hash}`

**Performance:**
- 10,000 entry capacity
- >90% hit rate in production
- Reduces WASM evaluation overhead

### 5. YAML Policy Compiler

**Purpose:** Allow non-Rust users to author policies declaratively via YAML, compiled to WASM.

**Pipeline:** `YAML → Parse/Validate → Rust codegen → cargo build --target wasm32-unknown-unknown → .wasm`

**Architecture:**
```
internal/compiler/
  ├── schema.go      ← YAML schema structs + validation
  ├── parser.go      ← Parse YAML, resolve $variables, validate
  ├── codegen.go     ← Generate Rust source from parsed policy
  └── build.go       ← Invoke cargo build, produce .wasm

cmd/warmor-compile/  ← CLI entry point
```

**YAML Schema:**
```yaml
name: my-policy
version: 1
variables:
  blocked: ["/usr/bin/nc", "/usr/bin/ncat"]
rules:
  - name: block-netcat
    event: process
    conditions:
      all:
        - path: { any_of: $blocked }
    action: deny
default_action: allow
```

**Condition Operators:** `eq`, `not`, `any_of`, `none_of`, `glob`, `gt`, `lt`, `gte`, `lte`, `starts_with`, `contains`

**Matchable Fields:**
- process: `pid`, `uid`, `gid`, `comm`, `path`, `args`
- file: `pid`, `uid`, `gid`, `comm`, `path`, `operation`, `flags`
- network: `pid`, `uid`, `gid`, `comm`, `operation`, `protocol`, `remote_addr`, `remote_port`, `local_port`

**Generated Rust follows the same ABI as hand-written policies:**
- Exports: `malloc(size)`, `evaluate_syscall(ptr, len) -> i32`
- Return values: 0=ALLOW, 1=DENY, 2=LOG

**Runtime compilation:** The daemon also accepts `.yaml`/`.yml` policy files directly, compiling at load time if the Rust toolchain is available.

### 6. Observability

**Metrics (Prometheus):**
- `warmor_events_total{action="ALLOW|DENY|LOG"}`
- `warmor_cache_hits_total`
- `warmor_cache_misses_total`
- `warmor_cache_size`
- `warmor_evaluation_latency_microseconds`
- `warmor_policy_info{path, version}`
- `warmor_events_processing_errors_total`

**Grafana Dashboards** (provisioned via ConfigMap or JSON import):
- Events/sec rate, Actions breakdown (pie chart)
- Deny rate, Cache hit rate (gauges)
- P95/P99 evaluation latency (timeseries)
- Processing errors, Policy info

**Logging (Structured JSON):**
```json
{
  "level": "warn",
  "service": "warmor",
  "pid": 1234,
  "action": "DENY",
  "latency_us": 45,
  "cached": false
}
```

---

## Platform-Specific Implementations

### Linux (eBPF) - Production ✅

**Architecture:**
```
Application → Syscall → eBPF Hook → Ring Buffer → warmor Daemon → WASM → Decision
```

**eBPF Programs:**
- `execve_monitor.bpf.c` - Process execution monitoring
- `openat_monitor.bpf.c` - File access monitoring
- `connect_monitor.bpf.c` - Network connection monitoring

**Key Features:**
- Kernel-space monitoring (<50μs latency)
- Zero-copy ring buffer
- High throughput (>50k events/sec)
- Full enforcement capability

**Implementation Files:**
- `internal/platform/linux.go` - Platform implementation
- `internal/ebpf/loader.go` - eBPF program loader
- `bpf/*.bpf.c` - eBPF C programs

**Documentation:** [PLATFORM_LINUX.md](PLATFORM_LINUX.md)

### LSM-BPF Kernel Enforcement (Linux 5.7+)

**Architecture:**
```
Application → Syscall → LSM Hook → Policy Map Lookup
  ├─ HIT + DENY  → return -EPERM (blocked in kernel, zero userspace latency)
  ├─ HIT + ALLOW → return 0 (permitted, no userspace trip)
  └─ MISS        → emit to ringbuf → WASM evaluates → decision compiled back into policy map
```

Unlike tracepoint-based monitoring which observes syscalls after they begin, LSM-BPF hooks are **synchronous** — they execute inline within the kernel security path and can return `-EPERM` to block an operation before it completes.

**LSM Programs:**
- `lsm_exec.bpf.c` — `bprm_check_security` hook (blocks exec before binary loads)
- `lsm_file.bpf.c` — `file_open` hook (blocks file access before open completes)
- `lsm_connect.bpf.c` — `socket_connect` hook (blocks connections before handshake)

**Policy Map (BPF_MAP_TYPE_HASH):**
```c
struct policy_key {
    __u64 cgroup_id;    // 0 = global rule
    __u32 rule_hash;    // FNV-1a hash of filename/pattern
    __u8  event_type;   // 0=exec, 1=file, 2=net
};

struct policy_value {
    __u8  action;       // 0=allow, 1=deny
    __u8  audit;        // 1=log even if allowed
    __u32 hit_count;    // for metrics
};
```

**Two-Tier Lookup:**
1. Cgroup-specific: `policy_map[{cgroup_id, hash, type}]`
2. Global fallback: `policy_map[{0, hash, type}]`

**WASM→BPF Feedback Loop:**
```
First occurrence:  LSM miss → ringbuf → WASM evaluates → write decision to policy_map
Second occurrence: LSM hit → kernel allows/denies immediately (no userspace trip)
```

**Graceful Fallback:** If `CONFIG_BPF_LSM` is absent or the kernel lacks LSM-BPF support, the system falls back to tracepoint-only mode with a warning. The `--lsm-enforce` flag controls whether deny decisions are enforced or audit-only.

**Implementation Files:**
- `bpf/warmor_lsm.h` — Shared structs, maps, FNV-1a hash helper
- `bpf/lsm_exec.bpf.c` — Exec enforcement
- `bpf/lsm_file.bpf.c` — File access enforcement
- `bpf/lsm_connect.bpf.c` — Network enforcement
- `internal/ebpf/lsm_loader.go` — Go LSM program loader
- `internal/ebpf/policy_map.go` — Policy map manager (userspace↔BPF)

---

### Windows (ETW + eBPF-for-Windows) - Beta 🚧

**Per-event-type backends:** each event type is served by one backend,
chosen at startup.

| Event | eBPF-for-Windows (primary) | ETW (fallback) |
|---|---|---|
| Process | `process` hook (ntosebpfext): creation denied in the kernel | Kernel-Process: detect, then terminate |
| Network | `cgroup/connect4/6`, `recv_accept4/6`: rejected in the kernel | Kernel-Network: detect, then terminate |
| File | no hook exists | Kernel-File (always) |

```
eBPF hook ──(cached verdict)──▶ allow / reject in kernel
    │
    └─ ring buffer ─▶ daemon ─▶ WASM ─▶ decision ─▶ kernel map (next attempt)
ETW provider ─▶ daemon ─▶ WASM ─▶ decision ─▶ TerminateProcess (PID-reuse checked)
```

**Fallback:** eBPF is used when `ebpfapi.dll` and the driver are present and
the native images load and attach. Otherwise, per event type, the matching
ETW provider is enabled instead. `--no-lsm` forces ETW and `--require-lsm`
makes eBPF mandatory.

**Implementation Files:**
- `internal/platform/windows.go` - Platform implementation
- `internal/platform/etw/` - ETW consumer (fallback; always used for files)
- `internal/platform/efw/` - eBPF-for-Windows loader and kernel policy maps
- `bpf-windows/` - eBPF-for-Windows programs (network, process)

**Documentation:** [PLATFORM_WINDOWS.md](PLATFORM_WINDOWS.md)

### macOS (ESF) - Beta 🚧

**Architecture:**
```
Application → Syscall → ESF Hook → ESF Client → warmor Daemon → WASM → Decision
```

**ESF Event Types:**

**AUTH Events (Can Block):**
- `ES_EVENT_TYPE_AUTH_EXEC` - Process execution
- `ES_EVENT_TYPE_AUTH_OPEN` - File open
- `ES_EVENT_TYPE_AUTH_CREATE` - File creation

**NOTIFY Events (Monitoring):**
- `ES_EVENT_TYPE_NOTIFY_EXIT` - Process termination
- `ES_EVENT_TYPE_NOTIFY_WRITE` - File write
- `ES_EVENT_TYPE_NOTIFY_CONNECT` - Network connection

**Key Features:**
- Kernel-space monitoring (<100μs latency)
- AUTH event enforcement
- System Extension required
- Full Disk Access required

**Implementation Files:**
- `internal/platform/darwin.go` - Platform implementation
- `internal/platform/esf/client.go` - ESF client
- `internal/platform/esf/bridge.c` - C bridge
- `macos/SystemExtension/` - System Extension config

**Documentation:** [PLATFORM_MACOS.md](PLATFORM_MACOS.md)

---

## Data Flow

### Event Capture Flow

```
1. Application makes syscall
   ↓
2. Platform hook intercepts (eBPF/ETW/ESF)
   ↓
3. Raw event data captured
   ↓
4. Platform-specific parser converts to api.Event
   ↓
5. Event sent to daemon via channel
   ↓
6. Daemon receives event
```

### Policy Evaluation Flow

```
1. Check decision cache
   ├─ HIT → Return cached decision
   └─ MISS → Continue
   ↓
2. Serialize event to bytes
   ↓
3. Call WASM policy function
   ↓
4. WASM evaluates rules
   ↓
5. Return decision (ALLOW/DENY/LOG)
   ↓
6. Cache decision
   ↓
7. Log action
   ↓
8. Update metrics
```

### Enforcement Flow

```
1. Receive decision from WASM
   ↓
2. Compile decision into BPF policy map (if LSM active)
   ↓
3. If ALLOW → Allow syscall to proceed
   ↓
4. If DENY → Block syscall (platform-specific)
   ├─ Linux (LSM): Already blocked in kernel via -EPERM (synchronous)
   ├─ Linux (tracepoint): Return error from eBPF
   ├─ Windows: Terminate process (eBPF mode)
   └─ macOS: Respond with ES_AUTH_RESULT_DENY
   ↓
5. If LOG → Allow but log event
```

### LSM Kernel Fast-Path (Linux only)

```
1. LSM hook fires (7 hooks):
   - bprm_check_security (exec)
   - file_open
   - socket_connect / socket_bind / socket_listen
   - ptrace_access_check
   - sb_mount
   ↓
2. Compute FNV-1a hash of subject (filename, endpoint, port, comm, fstype)
   ↓
3. Lookup policy_map[{cgroup_id, hash, event_type}]
   ├─ HIT + action=DENY → return -EPERM (blocked, emit audit event)
   ├─ HIT + action=ALLOW → return 0
   └─ MISS → emit event to lsm_events ringbuf, return 0 (default-allow)
   ↓
4. On MISS: userspace WASM evaluates → writes result back to policy_map
   ↓
5. Next identical event → kernel fast-path (no userspace trip)
```

---

## Performance Characteristics

### Latency Breakdown

**Linux (eBPF) - Production:**
- Event capture: ~10μs
- Event parsing: ~5μs
- Cache lookup: ~2μs
- WASM evaluation: ~30μs (cache miss)
- **Total: <100μs (P95)** ✅

**Windows (ETW) - Beta:**
- Event capture: ~50μs
- Event parsing: ~15μs
- Cache lookup: ~2μs
- WASM evaluation: ~30μs (cache miss)
- **Total: <100μs (P95)** ✅

**Windows (eBPF) - Beta:**
- Event capture: ~10μs
- Event parsing: ~5μs
- Cache lookup: ~2μs
- WASM evaluation: ~30μs (cache miss)
- **Total: <100μs (P95)** ✅

**macOS (ESF) - Beta:**
- Event capture: ~50μs
- Event parsing: ~10μs
- Cache lookup: ~2μs
- WASM evaluation: ~30μs (cache miss)
- **Total: <100μs (P95)** ✅

### Throughput

| Platform | Events/sec | CPU Usage | Memory |
|----------|------------|-----------|--------|
| Linux (eBPF) | 100k+/sec | <5% | <100MB |
| Windows (ETW) | 100k+/sec | <5% | <100MB |
| Windows (eBPF) | 100k+/sec | <5% | <100MB |
| macOS (ESF) | 100k+/sec | <5% | <100MB |

---

## Security Considerations

### Privilege Requirements

**Linux:**
- Root/CAP_BPF required for eBPF
- Cannot be bypassed (kernel-level)

**Windows:**
- Administrator required for ETW/eBPF
- ETW: User-space (can be bypassed)
- eBPF: Kernel-level (cannot be bypassed)

**macOS:**
- Root required for ESF
- System Extension approval required
- Full Disk Access required
- Cannot be bypassed (kernel-level)

### WASM Sandbox

**Isolation:**
- No file system access
- No network access
- No syscall access
- Memory-safe execution

**Resource Limits:**
- Max memory: 64MB
- Max execution time: 100ms
- No infinite loops

### Attack Surface

**Minimal:**
- WASM policies cannot crash daemon
- Platform hooks are read-only
- No external dependencies in hot path
- Structured logging prevents injection

---

## Deployment Architectures

### Standalone Mode

```
┌─────────────────┐
│  warmor-daemon  │
│  + policy.wasm  │
└─────────────────┘
```

**Use Case:** Single-host protection

### Kubernetes DaemonSet (Helm Chart)

```
┌──────────────────────────────────────────────────┐
│                  Kubernetes Cluster               │
│                                                  │
│  ┌─────────────┐  ┌─────────────┐               │
│  │   Node A    │  │   Node B    │   ...          │
│  │ ┌─────────┐ │  │ ┌─────────┐ │               │
│  │ │ warmor  │ │  │ │ warmor  │ │               │
│  │ │DaemonSet│ │  │ │DaemonSet│ │               │
│  │ └─────────┘ │  │ └─────────┘ │               │
│  └─────────────┘  └─────────────┘               │
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │ Prometheus  →  Grafana Dashboards          │  │
│  │ ServiceMonitor scrapes /metrics on :9090   │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

**Use Case:** Cluster-wide enforcement with centralized observability

**Helm chart includes:**
- DaemonSet with privileged eBPF access, host PID/network namespace
- RBAC (ServiceAccount, ClusterRole, ClusterRoleBinding)
- Service for metrics scraping
- ServiceMonitor for Prometheus Operator
- Grafana dashboard ConfigMap for sidecar auto-provisioning
- Policy ConfigMap with default YAML policy

**Install:** `helm install warmor deploy/helm/warmor/`

### Distributed Mode with mTLS

```
┌─────────────────────────────────────────────────────────────┐
│                    warmor-server (Policy Hub)                │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────────┐ │
│  │  REST    │  │ Policy Store │  │  A/B Testing Engine   │ │
│  │  API     │  │ (YAML+WASM)  │  │  (consistent hash)    │ │
│  └──────────┘  └──────────────┘  └───────────────────────┘ │
│  ┌──────────────────────────────────────────────────────┐   │
│  │          mTLS + JWT Auth (Ed25519/HMAC-SHA256)       │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
          ▲  mTLS           ▲  mTLS           ▲  mTLS
          │                 │                 │
┌─────────────────┐ ┌──────────────┐ ┌──────────────────────┐
│  warmor-daemon  │ │ warmor-daemon│ │  warmor-daemon       │
│  (Agent A)      │ │ (Agent B)    │ │  (Agent C)           │
│  + containerd   │ │ + CRI-O      │ │  + per-container     │
│    integration  │ │   OCI hooks  │ │    policy scope      │
└─────────────────┘ └──────────────┘ └──────────────────────┘
```

**Use Case:** Fleet management, per-container enforcement, centralized policy distribution

### Monitoring Stack

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│   warmor-daemon ──(metrics:9090)──▶ Prometheus ──▶ Grafana  │
│                                                              │
│   Alert Rules:                                               │
│   - warmor_lsm_deny_rate > 100/min → PagerDuty             │
│   - warmor_agent_last_heartbeat > 5m → Slack                │
│   - warmor_policy_load_failures > 0 → Critical             │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

**Use Case:** Real-time security posture visibility, automated alerting

---

## Technology Stack

### Core Technologies
- **Go 1.26.2+** - Daemon implementation
- **Rust 1.70+** - Policy implementation
- **WASM** - Policy execution engine
- **Wazero** - Pure Go WASM runtime

### Platform Technologies
- **Linux:** eBPF, cilium/ebpf library
- **Windows:** ETW, eBPF-for-Windows
- **macOS:** Endpoint Security Framework

### Security & Auth
- **Ed25519** - Certificate generation, policy signing, JWT (EdDSA)
- **mTLS** - Mutual TLS for agent↔server communication
- **HMAC-SHA256** - JWT token signing (shared-secret mode)

### CLI & UX
- **Bubble Tea** - Terminal UI framework (warmorctl)
- **Lipgloss** - TUI styling and layout

### Container Runtime
- **containerd** - Shim plugin for container lifecycle events
- **CRI-O** - OCI hook integration
- **Kubernetes** - DaemonSet with BPF capabilities

### Observability
- **Prometheus** - Metrics collection (LSM decisions, latency, policy loads)
- **Grafana** - Pre-built dashboards with auto-provisioning
- **Alert Rules** - Deny rate spikes, heartbeat failures, load errors
- **zerolog** - Structured logging
- **pprof** - Performance profiling

---

## Development Phases (Complete)

### Phase 6: LSM-BPF Kernel Enforcement ✅
- Synchronous kernel-level blocking via LSM-BPF hooks (exec, file_open, socket_connect, socket_bind, socket_listen, ptrace_access_check, sb_mount)
- BPF hash map policy cache with WASM→BPF feedback loop
- Cgroup-aware two-tier policy lookup (per-container + global)
- FNV-1a hashing for O(1) pattern matching in BPF context
- Audit-only mode via `lsm_enforce` toggle
- Graceful fallback to tracepoint-only on unsupported kernels

### Phase 7: Advanced Features ✅
- Stateful policy engine with process lineage tracking
- Central policy management server (`warmor-server`) for fleet management
- A/B testing framework for safe canary policy rollouts
- Advanced enforcement (network filtering, process sandboxing)
- SIEM integration (CEF-formatted event streaming to syslog)

### Phase 8: Production Infrastructure ✅
- **mTLS & Policy Signing** — Ed25519 certificates, mutual TLS for agent↔server, signed WASM bundles, JWT auth (HMAC-SHA256 + EdDSA)
- **warmorctl CLI** — Bubble Tea TUI with real-time dashboard, agent management, policy CRUD, rollout control, certificate generation
- **Container Runtime Integration** — containerd shim plugin, CRI-O OCI hooks, per-container policy scoping, Kubernetes DaemonSet
- **Enhanced Observability** — Prometheus metrics exporter (LSM decisions, latency histograms, policy loads), Grafana dashboards, alerting rules (deny spikes, heartbeat failures, load errors)

## Future Enhancements

### Phase 9 (Planned)
- eBPF-for-Windows enforcement mode
- Network policy (L3/L4 filtering via XDP)
- Distributed tracing (OpenTelemetry spans per event)
- Policy marketplace with community-contributed rules
- GUI web console for fleet management

---

## References

### Documentation
- [Product Requirements](PRD.md)
- [Project Overview](OVERVIEW.md)
- [Quick Start](quick-start.md)
- [Linux Platform Guide](PLATFORM_LINUX.md)
- [Windows Platform Guide](PLATFORM_WINDOWS.md)
- [macOS Platform Guide](PLATFORM_MACOS.md)
- [Security Posture](SECURITY_POSTURE.md)
- [BPF Compatibility](BPF_COMPATIBILITY.md)

### External Resources
- [eBPF Documentation](https://ebpf.io/)
- [WASM Specification](https://webassembly.org/)
- [Wazero Runtime](https://wazero.io/)
- [Microsoft ETW](https://docs.microsoft.com/en-us/windows/win32/etw/)
- [eBPF-for-Windows](https://github.com/microsoft/ebpf-for-windows)
- [Apple ESF](https://developer.apple.com/documentation/endpointsecurity)

---

**Last Updated:** 2026-06-12  
**Version:** 1.2.0-beta  
**Status:** Phase 6 In Progress (LSM-BPF Kernel Enforcement)