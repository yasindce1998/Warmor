# warmor Architecture

**Last Updated:** 2026-10-14
**Status:** Describes current `main`. Phases 1-8 are partially done, and Phase 9 is mostly library-only. See [Feature Status](STATUS.md) for the per-feature reference.

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
│  │ MATURE   │    │ EXPER.   │    │  EXPERIMENTAL    │      │
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
│  │  - Structured logging (zerolog)                    │     │
│  │  - Decision cache (10k entries, TTL)               │     │
│  │  - Event sinks: stdout / file / webhook            │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

---

## Platform Support Matrix

| Platform | Status | Technology | Enforcement on `main` |
|----------|--------|------------|-------------|
| **Linux** | Most mature | eBPF tracepoints + LSM-BPF | Kernel `EPERM` for cached exec/connect denies (`--lsm-enforce`); detect-then-`SIGKILL` for everything else |
| **Windows** | Experimental beta | ETW (+ eBPF-for-Windows, never built or run in CI) | ETW: detect, then `TerminateProcess`. eBPF kernel blocking unverified. |
| **macOS** | Experimental, detection only | ESF | None: every AUTH event is answered ALLOW |

Latency and throughput are measured in [PERFORMANCE.md](PERFORMANCE.md); see [Performance](#performance-characteristics) for a summary.

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
- `LinuxPlatform` - eBPF-based monitoring and LSM enforcement (most mature)
- `WindowsPlatform` - ETW + eBPF-for-Windows (experimental)
- `DarwinPlatform` - ESF-based monitoring (experimental, detection only; requires cgo)

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
- Sandboxed execution in Wazero. A trap cannot crash the daemon, but there is **no memory or time limit yet**, so a looping policy hangs the event loop.
- Hot reload via SIGHUP
- Evaluation latency (target <100μs P95): measured P95 32μs for a compiled YAML policy and 55μs for the Rust `advanced` crate on a cache miss ([PERFORMANCE.md](PERFORMANCE.md))
- Two ABIs: JSON `evaluate_syscall(ptr,len)` and binary `evaluate_event`. If a module exports `evaluate_event`, the host uses the binary ABI.

### 4. Decision Cache

**Implementation:** map with TTL (5 min). When full, it evicts the entry with the oldest expiry with an O(n) scan. This is not a true LRU.

**Key Format:** `{type}:{pid}:{uid}:{target_hash}`

**Performance:**
- 10,000 entry capacity
- Hit rate has not been measured. The PID in the key means a new process always misses.

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

**Runtime compilation:** The daemon also accepts `.yaml`/`.yml` policy files directly and compiles them at load time. That needs `cargo` and the wasm32 target **on the enforcing host**, which the distroless image lacks. If a sibling `.wasm` with the same base name exists, it is loaded instead, even if stale.

**Temporal rules:** a rule's `temporal:` block is compiled into the same evaluator (the action applies outside the permitted window) and reads the ABI v3 wall clock and container age; see [Temporal Policies](temporal-policies.md).

**Known gap:** other keys the schema does not know are silently ignored.

### 6. Observability

**Metrics (Prometheus):**
- `warmor_events_total{action="ALLOW|DENY|LOG"}`
- `warmor_cache_hits_total`
- `warmor_cache_misses_total`
- `warmor_cache_size`
- `warmor_evaluation_latency_microseconds`
- `warmor_policy_info{path, version}`
- `warmor_events_processing_errors_total`
- `warmor_audit_denied_total`
- `warmor_events_processed_total{event_type}`, `warmor_events_dropped_total` (Windows monitors only; Linux readers block instead of dropping)
- `warmor_lsm_decisions_total{hook, action="deny|pass"}` (outcomes the kernel reports to userspace)
- `warmor_policy_map_syncs_total{result="synced|failed|skipped_unmatchable|skipped_unsound|skipped_stale"}`, `warmor_ebpf_map_entries{map_name}`
- `warmor_ebpf_loader_status` (1 = requested kernel enforcement active, 0 = degraded)
- `warmor_wasm_exec_duration_seconds{policy_id}`, `warmor_wasm_exec_errors_total{policy_id, kind="timeout|error"}`
- `warmor_policy_loads_total{policy_id, status}`
- `warmor_agent_registrations_total{status}`, `warmor_agent_heartbeats_total{status}`, `warmor_agent_last_heartbeat_timestamp{agent_id}` (agents connected to a policy server)

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

### Linux (eBPF) - Most mature

**Architecture:**
```
Application → Syscall → eBPF Hook → Ring Buffer → warmor Daemon → WASM → Decision
```

**eBPF Programs:**
- `execve_monitor.bpf.c` - Process execution monitoring
- `openat_monitor.bpf.c` - File access monitoring
- `connect_monitor.bpf.c` - Network connection monitoring

**Key Features:**
- Kernel-space monitoring through ring buffers
- Tracepoints observe only. A deny for a tracepoint event is enforced by `SIGKILL` from userspace.
- Latency and throughput have not been measured

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

Unlike tracepoint-based monitoring, which observes syscalls after they begin, LSM-BPF hooks are **synchronous**. They run inline in the kernel security path and can return `-EPERM` to block an operation before it completes. They do so **only on a map hit**. A miss is allowed (default-allow) and reported.

**What reaches the map on `main`:** the daemon writes WASM decisions into the map only for **exec** (exact path) and **connect** (endpoint) events, and only for tracepoint-origin events. File (the hook sees only the basename), bind, listen, ptrace and mount entries are never written, so those hooks never block. The map is not preloaded from the compiled policy, not cleared on reload, and has no eviction (HASH, 65536 entries).

**LSM Programs:**
- `lsm_exec.bpf.c` — `bprm_check_security` (can block exec on a map hit)
- `lsm_file.bpf.c` — `file_open` (observe only on `main`: no entries written)
- `lsm_connect.bpf.c` — `socket_connect` (can block connect on a map hit)
- `lsm_bind.bpf.c`, `lsm_listen.bpf.c`, `lsm_ptrace.bpf.c`, `lsm_mount.bpf.c` — observe only on `main`

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

**WASM→BPF Feedback Loop (exec and connect only):**
```
First occurrence:  LSM miss → allowed → event → WASM evaluates → DENY → SIGKILL + write decision to policy_map
Second occurrence: LSM hit → kernel allows/denies immediately (no userspace trip)
```

**Graceful Fallback:** If `CONFIG_BPF_LSM` is absent or the kernel lacks LSM-BPF support, the system falls back to tracepoint-only mode with a warning. The `--lsm-enforce` flag controls whether deny decisions are enforced or audit-only.

**Implementation Files:**
- `bpf/warmor_lsm.h` — Shared structs, maps, FNV-1a hash helper
- `bpf/lsm_exec.bpf.c` — Exec enforcement
- `bpf/lsm_file.bpf.c` — File access hook
- `bpf/lsm_connect.bpf.c` — Network enforcement
- `bpf/lsm_{bind,listen,ptrace,mount}.bpf.c` — Additional hooks
- `internal/ebpf/lsm_loader.go` — Go LSM program loader
- `internal/ebpf/policy_map.go` — Policy map manager (userspace↔BPF)

---

### Windows (ETW + eBPF-for-Windows) - Experimental

> The ETW path is what CI exercises. The eBPF-for-Windows programs and driver have **never been built or run in CI**, so the kernel-blocking rows below are unverified.

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

### macOS (ESF) - Experimental, detection only

> On `main` the ESF client answers **every AUTH event with ALLOW**. The cgo code is not compiled in CI, and release binaries are built without cgo.

**Architecture:**
```
Application → Syscall → ESF Hook → ESF Client → warmor Daemon → WASM → Decision
```

**ESF Event Types:**

**AUTH Events (could block; always answered ALLOW on `main`):**
- `ES_EVENT_TYPE_AUTH_EXEC` - Process execution
- `ES_EVENT_TYPE_AUTH_OPEN` - File open
- `ES_EVENT_TYPE_AUTH_CREATE` - File creation

**NOTIFY Events (Monitoring):**
- `ES_EVENT_TYPE_NOTIFY_EXIT` - Process termination
- `ES_EVENT_TYPE_NOTIFY_WRITE` - File write
- `ES_EVENT_TYPE_NOTIFY_CONNECT` - Network connection

**Key Features:**
- ESF event monitoring
- AUTH event enforcement: not implemented (always ALLOW)
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
4. If DENY (and not --audit) → act (platform-specific)
   ├─ Linux: SIGKILL the process (after the fact). If the kernel map already
   │         had a deny entry (exec/connect, --lsm-enforce), the kernel
   │         refused it with -EPERM before this point.
   ├─ Windows (ETW): TerminateProcess (PID reuse checked)
   ├─ Windows (eBPF): kernel map entry for next attempt (unverified)
   └─ macOS: nothing (AUTH always answered ALLOW)
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
4. On MISS: userspace WASM evaluates; DENY → SIGKILL. For exec and connect
   only, the result is written back to policy_map.
   ↓
5. Next identical exec/connect in the same cgroup → kernel fast path
```

---

## Performance Characteristics

Measured 2026-10-15 on one laptop (WSL2; kernel numbers in a nested KVM VM).
Methodology, raw output and caveats are in [PERFORMANCE.md](PERFORMANCE.md).
"Declared" policies export their fields-read declaration (every compiled
YAML policy); "undeclared" ones do not.

| Metric | Design target | Measured |
|--------|---------------|----------|
| P95 evaluation latency (cache miss, WASM) | <100μs | 32μs YAML, 38μs fixture, 55μs Rust `advanced` crate |
| P95 latency, cache hit | | 1.2–1.3μs |
| Kernel fast path (BPF map hit) | <1μs | 0.11μs connect, 0.34μs exec (BPF program run time) |
| Kernel, event sent to userspace | | about +13–20μs per event (reader wake-up) |
| Throughput (daemon event loop) | 100k events/s | 175k/s declared, 24k–41k/s undeclared |
| CPU overhead | <5% | 11% of one core at 10k events/s declared |
| Memory | <50MB | 60–128MB RSS (not met) |

---

## Security Considerations

### Privilege Requirements

**Linux:**
- Root/CAP_BPF required for eBPF
- Kernel blocking applies only to operations with a map entry. Everything else is detect-then-kill, which a fast process can race.

**Windows:**
- Administrator required for ETW/eBPF
- ETW: User-space (can be bypassed)
- eBPF: Kernel-level (cannot be bypassed)

**macOS:**
- Root required for ESF
- System Extension approval required
- Full Disk Access required
- No enforcement on `main`

### WASM Sandbox

**Isolation:**
- No file system access
- No network access
- No syscall access
- Memory-safe execution

**Resource Limits:**
- None on `main`. There is no memory-page limit or per-evaluation deadline, so an infinite loop in a policy hangs the event loop. Adding limits is in progress.

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

**Install:** not working on `main`. There is no LSM enforce value, the YAML policy needs `cargo` in a distroless image, and the webhook has no handler. See [Feature Status](STATUS.md#5-container-runtime-and-kubernetes).

### Distributed Mode with mTLS

```
┌─────────────────────────────────────────────────────────────┐
│                    warmor-server (Policy Hub)                │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────────┐ │
│  │  REST    │  │ Policy Store │  │  A/B Testing Engine   │ │
│  │  API     │  │ (WASM, vers.)│  │  (consistent hash)    │ │
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
└─────────────────┘ └──────────────┘ └──────────────────────┘
```

**Use Case:** Fleet management and centralized policy distribution. Per-container policy, containerd integration and consuming the OCI hook's bindings are **not implemented** on `main`. Downloaded policies are not signature-verified by the daemon.

### Monitoring Stack

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│   warmor-daemon ──(metrics:9090)──▶ Prometheus ──▶ Grafana  │
│                                                              │
│   Alert rules ship in deploy/prometheus and the Helm chart.  │
│   Rules on warmor_events_total work. Rules on LSM-decision,  │
│   heartbeat and policy-load metrics never fire (the metrics  │
│   are not updated), and warmor_ebpf_loader_status does not   │
│   exist.                                                     │
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
- **CRI-O / OCI hook** - `warmor-oci-hook` (experimental: no auth/TLS, bindings unused)
- **containerd** - library code only (`internal/container`), not wired
- **Kubernetes** - Helm chart and DaemonSet manifests (not working on `main`)

### Observability
- **Prometheus** - Metrics collection (events, cache, evaluation latency)
- **Grafana** - Pre-built dashboards with auto-provisioning
- **Alert Rules** - Deny rate spikes, heartbeat failures, load errors
- **zerolog** - Structured logging

---

## Development Phases

See [OVERVIEW.md](OVERVIEW.md) for the phase-by-phase summary and
[STATUS.md](STATUS.md) for the per-feature reference. In short:

- **Phases 1-2:** done. DENY is enforced by `SIGKILL`.
- **Phases 3-8:** partial. Highlights:
  - LSM hooks attach, but only exec/connect get kernel entries.
  - The policy server, mTLS/JWT, signed bundles and `warmorctl` ship.
  - The Helm chart, CRD, webhook, containerd and per-container policy do not work or are missing.
- **Phase 9:** `warmor-learn` and `warmor-simulate` ship, and so do YAML temporal policies. Integrity is offline only. Escape, drift, attack graph, blast radius and canary auto-rollback are library-only.

## Future Enhancements

- Kernel-side default-deny and preloading static rules from the compiled policy
- Wiring the library-only Phase 9 features into the daemon and server
- Policy signature verification in the daemon
- Verified eBPF-for-Windows enforcement and macOS ESF blocking
- Network policy (L3/L4 filtering via XDP)
- Distributed tracing (OpenTelemetry spans per event)

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

**Last Updated:** 2026-10-14  
**Status:** Phase 6 In Progress (LSM-BPF Kernel Enforcement)