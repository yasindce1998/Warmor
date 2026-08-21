

# Warmor

<p align="center">
  <img src="https://github.com/user-attachments/assets/55cb3f75-fb55-4537-858d-8c7b94facbc2" alt="warmor logo">
</p>

<p align="center">
  <strong>Kernel-level security enforcement that follows your containers everywhere.</strong><br>
  Write once. Enforce on Linux, Windows, macOS. Block threats before they execute.
</p>

<p align="center">
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go" alt="Go"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-1.70+-orange?style=flat&logo=rust" alt="Rust"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <a href="docs/OVERVIEW.md"><img src="https://img.shields.io/badge/Status-v0.1.0--pre--stable-yellow" alt="Status"></a>
  <a href="docs/PLATFORM_LINUX.md"><img src="https://img.shields.io/badge/Linux-eBPF%20%2B%20LSM-brightgreen" alt="Linux"></a>
  <a href="docs/PLATFORM_WINDOWS.md"><img src="https://img.shields.io/badge/Windows-ETW%20%2B%20eBPF-yellow" alt="Windows"></a>
  <a href="docs/PLATFORM_MACOS.md"><img src="https://img.shields.io/badge/macOS-ESF-yellow" alt="macOS"></a>
</p>

---

## What is Warmor?

Warmor (WebAssembly + Armor) is an autonomous security intelligence platform that enforces security policies at the kernel level using eBPF/LSM hooks and evaluates them in a WebAssembly sandbox. It solves the **policy portability problem** — write security rules once in YAML or Rust, compile to WASM, and enforce identically across Linux, Windows, and macOS.

Unlike traditional security agents that only monitor, Warmor **blocks threats synchronously** at the kernel security boundary. Denied operations never execute.

---

## Quick Start

```bash
git clone https://github.com/yasindce1998/warmor.git && cd warmor
make all
sudo ./warmor-daemon --policy policy.yaml --lsm-enforce
```

That's it. Your system is now enforcing security policy at the kernel level.

> **First time?** See the [Getting Started Guide](GETTING_STARTED.md) for detailed setup instructions, dependency installation, and your first policy walkthrough.

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│  YAML Policy  ──→  warmor-compile  ──→  WASM Module  ──→  Daemon   │
│                                                            │        │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐ │        │
│  │  Kernel  │───→│  Ring Buffer │───→│  WASM Evaluator  │─┘        │
│  │ LSM/eBPF │←───│  Policy Map  │←───│  Decision Cache  │          │
│  │  Hooks   │    └──────────────┘    └──────────────────┘          │
│  └──────────┘                                                       │
│   execve, openat, connect, sendto, recvfrom, mount, ptrace          │
└─────────────────────────────────────────────────────────────────────┘
```

1. **Kernel hooks** intercept syscalls (LSM-BPF on Linux, eBPF-for-Windows/ETW on Windows, ESF on macOS)
2. **BPF policy map** handles cached decisions in-kernel (<1us) — no userspace round-trip
3. **WASM sandbox** evaluates new events safely — policy bugs can't crash the system
4. **Decisions feed back** into the kernel map, accelerating future identical events

---

## Core Features

### Cross-Platform Enforcement

| Platform | Technology | Mode |
|----------|-----------|------|
| **Linux** | eBPF + LSM-BPF (7 hooks) | Production — kernel-level blocking |
| **Windows** | eBPF + ETW (hybrid mode) | Beta — kernel network enforcement + reliable telemetry |
| **macOS** | Endpoint Security Framework | Beta — AUTH event blocking |

### Performance

| Metric | Value |
|--------|-------|
| P95 Latency | <100us |
| Cache Hit Rate | >90% (10k LRU) |
| Memory | <50MB |
| CPU Overhead | <5% |
| Kernel fast-path | <1us (BPF map hit) |

### Policy Engine

- **YAML DSL** — Declarative rules with glob/regex matching, variables, conditions
- **Rust WASM** — Full Rust policies compiled to `wasm32-wasi` for complex logic
- **Hot-Reload** — SIGHUP to swap policies without restart or downtime
- **Two-Tier Cache** — First WASM eval compiles into BPF map; subsequent hits handled entirely in kernel
- **Policy Signing** — Ed25519 signed WASM bundles with verification chain

---

## Security Intelligence

Warmor goes beyond static policy enforcement — it learns, adapts, and predicts.

### Live Policy Synthesis

Observe containers in **learning mode**, record every allowed operation, then auto-generate a deny-everything-else policy. Zero manual rule writing.

```bash
warmor-learn --duration 30m -o learned-policy.yaml
```

### Policy Simulator

Replay days of historical events against a candidate policy **before deployment**. Know exactly what would break.

```bash
warmor-simulate --policy candidate.yaml --data ./events/ --since 7d -o report.json
```

### Container Escape Detection

Pattern-based detection of breakout techniques: `nsenter`, host filesystem mounts, ptrace across cgroup boundaries, Docker socket access, `/proc/*/ns/*` traversal, cloud metadata SSRF.

### Supply Chain Tripwires

eBPF-powered binary integrity verification at exec time. SHA-256 hash every binary in your image, load the allowlist into a BPF map, and block anything that doesn't match — in kernel, before it runs.

```bash
warmor-integrity-scan --rootfs /path -o integrity-db.json
```

### Attack Graph Visualization

Maps deny events to **MITRE ATT&CK** techniques. Builds kill-chain DAGs per container showing progression from reconnaissance through lateral movement to impact.

### Blast Radius Analysis

Real-time graph of container relationships (network connections, shared volumes, IPC namespaces). Query: "If container X is compromised, what can it reach?" — answered via BFS reachability analysis.

### Drift Detection

Behavioral fingerprinting across your fleet. Same image, different behavior? Z-score based outlier detection flags the anomalous node — potential compromise indicator.

### Canary Rollout with Auto-Rollback

Deploy new policies to a canary cohort. Warmor monitors deny-rate delta in real-time. If the canary exceeds threshold — automatic rollback. No humans in the loop for safety.

### Temporal Policies

Time-dimension constraints that static policies can't express:
- "Init binaries allowed only in first 60 seconds"
- "SSH only Mon-Fri 08:00-18:00"
- "No new binaries from /tmp after container stabilizes (5 min)"
- "Backup file creation only during 02:00-04:00 window"

---

## Policy Toolchain

| Tool | Purpose |
|------|---------|
| `warmor-daemon` | Main enforcement daemon with LSM-BPF hooks |
| `warmor-server` | Central fleet management, A/B rollouts, drift aggregation |
| `warmor-compile` | YAML to WASM compilation pipeline |
| `warmorctl` | Interactive TUI (dashboard, agents, policies, rollouts, certs) |
| `warmor-learn` | Learning mode — observe and synthesize policies |
| `warmor-simulate` | Replay historical events against candidate policies |
| `warmor-integrity-scan` | Build binary hash allowlists for supply chain enforcement |
| `warmor-policy-gen` | Generate policies from audit logs |
| `warmor-sbom-policy` | Generate policies from SBOM manifests |
| `warmor-policy-diff` | Compare two policies and show what changes |
| `warmor-policy-merge` | Merge multiple policies with conflict resolution |
| `warmor-policy-bundle` | Package policies into signed OCI bundles |
| `warmor-oci-hook` | Container runtime hook (containerd/CRI-O integration) |
| `warmor-dashboard` | Real-time SSE dashboard (policy decisions, counters) |

---

## Rust WASM Policy Library

10 production-ready Rust policy crates covering real-world threat scenarios:

| Policy | Threat Domain | Pattern |
|--------|--------------|---------|
| [`advanced`](policies/advanced/) | Process/file enforcement | evaluate_syscall |
| [`cross-platform`](policies/cross-platform/) | Platform-aware security | C FFI + evaluate |
| [`multi`](policies/multi/) | Multi-event dispatch | Tagged enum |
| [`container-escape`](policies/container-escape/) | Container breakout (12 techniques) | Tagged enum |
| [`supply-chain`](policies/supply-chain/) | Runtime integrity (9 controls) | Tagged enum |
| [`temporal-access`](policies/temporal-access/) | Time-based access control (8 rules) | Cross-platform |
| [`zero-trust-net`](policies/zero-trust-net/) | Network microsegmentation (10 controls) | Cross-platform |
| [`lateral-movement`](policies/lateral-movement/) | Lateral movement detection (10 techniques) | Tagged enum |
| [`crypto-mining`](policies/crypto-mining/) | Cryptojacking detection (12 indicators) | Tagged enum |
| [`example`](policies/example/) | Starter template | evaluate_syscall |

Build any policy:
```bash
cd policies/container-escape
cargo build --release --target wasm32-wasi
# Output: target/wasm32-wasi/release/container_escape.wasm
```

See [Rust Policy Examples](docs/rust-policy-examples.md) for full documentation and authoring guide.

---

## Kubernetes Deployment

```bash
helm install warmor deploy/helm/warmor \
  --set image.tag=latest \
  --set config.lsmEnforce=true \
  --set config.policyPath=/etc/warmor/policy.wasm
```

Includes: DaemonSet with BPF capabilities, RBAC, ServiceMonitor, Grafana dashboards, alert rules.

---

## Architecture

```
internal/
  enforcer/       — Core event loop, WASM evaluation, LSM integration
  ebpf/           — LSM-BPF loader, policy map, ring buffer, CO-RE BTF
  wasm/           — Wazero runtime, ABI v2, multi-event dispatch
  cache/          — Decision cache with BPF map sync
  streaming/      — Pipeline: enrichers → sinks (Prometheus, SIEM, file)
  policyserver/   — Fleet management, A/B rollouts, canary analyzer
  lineage/        — Process tree tracking (parent/child/cgroup ancestry)
  container/      — Runtime detection (Docker, containerd, CRI-O, Podman)
  learner/        — Learning mode recorder + policy synthesizer
  simulator/      — Event replay engine for policy testing
  integrity/      — Binary hash verification (SHA-256 + FNV-1a fast path)
  escape/         — Container escape pattern correlator
  drift/          — Behavioral fingerprint + z-score anomaly detection
  attackgraph/    — MITRE ATT&CK correlation + kill-chain DAG
  blastradius/    — Container relationship graph + BFS reachability
  temporal/       — Time-dimension enricher + constraint evaluation
  compiler/       — YAML → Rust → WASM compilation pipeline
  platform/       — OS abstraction (Linux eBPF, Windows ETW, macOS ESF)
  crypto/         — mTLS (Ed25519), JWT (HMAC+EdDSA), policy signing
  metrics/        — Prometheus counters, histograms, gauges
  logging/        — Structured JSON (zerolog), Windows Event Viewer integration
  dashboard/      — Real-time SSE dashboard (ring buffer, embedded HTML)
```

See [Architecture Deep Dive](docs/architecture.md) for data flow diagrams.

---

## Documentation

| Category | Documents |
|----------|-----------|
| **Getting Started** | [Quick Start](docs/quick-start.md) &bull; [Build Guide](BUILD.md) &bull; [Getting Started](GETTING_STARTED.md) |
| **Architecture** | [System Design](docs/architecture.md) &bull; [Security Posture](docs/SECURITY_POSTURE.md) &bull; [BPF Compatibility](docs/BPF_COMPATIBILITY.md) |
| **Platforms** | [Linux](docs/PLATFORM_LINUX.md) &bull; [Windows](docs/PLATFORM_WINDOWS.md) &bull; [macOS](docs/PLATFORM_MACOS.md) |
| **Policies** | [Authoring Guide](docs/policy-authoring.md) &bull; [Rust Examples](docs/rust-policy-examples.md) &bull; [YAML DSL](docs/policy-authoring.md) |
| **Toolchain** | [Policy Gen](docs/policy-generation.md) &bull; [SBOM Enforcement](docs/sbom-enforcement.md) &bull; [Diff](docs/policy-diff.md) &bull; [Merge](docs/policy-merge.md) &bull; [Bundle](docs/policy-bundle.md) |
| **Intelligence** | [Learning Mode](docs/learning-mode.md) &bull; [Simulator](docs/policy-simulator.md) &bull; [Escape Detection](docs/escape-detection.md) &bull; [Supply Chain](docs/supply-chain-integrity.md) |
| **Fleet** | [Canary Rollout](docs/canary-rollout.md) &bull; [Drift Detection](docs/drift-detection.md) &bull; [Attack Graph](docs/attack-graph.md) &bull; [Blast Radius](docs/blast-radius.md) &bull; [Temporal](docs/temporal-policies.md) |
| **Kubernetes** | [CRD Usage](docs/crd-usage.md) &bull; [Helm Chart](deploy/helm/warmor/) |
| **Project** | [Overview](docs/OVERVIEW.md) &bull; [PRD, Phase Tracking & Roadmap](docs/PRD.md) |

---

## Contributing

We welcome contributions! Open an [issue](https://github.com/yasindce1998/warmor/issues) or pull request.

**High-impact areas:**
- Windows eBPF kernel enforcement
- macOS ESF blocking mode improvements
- New Rust WASM policy crates (threat detection scenarios)
- Performance benchmarks and optimization
- Integration tests on additional kernel versions

---

## License

MIT License. See [LICENSE](LICENSE).

## Acknowledgments

- [cilium/ebpf](https://github.com/cilium/ebpf) — eBPF library for Go
- [tetratelabs/wazero](https://github.com/tetratelabs/wazero) — Pure Go WebAssembly runtime (zero dependencies)
- [Rust](https://www.rust-lang.org/) — Policy implementation language
- [MITRE ATT&CK](https://attack.mitre.org/) — Threat framework for attack graph correlation

---

<p align="center">
  <strong>Warmor v0.1.0</strong> — From policy enforcement to autonomous security intelligence.<br>
  <a href="https://github.com/yasindce1998/warmor/issues">Issues</a> &bull; <a href="https://github.com/yasindce1998/warmor/discussions">Discussions</a>
</p>
