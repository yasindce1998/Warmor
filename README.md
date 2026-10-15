

# Warmor

<p align="center">
  <img src="https://github.com/user-attachments/assets/55cb3f75-fb55-4537-858d-8c7b94facbc2" alt="warmor logo">
</p>

<p align="center">
  <strong>Kernel-level security enforcement that follows your containers everywhere.</strong><br>
  Write policy once, compile to WASM, evaluate it the same way on every platform.
</p>

<p align="center">
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go" alt="Go"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-1.70+-orange?style=flat&logo=rust" alt="Rust"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <a href="docs/STATUS.md"><img src="https://img.shields.io/badge/Status-pre--stable-yellow" alt="Status"></a>
  <a href="docs/PLATFORM_LINUX.md"><img src="https://img.shields.io/badge/Linux-eBPF%20%2B%20LSM-brightgreen" alt="Linux"></a>
  <a href="docs/PLATFORM_WINDOWS.md"><img src="https://img.shields.io/badge/Windows-experimental-orange" alt="Windows"></a>
  <a href="docs/PLATFORM_MACOS.md"><img src="https://img.shields.io/badge/macOS-experimental%2C%20detection%20only-orange" alt="macOS"></a>
</p>

---

## What is Warmor?

Warmor (WebAssembly + Armor) is a runtime security enforcer. It hooks the kernel with eBPF and LSM-BPF and evaluates every event against a policy running in a WebAssembly sandbox. It targets the **policy portability problem**: write security rules once in YAML or Rust, compile them to WASM, and evaluate them with the same engine on Linux, Windows and macOS. Linux is the mature platform; Windows and macOS are experimental.

**How enforcement works today (two tiers):**

1. **In the kernel (Linux, `--lsm-enforce`).** LSM hooks return `-EPERM` for operations that already have a deny entry in the kernel policy map. On `main`, those entries are only written for **exec (exact binary path)** and **connect (remote address and port)**. They are written after the WASM policy has seen that operation once.
2. **In userspace (everything else).** A map miss is allowed by the kernel and sent to the daemon. The WASM policy evaluates it, and on DENY the daemon kills the process with `SIGKILL`. The first occurrence of a denied operation, and every file, bind, listen, ptrace or mount deny, is therefore **detected and then killed, not prevented**.

Pre-loading kernel rules from the compiled policy and a default-deny mode are in progress. See **[Feature Status](docs/STATUS.md)** for exactly what ships on `main`.

---

## Quick Start

Requirements: Linux with BTF (`/sys/kernel/btf/vmlinux`), Go 1.26+, and Rust with the `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`) for compiling YAML policies. Kernel blocking also needs `CONFIG_BPF_LSM=y` with `bpf` in `/sys/kernel/security/lsm`.

```bash
git clone https://github.com/yasindce1998/warmor.git && cd warmor
go build -o bin/ ./cmd/...              # prebuilt BPF objects are checked in

# Compile a YAML policy to WASM (-o must come before the input file)
./bin/warmor-compile -o crypto.wasm examples/policies/block-crypto-miners.yaml

# Start in audit mode first: denies are logged, nothing is killed
sudo ./bin/warmor-daemon --policy crypto.wasm --audit --event-sink stdout

# Then enforce: LSM blocking for cached exec/connect denies, SIGKILL for the rest
sudo ./bin/warmor-daemon --policy crypto.wasm --lsm-enforce
```

> **Start with `--audit`.** Without it, denied processes are SIGKILLed even when `--lsm-enforce` is off. The daemon's default `--policy` (`policies/example/policy.wasm`, built with `make build-policy`) is a starter example, not a production policy.

The daemon prints a `Security posture:` line at startup that tells you whether LSM blocking is active, audit-only, or unavailable (tracepoint observe mode).

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
│   LSM: exec, file_open, connect, bind, listen, ptrace, sb_mount     │
│   tracepoints: execve, openat, connect                              │
└─────────────────────────────────────────────────────────────────────┘
```

1. **Kernel hooks** see operations (LSM-BPF and tracepoints on Linux; ETW, plus experimental eBPF-for-Windows, on Windows; ESF on macOS)
2. **BPF policy map** answers operations that already have an entry, in the kernel. A miss is allowed and reported to userspace.
3. **WASM sandbox** evaluates each new event in an isolated module. It has no memory or time limit yet, so a looping policy can stall the event loop.
4. **Decisions feed back** into the kernel map, for exec and connect only on `main`. A userspace DENY kills the offending process.

---

## Core Features

### Cross-Platform Enforcement

| Platform | Technology | Status on `main` |
|----------|-----------|------|
| **Linux** | eBPF tracepoints + LSM-BPF (7 hooks) | Most mature. Kernel blocking for cached exec/connect denies, and detect-then-`SIGKILL` for everything else. LSM attach is tested in a VM in CI. |
| **Windows** | ETW, plus eBPF-for-Windows | **Experimental beta.** The ETW path (detect, then `TerminateProcess`) is what is tested in CI. The eBPF-for-Windows programs have never been built or run in CI, so their kernel blocking is unverified. |
| **macOS** | Endpoint Security Framework | **Experimental, detection only.** Every AUTH event is answered ALLOW. The cgo ESF code is not compiled in CI, and release binaries are built without cgo. |

### Performance (design targets, unverified)

These are **targets, not measurements**. None of them has been benchmarked on `main`. A benchmark harness is in progress.

| Metric | Design target |
|--------|-------|
| P95 evaluation latency | <100us |
| Decision cache hit rate | >90% (10k-entry cache; the current key includes the PID, which works against this) |
| Memory | <50MB |
| CPU overhead | <5% |
| Kernel fast path | <1us (BPF map hit) |

### Policy Engine

- **YAML DSL** — Declarative rules with glob matching, variables and conditions, compiled by `warmor-compile` (needs `cargo` and the `wasm32-unknown-unknown` target). Unknown keys are silently ignored, so check rules with `--rust-only` if in doubt.
- **Rust WASM** — Full Rust policies compiled to `wasm32-unknown-unknown` for complex logic
- **Hot-Reload** — SIGHUP swaps the WASM module without a restart. Kernel map entries from the old policy are not cleared yet.
- **Two-Tier Cache** — A userspace decision cache, plus the kernel policy map for exec and connect decisions
- **Policy Signing** — Ed25519 signatures on WASM policies: signed OCI bundles (`warmor-policy-bundle --push/--pull`), and detached `<policy>.sig` files that `warmor-daemon --verify-key` checks at startup, on reload and on every policy server download, failing closed (see [Policy Bundle](docs/policy-bundle.md#detached-signatures-daemon-and-policy-server))

---

## Security Intelligence

Warmor goes beyond static policy enforcement. On `main`, **learning and simulation ship as CLI tools**. The other features in this section are **experimental Go libraries with unit tests that are not yet wired into the daemon or server**: no flag or binary reaches them. See [Feature Status](docs/STATUS.md).

### Live Policy Synthesis — Shipped (offline)

Record events with the daemon's file sink, then have `warmor-learn` synthesize an allowlist policy from them.

```bash
sudo warmor-daemon --policy crypto.wasm --audit --event-sink file:/var/log/warmor/events.ndjson
warmor-learn --events /var/log/warmor/events.ndjson --follow --duration 30m -o learned-policy.yaml
```

### Policy Simulator — Shipped

Replay recorded events against a candidate policy **before deployment** to see what would newly be denied. The simulator reads `events-*.ndjson` files from a directory. The daemon has no dedicated event-store sink yet, so name the file sink accordingly.

```bash
sudo warmor-daemon --policy current.wasm --audit --event-sink file:/var/lib/warmor/events/events-current.ndjson
warmor-simulate --policy candidate.yaml --data /var/lib/warmor/events --since 7d --format json -o report.json
```

### Supply Chain Integrity — Shipped (in-kernel; requires `CONFIG_IMA`)

Refuse to execute any binary whose **content** isn't in an allowlist of known-good SHA-256 digests, wherever it lives. A sleepable LSM program hashes each exec with IMA. Requires `CONFIG_IMA` with SHA-256 as IMA's hash (the daemon checks at startup). Tested in VMs on IMA-enabled 6.1 and 6.18 kernels; start with `audit`.

```bash
warmor-integrity-scan --rootfs /path --all -o integrity-db.json
sudo warmor-daemon --policy policy.wasm --integrity-db integrity-db.json --integrity-mode audit   # then enforce
```

See [Supply Chain Integrity](docs/supply-chain-integrity.md).

### Container Escape Detection — Shipped (detection, after the fact)

`--escape-detect=alert|deny` matches events from container cgroups against breakout techniques: `nsenter`, block-device and cgroup v1 mounts, cross-cgroup ptrace, container runtime socket connects, `/proc/*/ns/*` access, and escape tools. Matches are logged, counted and labelled; `deny` also terminates the process. See [Escape Detection](docs/escape-detection.md).

### Attack Graph — Experimental (library only, not yet wired into the daemon)

Maps events to **MITRE ATT&CK** techniques and builds per-container kill-chain graphs (`internal/attackgraph`).

### Blast Radius Analysis — Experimental (library only, not yet wired into the daemon)

Container relationship graph (network connections, shared volumes, shared namespaces) with BFS reachability queries (`internal/blastradius`).

### Drift Detection — Experimental (library only, not yet wired into the server)

Z-score outlier detection over behavioural fingerprints of containers running the same image (`internal/drift`).

### Canary Rollout — Partial (manual ramp; auto-rollback is library only)

`warmor-server` supports percentage-based rollouts with consistent hashing: create, ramp, complete and abort through the admin API or `warmorctl`. The deny-rate `CanaryAnalyzer` that would trigger automatic rollback exists but is **not connected**. Nothing feeds it decisions, so there is **no automatic rollback** on `main`.

### Temporal Policies — Experimental (library only, not yet wired into the daemon)

Time constraints (container age, time of day, day of week) in `internal/temporal`. The YAML compiler does **not** understand a `temporal:` block yet. It silently ignores it, which turns the rule into an unconditional one, so do not use `temporal:` in policies today.

---

## Policy Toolchain

| Tool | Purpose |
|------|---------|
| `warmor-daemon` | Enforcement daemon: tracepoints, LSM-BPF hooks, WASM evaluation, event sinks, policy-server client |
| `warmor-server` | Central policy server: agent registration and heartbeats, policy versions, percentage rollouts, mTLS/JWT |
| `warmor-compile` | YAML to WASM compiler (needs `cargo` and the `wasm32-unknown-unknown` target) |
| `warmorctl` | Interactive TUI (dashboard, agents, policies, rollouts, certs). Interactive only; there are no subcommands. |
| `warmor-learn` | Synthesize a policy from recorded daemon events |
| `warmor-simulate` | Replay recorded events against candidate policies |
| `warmor-integrity-scan` | Build and verify SHA-256 binary hash databases (the daemon's `--integrity-db` allowlist) |
| `warmor-policy-gen` | Generate policies from audit logs |
| `warmor-sbom-policy` | Generate policies from SBOM manifests |
| `warmor-policy-diff` | Compare two policies and show what changes |
| `warmor-policy-merge` | Merge multiple policies with conflict resolution |
| `warmor-policy-bundle` | Package policies into signed OCI bundles; sign/verify detached `<policy>.sig` |
| `warmor-oci-hook` | **Experimental.** OCI runtime hook that reports container start/stop to `warmor-server`. It has no auth or TLS, so it only works against `warmor-server --insecure`, and the server does not use the bindings yet. |

There is no `warmor-dashboard` binary on `main`. The SSE dashboard in `internal/dashboard` is library-only.

---

## Rust WASM Policy Library

10 example Rust policy crates covering threat scenarios.

All 10 crates build for `wasm32-unknown-unknown` and use the JSON ABI (`evaluate_syscall`). CI builds every crate and runs each through the real WASM host (`TestPolicyCrates`): benign events must be allowed and the crate's own attack examples denied. The host does not send `args`, `parent_comm`, `cgroup_id` or time context yet, so rules on those fields never fire.

| Policy | Threat Domain | Pattern |
|--------|--------------|---------|
| [`advanced`](policies/advanced/) | Process/file enforcement | evaluate_syscall |
| [`cross-platform`](policies/cross-platform/) | Platform-aware security | Flat struct |
| [`multi`](policies/multi/) | Multi-event dispatch | Tagged enum |
| [`container-escape`](policies/container-escape/) | Container breakout (12 techniques) | Tagged enum |
| [`supply-chain`](policies/supply-chain/) | Runtime integrity (9 controls) | Tagged enum |
| [`temporal-access`](policies/temporal-access/) | Time-based access control (8 rules) | Flat struct |
| [`zero-trust-net`](policies/zero-trust-net/) | Network microsegmentation (10 controls) | Flat struct |
| [`lateral-movement`](policies/lateral-movement/) | Lateral movement detection (10 techniques) | Tagged enum |
| [`crypto-mining`](policies/crypto-mining/) | Cryptojacking detection (12 indicators) | Tagged enum |
| [`example`](policies/example/) | Starter template | evaluate_syscall |

Build any policy:
```bash
rustup target add wasm32-unknown-unknown
cd policies/container-escape
cargo build --release --target wasm32-unknown-unknown
# Output: target/wasm32-unknown-unknown/release/warmor_policy_container_escape.wasm

# Or build every crate at once:
./scripts/build-rust-policies.sh
```

See [Rust Policy Examples](docs/rust-policy-examples.md) for full documentation and authoring guide.

---

## Kubernetes Deployment

> **The Helm chart does not work on `main` and is being fixed.** Do not install it yet.
> - The chart has no value that enables `--lsm-enforce`, and `--set config.*` values are ignored.
> - The policy ConfigMap ships YAML, which the daemon can only compile with `cargo`, and the distroless image does not include it.
> - The `ValidatingWebhookConfiguration` has no handler behind it.
> - The `WarmorPolicy` CRD has no controller.
>
> See [Feature Status](docs/STATUS.md#5-container-runtime-and-kubernetes).

The chart (`deploy/helm/warmor`) contains a DaemonSet with BPF capabilities, RBAC, a ServiceMonitor, Grafana dashboards and alert rules. Some of the dashboards and alerts depend on metrics that the daemon does not update yet.

---

## Architecture

```
internal/                                      (status on main)
  enforcer/       — Core event loop, WASM evaluation, SIGKILL actions   Shipped
                    (NetFilter, sandbox, learning mode inside)           Library-only
  ebpf/           — Tracepoint + LSM-BPF loaders, policy map, ring buf   Shipped (see STATUS for map gaps)
  wasm/           — Wazero runtime, JSON and binary ABIs                 Shipped
  cache/          — Userspace decision cache                             Shipped
  streaming/      — Pipeline: enrichers → stdout/file/webhook sinks      Shipped (syslog sink library-only)
  policyserver/   — Policy server, percentage rollouts                   Shipped (canary analyzer library-only)
  lineage/        — Process tree tracking                                Partial (no PPID in events)
  learner/        — Learning recorder + policy synthesizer               Shipped (warmor-learn)
  simulator/      — Event replay engine                                  Shipped (warmor-simulate)
  integrity/      — SHA-256 binary hash scan/verify                      Shipped (kernel side experimental)
  compiler/       — YAML → Rust → WASM compilation pipeline              Shipped
  platform/       — Linux eBPF, Windows ETW / eBPF-for-Windows, macOS    Linux shipped; Windows/macOS experimental
  crypto/         — mTLS (Ed25519), JWT (HMAC+EdDSA), bundle signing     Shipped
  metrics/        — Prometheus collector and exporter                    Partial (exporter metrics never updated)
  logging/        — Structured JSON (zerolog)                            Shipped
  policygen/ sbompolicy/ policydiff/ policymerge/ policybundle/          Shipped (CLI tools)
  container/      — Runtime detection, containerd monitor                Library-only
  escape/         — Container escape pattern correlator                  Shipped (--escape-detect)
  drift/          — Behavioral fingerprint + z-score detection           Library-only
  attackgraph/    — MITRE ATT&CK correlation + kill-chain DAG            Library-only
  blastradius/    — Container relationship graph + BFS reachability      Library-only
  temporal/       — Time-dimension enricher + constraint evaluation      Library-only
  patterns/       — Glob/regex matcher helpers                           Library-only
  dashboard/      — SSE dashboard (ring buffer, embedded HTML)           Library-only
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
| **Project** | [Feature Status](docs/STATUS.md) &bull; [Overview](docs/OVERVIEW.md) &bull; [PRD, Phase Tracking & Roadmap](docs/PRD.md) |

---

## Contributing

We welcome contributions! Open an [issue](https://github.com/yasindce1998/warmor/issues) or pull request.

**High-impact areas:**
- Wiring the library-only features into the daemon (see [Feature Status](docs/STATUS.md))
- Windows eBPF kernel enforcement (build and verify the eBPF-for-Windows programs)
- macOS ESF blocking (AUTH responses currently always ALLOW)
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
  <strong>Warmor</strong> — pre-stable. See <a href="docs/STATUS.md">Feature Status</a> for what ships today.<br>
  <a href="https://github.com/yasindce1998/warmor/issues">Issues</a> &bull; <a href="https://github.com/yasindce1998/warmor/discussions">Discussions</a>
</p>
