<p align="center">
  <img src="https://github.com/user-attachments/assets/55cb3f75-fb55-4537-858d-8c7b94facbc2" alt="warmor logo" width="260">
</p>

<h1 align="center">Write policy once. Enforce it everywhere.</h1>

<p align="center">
  <strong>Warmor is a runtime security enforcer that carries your policy across platforms.</strong><br>
  Write rules in YAML or Rust, compile them to WebAssembly, and evaluate them with the same engine — from the Linux kernel to Windows and macOS.
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

<p align="center">
  <a href="#quick-start"><strong>Quick Start</strong></a> &bull;
  <a href="docs/STATUS.md"><strong>What ships today</strong></a> &bull;
  <a href="docs/README.md"><strong>Explore the docs</strong></a>
</p>

---

## The problem: your security policy doesn't travel

Every platform has its own enforcement API, its own event model, its own rule language. Write a deny rule for one host and you rewrite it for the next. Warmor fixes that by making **the policy — not the platform — the unit you deploy**: a WebAssembly module, evaluated the same way everywhere, backed by kernel hooks on Linux.

> Warmor is **pre-stable**. Linux is the mature platform; Windows and macOS are experimental. [See exactly what ships on `main`](docs/STATUS.md).

## Why Warmor

- **Portable by design.** One policy in YAML or Rust → one WASM module → one evaluator on Linux, Windows and macOS.
- **Kernel-fast when it counts.** LSM-BPF hooks block known-deny operations in the kernel (`-EPERM`) before userspace sees them; everything else is evaluated in a WASM sandbox and enforced in userspace.
- **Sandboxed evaluation.** Wazero runs each policy with a 16 MiB memory cap and a 50 ms deadline; exceeding either fails closed (DENY).
- **Signed from author to agent.** Ed25519 signatures on WASM policies and OCI bundles, checked at startup, on reload and on every policy-server download.
- **Built for real fleets.** A policy server with versioned rollouts, mTLS/JWT, durable state, and a public [control-plane protocol](docs/control-plane-protocol.md) for hosted implementations.

## How it works

```
  YAML / Rust policy ──▶ warmor-compile ──▶ WASM module ──▶ daemon
                                                              │
   ┌────────────┐     ┌──────────────┐     ┌──────────────────┐
   │  Kernel    │────▶│  Ring buffer │────▶│  WASM evaluator  │
   │  LSM/eBPF  │◀────│  Policy map  │◀────│  Decision cache  │
   │   hooks    │     └──────────────┘     └──────────────────┘
   └────────────┘
   LSM: exec, file_open, connect, bind, listen, ptrace, sb_mount
   tracepoints: execve, openat, connect
```

1. **Kernel hooks** see operations — LSM-BPF and tracepoints on Linux, ETW (plus experimental eBPF-for-Windows) on Windows, ESF on macOS.
2. **The BPF policy map** answers operations that already have an entry, in the kernel. A miss is allowed and reported to userspace.
3. **The WASM sandbox** evaluates new events with strict resource limits; errors and timeouts fail closed.
4. **Decisions feed back** into the kernel map for exec and connect on `main`; other denies are enforced in userspace.

**Two tiers, honestly:** with `--lsm-enforce`, the kernel returns `-EPERM` for operations that already have a deny entry (exec = exact binary path, connect = remote address and port). Everything else is detected by WASM and then terminated with `SIGKILL` — the first occurrence of a denied operation is **detected and killed, not prevented**. The opt-in [`--default-deny`](docs/design/kernel-default-deny.md) mode closes the first-occurrence gap for exec/connect when the policy is an eligible allowlist.

## Quick Start

Requirements: Linux with BTF (`/sys/kernel/btf/vmlinux`), Go 1.26+, and Rust with the `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`) to compile YAML policies. Kernel blocking also needs `CONFIG_BPF_LSM=y` with `bpf` in `/sys/kernel/security/lsm`.

```bash
git clone https://github.com/yasindce1998/warmor.git && cd warmor
go build -o bin/ ./cmd/...              # prebuilt BPF objects are checked in

# Compile a YAML policy to WASM (-o may appear before or after the input file)
./bin/warmor-compile -o crypto.wasm examples/policies/block-crypto-miners.yaml

# Start in audit mode first: denies are logged, nothing is killed
sudo ./bin/warmor-daemon --policy crypto.wasm --audit --event-sink stdout

# Then enforce: LSM blocking for cached exec/connect denies, SIGKILL for the rest
sudo ./bin/warmor-daemon --policy crypto.wasm --lsm-enforce
```

> **Start with `--audit`.** Without it, denied processes are SIGKILLed even when `--lsm-enforce` is off. The default `--policy` (`policies/example/policy.wasm`, built with `make build-policy`) is a starter example, not a production policy. The daemon prints a `Security posture:` line at startup showing whether LSM blocking is active, audit-only, or unavailable.

> **First time?** Follow the [Getting Started Guide](GETTING_STARTED.md) for setup, dependencies and your first policy.

## Capabilities at a glance

Status is per feature — see [Feature Status](docs/STATUS.md) for the full, code-verified matrix.

| Area | What it does | Status |
|---|---|---|
| **Policy engine** | YAML DSL with globs, variables, conditions and temporal windows; Rust WASM policies; hot reload; signed policies | Shipped |
| **Kernel enforcement** | 7 LSM hooks + 3 tracepoints; cached exec/connect denies blocked in-kernel; opt-in default-deny allowlists | Shipped / partial |
| **Policy feedback** | Dynamic kernel fast-path for exec, connect, bind, listen, mount and ptrace denies | Shipped (deny-only) |
| **Learning & simulation** | `warmor-learn` synthesizes an allowlist from recorded events; `warmor-simulate` replays against a candidate policy | Shipped (offline) |
| **Supply-chain integrity** | In-kernel IMA SHA-256 allowlist for executed binaries (`CONFIG_IMA` required) | Shipped |
| **Escape detection** | Container-breakout patterns with `alert`/`deny` modes | Shipped (detection) |
| **Attack graph & blast radius** | MITRE ATT&CK correlation, kill-chain metrics and container reachability | Shipped / partial |
| **Dashboard & SIEM** | Live SSE dashboard; CEF syslog sink with MITRE labels | Shipped |
| **Drift** | Rolling host-behavior rates; server comparator for identified workloads | Local collection ships |
| **Canary rollouts** | Percentage rollouts with consistent hashing; automatic rollback is library-only | Partial |
| **Fleet state** | Versioned, durable policy server with signed assignment mode | Shipped |

### A few things you can do today

- **Synthesize a policy from real traffic:**
  ```bash
  sudo warmor-daemon --policy crypto.wasm --audit --event-sink file:/var/log/warmor/events.ndjson
  warmor-learn --events /var/log/warmor/events.ndjson --follow --duration 30m -o learned-policy.yaml
  ```
- **Replay before you deploy:** `warmor-simulate --policy candidate.yaml --data /var/lib/warmor/events --since 7d -o report.json`
- **Refuse untrusted binaries:** `warmor-integrity-scan --rootfs /path --all -o integrity-db.json` then run the daemon with `--integrity-db integrity-db.json --integrity-mode audit` (enforce once verified). See [Supply Chain Integrity](docs/supply-chain-integrity.md).
- **Detect breakout attempts:** `--escape-detect=alert|deny`. See [Escape Detection](docs/escape-detection.md).
- **Watch live decisions:** `--dashboard-port 8080` serves `/dashboard` on 127.0.0.1. See [Dashboard access](docs/dashboard.md).
- **Enforce time windows:** a rule's `temporal:` block enforces container age and UTC time-of-day windows. See [Temporal Policies](docs/temporal-policies.md).

## Performance

Measured on one otherwise-idle laptop (WSL2, Core Ultra 5 135U) with the harness in [docs/PERFORMANCE.md](docs/PERFORMANCE.md), which has the methodology, caveats and commands (`make bench`, `make bench-kernel`). Kernel numbers come from a nested KVM VM, not bare metal. "Declared" means the policy exports its fields-read declaration — every compiled YAML policy does, no Rust crate under `policies/` does yet.

| Metric | Measured | Design target |
|---|---|---|
| Decision latency, cache hit | P95 1.2–1.3 µs | <100 µs |
| Decision latency, cache miss (WASM) | P95 32 µs (YAML), 55 µs (Rust `advanced`) | <100 µs |
| Cache hit rate, synthetic host workload | 95.4% declared; 0% undeclared | >90% |
| Throughput, daemon event loop | 175k events/s declared; 24k–41k undeclared | 100k events/s |
| Memory (RSS, in-process harness) | 60–104 MB declared; 105–128 MB undeclared | <50 MB (not met) |
| Kernel fast path (policy-map hit) | 0.11 µs connect, 0.34 µs exec | <1 µs |

## Platforms

| Platform | Technology | Status on `main` |
|---|---|---|
| **Linux** | eBPF tracepoints + LSM-BPF (7 hooks) | Most mature. Kernel blocking for cached exec/connect denies; detect-then-`SIGKILL` for everything else. LSM attach tested in a VM in CI. |
| **Windows** | ETW, plus eBPF-for-Windows | **Experimental beta.** The ETW path (detect, then `TerminateProcess`) is CI-tested; eBPF-for-Windows kernel blocking is unverified. |
| **macOS** | Endpoint Security Framework | **Experimental, detection only.** AUTH events are always answered ALLOW; release archives contain tools only, no daemon. |

## Policy Toolchain

| Tool | Purpose |
|---|---|
| `warmor-daemon` | Enforcement daemon: tracepoints, LSM-BPF hooks, WASM evaluation, event sinks, policy-server client |
| `warmor-server` | Central policy server: agent registration and heartbeats, policy versions, percentage rollouts, mTLS/JWT |
| `warmor-controller` | Kubernetes controller: validates and compiles `WarmorPolicy` CRs and publishes the node-wide effective-policy ConfigMap |
| `warmor-compile` | YAML → WASM compiler (needs `cargo` and the `wasm32-unknown-unknown` target) |
| `warmorctl` | Interactive TUI (dashboard, agents, policies, rollouts, certs) |
| `warmor-learn` / `warmor-simulate` | Synthesize a policy from events / replay events against a candidate policy |
| `warmor-integrity-scan` | Build and verify SHA-256 binary hash databases (the daemon's `--integrity-db` allowlist) |
| `warmor-policy-gen` / `warmor-sbom-policy` | Generate policies from audit logs / SBOM manifests |
| `warmor-policy-diff` / `warmor-policy-merge` | Compare two policies / merge policies with conflict resolution |
| `warmor-policy-bundle` | Package policies into signed OCI bundles; sign/verify detached `<policy>.sig` |
| `warmor-policy-assignment` | Build and verify signed deployment assignments and agentstore publication artifacts |
| `warmor-oci-hook` | **Experimental.** OCI runtime hook reporting container start/stop to `warmor-server` (no auth/TLS; only works with `--insecure`) |
| `warmor-policy-host` | **Experimental.** Supervised WASM worker for the opt-in `--experimental-supervised-policy-host` backend |

There is no `warmor-dashboard` binary; the SSE dashboard is served by the daemon itself with `--dashboard-port`.

## Rust WASM policy library

10 example Rust crates cover threat scenarios from container escape to cryptojacking. All build for `wasm32-unknown-unknown`, use the JSON ABI (`evaluate_syscall`), and are checked against the real host in CI (`TestPolicyCrates`). See [Rust Policy Examples](docs/rust-policy-examples.md) and the [ABI v4 design](docs/design/abi-v4-process-context.md).

| Policy | Domain | Policy | Domain |
|---|---|---|---|
| [`advanced`](policies/advanced/) | Process/file enforcement | [`cross-platform`](policies/cross-platform/) | Platform-aware security |
| [`multi`](policies/multi/) | Multi-event dispatch | [`container-escape`](policies/container-escape/) | Container breakout (12 techniques) |
| [`supply-chain`](policies/supply-chain/) | Runtime integrity (9 controls) | [`temporal-access`](policies/temporal-access/) | Time-based access control |
| [`zero-trust-net`](policies/zero-trust-net/) | Network microsegmentation | [`lateral-movement`](policies/lateral-movement/) | Lateral movement detection |
| [`crypto-mining`](policies/crypto-mining/) | Cryptojacking detection | [`example`](policies/example/) | Starter template |

```bash
rustup target add wasm32-unknown-unknown
cd policies/container-escape && cargo build --release --target wasm32-unknown-unknown
# Or build every crate: ./scripts/build-rust-policies.sh
```

## Kubernetes

> **The Helm chart does not work on `main` and is being fixed — do not install it yet.** It has no value that enables `--lsm-enforce`; `--set config.*` values are ignored; the ConfigMap ships YAML that the distroless image cannot compile; the webhook has no handler and the `WarmorPolicy` CRD has no controller. See [Feature Status](docs/STATUS.md#5-container-runtime-and-kubernetes).

The chart (`deploy/helm/warmor`) contains a DaemonSet with BPF capabilities, RBAC, a ServiceMonitor, Grafana dashboards and alert rules.

## Dive deeper

The full [documentation index](docs/README.md) covers every guide, contract and design document. Good next stops:

- [Getting Started](GETTING_STARTED.md) and the [Build Guide](BUILD.md)
- [Feature Status](docs/STATUS.md) — the source of truth for what ships today
- [Architecture](docs/architecture.md), [Security Posture](docs/SECURITY_POSTURE.md), [BPF Compatibility](docs/BPF_COMPATIBILITY.md)
- [Policy Authoring](docs/policy-authoring.md), [Policy Toolchain](docs/policy-toolchain.md), [Control-plane Protocol](docs/control-plane-protocol.md)
- [Operations](docs/operations.md), [Dashboard](docs/dashboard.md), [CRD Usage](docs/crd-usage.md), [Releases](docs/RELEASING.md)

## Contributing

We welcome contributions! Open an [issue](https://github.com/yasindce1998/warmor/issues) or pull request.

**High-impact areas:**
- Wiring library-only features into the daemon and server (see [Feature Status](docs/STATUS.md))
- Windows eBPF kernel enforcement (build and verify the eBPF-for-Windows programs)
- macOS ESF blocking (AUTH responses currently always ALLOW)
- New Rust WASM policy crates, performance benchmarks, and integration tests on more kernel versions

## License

MIT License. See [LICENSE](LICENSE).

## Acknowledgments

- [cilium/ebpf](https://github.com/cilium/ebpf) — eBPF library for Go
- [tetratelabs/wazero](https://github.com/tetratelabs/wazero) — pure Go WebAssembly runtime (zero dependencies)
- [Rust](https://www.rust-lang.org/) — policy implementation language
- [MITRE ATT&CK](https://attack.mitre.org/) — threat framework for attack-graph correlation

---

<p align="center">
  <strong>Warmor</strong> — pre-stable. <a href="docs/STATUS.md">Feature Status</a> is the source of truth for what ships today.<br>
  <a href="https://github.com/yasindce1998/warmor/issues">Issues</a> &bull; <a href="https://github.com/yasindce1998/warmor/discussions">Discussions</a>
</p>
