# Policy Authoring Guide

Warmor policies are YAML files that define what process executions, file accesses, and network connections to allow, deny, or audit.

## Structure

```yaml
name: my-policy
version: 1
description: "What this policy enforces"

variables:
  my_list:
    - "/usr/bin/curl"
    - "/usr/bin/wget"

rules:
  - name: rule-name
    event: process | file | network
    conditions:
      all:         # AND — all must match
        - field: { operator: value }
      any:         # OR — at least one must match
        - field: { operator: value }
    action: allow | deny | log
    reason: "Human-readable explanation"
    temporal:      # optional, deny/log rules only: act only OUTSIDE this window
      max_container_age: "5m"
      time_of_day: { start: { hour: 9, minute: 0 }, end: { hour: 17, minute: 0 } }  # UTC
      days_of_week: [Monday, Friday]

default_action: allow | deny | log
```

See [Temporal Policies](temporal-policies.md) for the `temporal:` block.

## Event Types

| Event | Description | Available Fields |
|-------|-------------|-----------------|
| `process` | Process execution (execve) | `pid`, `uid`, `gid`, `comm`, `path`, `args`* |
| `file` | File system access | `pid`, `uid`, `gid`, `comm`, `path`, `operation`, `flags` |
| `network` | Network connections | `pid`, `uid`, `gid`, `comm`, `operation`, `protocol`, `remote_addr`, `remote_port`, `local_port` |

\* `args` is accepted by the schema but the host does not send it to WASM yet, so rules on it never fire.

## Condition Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `eq` | Exact match | `comm: { eq: "python3" }` |
| `not` | Not equal to | `uid: { not: 0 }` |
| `any_of` | Value in list | `path: { any_of: $my_list }` |
| `none_of` | Value not in list | `path: { none_of: $blocked }` |
| `glob` | Glob pattern match | `path: { glob: "/tmp/**" }` |
| `gt` / `lt` / `gte` / `lte` | Numeric comparison | `uid: { gte: 1000 }` |
| `starts_with` | String prefix | `path: { starts_with: "/opt/app" }` |
| `contains` | Substring match | `path: { contains: "passwd" }` |

## Actions

| Action | Audit Mode | Enforce Mode |
|--------|-----------|--------------|
| `allow` | Allow + no log | Allow + no log |
| `deny` | Allow + log | Block + log |
| `log` | Allow + log | Allow + log |

## Variables

Variables let you reuse lists across rules. Reference them with `$variable_name`:

```yaml
variables:
  network_tools:
    - "/usr/bin/nc"
    - "/usr/bin/ncat"
    - "/usr/bin/curl"

rules:
  - name: block-net-tools
    event: process
    conditions:
      all:
        - path: { any_of: $network_tools }
    action: deny
```

## Tips

- Start with `default_action: allow` and explicit deny rules
- Use audit mode to validate before enforcing
- Keep rule names unique and descriptive (they appear in logs/metrics)
- Use variables for lists you reference in multiple rules
- Order rules from most specific to most general (first match wins)
- The `reason` field appears in deny logs — make it actionable

## LSM-BPF Kernel Enforcement

With `--lsm-enforce`, deny rules can be enforced synchronously in the kernel via LSM-BPF hooks — but on `main` only for **exec** (exact path) and **connect** (remote address and port), and only **after** the WASM policy has seen that exact operation once:

- **Denied exec operations return EPERM** on repeat attempts — the process never starts
- **Denied connections fail at connect()** on repeat attempts — no network handshake occurs
- **File, bind, listen, ptrace and mount denies are never blocked in the kernel** — they are detected in userspace and the process is killed with `SIGKILL` after the fact

### How It Works

1. The first time an event matches a deny rule, the kernel map has no entry: the operation is allowed, the event reaches WASM, and the decision is compiled into a BPF hash map (exec and connect only)
2. On subsequent identical events, the kernel LSM hook looks up the hash map and returns `-EPERM` without any userspace round-trip
3. The hash key uses FNV-1a over the filename or endpoint, scoped by cgroup ID and event type

### Policy Design for LSM

- **Glob patterns** (`/tmp/**`) are matched in userspace WASM on the first hit, then the specific filename that was observed is hashed into the BPF map — not the pattern itself
- **`any_of` lists** are also matched in userspace first; a map entry is written only for the specific value that was observed (other elements get entries once they are seen and denied)
- **Network rules** hash the observed destination IP+port, so `remote_port: { any_of: [22, 4444] }` populates map entries per observed connection
- **Cgroup scoping** — entries are written with the cgroup of the event that triggered them; there is no way to request a global (cgroup 0) entry from YAML
- **Temporal rules** are never compiled into the BPF map (no kernel key holds time), and decisions for their event type are not cached; every such event is evaluated in WASM

### Audit vs Enforce Mode

| Flag | Behavior |
|------|----------|
| `--lsm-enforce=false` (default) | LSM programs load but never deny — all events are observed and logged |
| `--lsm-enforce=true` | LSM programs actively block denied operations in kernel |

Start with `--audit` to validate your policy won't disrupt workloads, then enable enforcement. Note that leaving out `--lsm-enforce` alone is **not** observe-only: denied processes are still killed with `SIGKILL` from userspace.

### Requirements

- Linux kernel 5.7+ (5.8+ recommended) with `CONFIG_BPF_LSM=y` — see [BPF Compatibility](BPF_COMPATIBILITY.md)
- `/sys/kernel/security/lsm` must contain "bpf"
- `CAP_SYS_ADMIN` + `CAP_BPF` (or root)
- If requirements are not met, warmor falls back to tracepoint-only mode automatically (or refuses to start with `--require-lsm`)

---

## Compilation

YAML policies are compiled to WASM at daemon startup. You can also pre-compile them:

```bash
# Pre-compile (requires Rust + wasm32-unknown-unknown target)
warmor-compile -o policy.wasm policy.yaml

# Validate without compiling
warmor-compile --validate policy.yaml

# Emit Rust source for inspection
warmor-compile --rust-only policy.yaml > policy.rs
```

The daemon accepts both `.yaml` and `.wasm` files via `--policy`. A `.yaml` file is always compiled from its own content (requires the Rust toolchain); the result is cached under the WASM cache directory keyed by the SHA-256 of the YAML and the compiler version, so an unchanged YAML is not rebuilt and an edited one always is. Nothing is written next to the YAML, so it may live on a read-only volume such as a ConfigMap. A `.wasm` file next to the YAML is never substituted for it — to run a precompiled policy, pass the `.wasm` to `--policy` directly.

Passing a precompiled `.wasm` is useful when:
- The Rust toolchain isn't available on the target host
- You want reproducible builds in CI
- You want faster daemon startup (no compile step)

### WASM Serialization Format

The compiled WASM module receives events as flat JSON with a `"type"` discriminator:

```json
{"type": "PROCESS", "pid": 1234, "uid": 0, "gid": 0, "comm": "sh", "filename": "/tmp/exploit"}
{"type": "FILE", "pid": 1234, "uid": 1000, "gid": 1000, "comm": "cat", "operation": "read", "path": "/etc/shadow", "flags": 0}
{"type": "NETWORK", "pid": 1234, "uid": 1000, "gid": 1000, "comm": "nc", "operation": "connect", "protocol": "tcp", "remote_addr": "10.0.0.1", "remote_port": 4444, "local_port": 0}
```

---

## Validation

Validate a policy locally before deploying:

```bash
warmor-compile --validate path/to/policy.yaml
```

`warmor-daemon --validate-policy <path>` loads the policy the way the daemon would (and checks its signature with `--verify-key`) without root or BPF, and exits 0 or 1. For a `.yaml` file it checks the schema and, if a precompiled `.wasm` with the same base name exists next to it, loads that in the WASM runtime — it does not compile the YAML, because that needs `cargo`. For a `.wasm` file it compiles and instantiates the module in the WASM runtime. Add `--verify-key signing.pub` to also check the policy's detached signature (see [policy-bundle.md](policy-bundle.md#detached-signatures-daemon-and-policy-server)).

> **Note:** the compiler silently ignores rule keys it does not know (a misspelt `temporal:` key included; the `temporal:` block itself is checked strictly). Run `warmor-compile --rust-only path/to/policy.yaml` to see exactly which conditions were compiled.

---

## Example Policies

The `policies/yaml-example/` directory contains categorized example policies organized by threat domain:

```
policies/yaml-example/
├── policy.yaml              # Generic template
├── cve/                     # CVE-specific exploit mitigations (22 policies)
│   ├── cve-2021-4034.yaml   # PwnKit (pkexec privilege escalation)
│   ├── cve-2021-44228.yaml  # Log4Shell
│   ├── cve-2024-3094.yaml   # XZ backdoor
│   └── ...
├── windows/                 # Windows threat prevention (4 policies)
│   ├── windows-credential-theft-prevention.yaml
│   ├── windows-lolbin-detection.yaml
│   ├── windows-lateral-movement.yaml
│   └── windows-ransomware-prevention.yaml
├── linux/                   # Linux-specific (3 policies)
│   ├── linux-lpe-prevention.yaml
│   ├── linux-ebpf-exploitation.yaml
│   └── ...
├── network/                 # Network egress/filtering (2 policies)
│   ├── egress-control.yaml
│   └── advanced-network-filtering.yaml
├── workload/                # Workload-specific (7 policies)
│   ├── kubernetes-hardening.yaml
│   ├── ci-cd-pipeline.yaml
│   ├── database-protection.yaml
│   └── ...
└── threat-detection/        # General threat detection (14 policies)
    ├── crypto-miner-detection.yaml
    ├── reverse-shell-detection.yaml
    ├── supply-chain-attack.yaml
    └── ...
```

### Windows-Specific Policies

The `windows/` category contains policies targeting Windows-specific attack vectors:

| Policy | Threats Covered |
|--------|----------------|
| `windows-credential-theft-prevention.yaml` | LSASS dumping, SAM hive access, DPAPI abuse, Mimikatz patterns |
| `windows-lolbin-detection.yaml` | Living-off-the-land binaries (certutil, mshta, regsvr32, rundll32) |
| `windows-lateral-movement.yaml` | PsExec, WMI remote execution, WinRM abuse, RDP tunneling |
| `windows-ransomware-prevention.yaml` | VSS deletion, backup destruction, mass file encryption patterns |

These policies use the same YAML format as Linux policies but target Windows-specific paths, processes, and behaviors. They work with both backends (eBPF-for-Windows and ETW). On Windows, file opens are reported as `open` (there is no `read` event), and `comm` is the lowercased image name.
