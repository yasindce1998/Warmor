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
    action: allow | deny | audit
    reason: "Human-readable explanation"

default_action: allow | deny | audit
```

## Event Types

| Event | Description | Available Fields |
|-------|-------------|-----------------|
| `process` | Process execution (execve) | `path`, `uid`, `gid`, `comm` |
| `file` | File system access | `path`, `uid`, `operation` |
| `network` | Network connections | `uid`, `remote_port`, `remote_ip`, `protocol` |

## Condition Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `glob` | Glob pattern match | `path: { glob: "/tmp/**" }` |
| `any_of` | Value in list | `path: { any_of: $my_list }` |
| `not` | Not equal to | `uid: { not: 0 }` |
| `equals` | Exact match | `comm: { equals: "python3" }` |
| `prefix` | String prefix | `path: { prefix: "/opt/app" }` |

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

## Actions

| Action | Audit Mode | Enforce Mode |
|--------|-----------|--------------|
| `allow` | Allow + no log | Allow + no log |
| `deny` | Allow + log | Block + log |
| `audit` | Allow + log | Allow + log |

## Tips

- Start with `default_action: allow` and explicit deny rules
- Use audit mode to validate before enforcing
- Keep rule names unique and descriptive (they appear in logs/metrics)
- Use variables for lists you reference in multiple rules
- Order rules from most specific to most general (first match wins)
- The `reason` field appears in deny logs — make it actionable

## LSM-BPF Kernel Enforcement

When running with `--lsm-enforce`, deny rules are enforced synchronously at the kernel level via LSM-BPF hooks. This means:

- **Denied exec operations return EPERM** — the process never starts
- **Denied file opens fail immediately** — the file is never accessed
- **Denied connections fail at connect()** — no network handshake occurs

### How It Works

1. The first time an event matches a deny rule, WASM evaluates it and the decision is compiled into a BPF hash map
2. On subsequent identical events, the kernel LSM hook looks up the hash map and returns `-EPERM` without any userspace round-trip
3. The hash key uses FNV-1a over the filename/pattern, scoped by cgroup ID and event type

### Policy Design for LSM

- **Glob patterns** (`/tmp/**`) are matched in userspace WASM on the first hit, then the specific filename that matched is hashed into the BPF map
- **`any_of` lists** each element is individually hashed into the map after first evaluation
- **Network rules** hash destination IP+port, so `remote_port: { any_of: [22, 4444] }` will populate map entries per observed connection
- **Cgroup scoping** — rules apply per-cgroup by default; set cgroup_id=0 in the map for global rules

### Audit vs Enforce Mode

| Flag | Behavior |
|------|----------|
| `--lsm-enforce=false` (default) | LSM programs load but never deny — all events are observed and logged |
| `--lsm-enforce=true` | LSM programs actively block denied operations in kernel |

Start with audit mode to validate your policy won't disrupt workloads, then enable enforcement.

### Requirements

- Linux kernel 5.7+ with `CONFIG_BPF_LSM=y`
- `/sys/kernel/security/lsm` must contain "bpf"
- `CAP_SYS_ADMIN` + `CAP_BPF` (or root)
- If requirements are not met, warmor falls back to tracepoint-only mode automatically

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

The daemon accepts both `.yaml` and `.wasm` files via `--policy`. When given a `.yaml` file, it checks for a `.wasm` file with the same base name and loads it directly if found — skipping compilation entirely.

Pre-compilation is useful when:
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

`warmor-daemon --validate-policy <path>` loads the policy in the WASM runtime (and checks its signature with `--verify-key`) without root or BPF, and exits 0 or 1. For YAML it only validates the schema, because compiling needs `cargo`.

> **Note:** the compiler silently ignores keys it does not know, such as `temporal:`. Run `warmor-compile --rust-only path/to/policy.yaml` to see exactly which conditions were compiled.

This needs no root or BPF and exits 0 if the policy is valid, 1 if not. For a
`.yaml` file it checks the schema, and loads a precompiled `.wasm` with the
same base name if there is one. It does not compile the YAML. For a `.wasm`
file it compiles and instantiates the module in the WASM runtime. Add
`--verify-key signing.pub` to also check the policy's detached signature
(see [policy-bundle.md](policy-bundle.md#detached-signatures-daemon-and-policy-server)).

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
