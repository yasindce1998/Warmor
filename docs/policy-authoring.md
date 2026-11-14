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

\* YAML `args` is the captured argv joined with single spaces, including argv[0].
It is not shell parsing; `eq`/`any_of` compare the complete joined string, while
`contains` searches for a substring. Missing argv is an empty string. The Linux
exec tracepoint captures at most 16 arguments of 63 bytes each; LSM exec events
do not carry argv yet. Rules cannot inspect arguments the sensor did not capture.
Callback inputs longer than 16 KiB or containing invalid UTF-8 are treated as
unknown, not silently truncated again. Rule order and action still apply:
nonblocking allow/log/audit rules require a definite match, while enforcing deny
rules conservatively match when their conditions could hold. An uncertain audit
or log rule is skipped, so it cannot suppress a later enforcing denial or default
deny. An earlier definite match retains first-match precedence. Known unrelated
conditions can still rule a match out.

Policies using YAML `args` or network `operation` declare **ABI 5**, which adds
argv host callbacks and string-length queries; older agents reject them. Upgrade
agents before distributing those newly compiled policies. Other generated
policies retain ABI 3 compatibility.

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

References must resolve, including references inside lists and other variables;
cycles are errors. Use `$$name` to match the literal string `$name`.
Operands must be scalar or flat lists. Expansion is bounded to depth 32,
4096 visited values and 1 MiB of visited string data per operand; larger
expansions are rejected before compiling.

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

With `--lsm-enforce`, deny rules can be enforced synchronously via LSM-BPF for **exec** (literal path) and **connect** (remote address and port). Dynamic entries protect repeats **after** WASM has seen the complete operation once. Opt-in `--default-deny` additionally supports eligible static allowlists without waiting for a first observation; see [kernel default-deny](design/kernel-default-deny.md).

- **Denied exec operations return EPERM** on repeat attempts — the process never starts
- **Denied connections fail at connect()** on repeat attempts — no network handshake occurs
- **File, bind, listen, ptrace and mount denies are never blocked in the kernel** — they are detected in userspace and the process is killed with `SIGKILL` after the fact

### How It Works

1. The first time an event matches a deny rule, the kernel map has no entry: the operation is allowed, the event reaches WASM, and the decision is compiled into a BPF hash map (exec and connect only)
2. On subsequent identical events, the kernel LSM hook looks up the hash map and returns `-EPERM` without any userspace round-trip
3. The map compares full literal filename or structured family/address/port keys, scoped by cgroup ID and hook type; 32-bit hash collisions do not share verdicts

### Policy Design for LSM

- **Glob patterns** (`/tmp/**`) are matched in userspace WASM on the first hit, then the complete specific filename is keyed in the BPF map — not the pattern itself
- **`any_of` lists** are also matched in userspace first; a map entry is written only for the specific value that was observed (other elements get entries once they are seen and denied)
- **Network rules** key the complete observed destination IP+port, so `remote_port: { any_of: [22, 4444] }` populates map entries per observed connection
- **Cgroup scoping** — dynamic entries use the observed cgroup; unknown scope is refused. With opt-in `--default-deny`, eligible compiled allowlists are preloaded globally, subject to the configured cgroup filter
- **Complete identity** — policy-derived exec fast paths cap at 127 UTF-8 bytes (the shared sensor/WASM limit), with no embedded NUL. Long inputs do not persist. Literal path matching does not resolve symlinks, mount namespaces or file content. Canonical IP strings are required for static endpoint rules. See [exact identity limitations](design/kernel-default-deny.md#exact-identity-contract-and-limitations)
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

`warmor-daemon --validate-policy <path>` loads the policy the way the daemon would (and checks its signature with `--verify-key`) without root or BPF, and exits 0 or 1. For a `.yaml` file it checks the schema and, if a precompiled `.wasm` with the same base name exists next to it, loads that in the WASM runtime — it does not compile the YAML, because that needs `cargo`. For a `.wasm` file it compiles and instantiates the module in the WASM runtime. Add `--verify-key signing.pub` to also check the policy's detached signature (see [Policy toolchain](policy-toolchain.md#detached-signatures-daemon-and-policy-server)).

Validation is strict: unknown keys (including misspelled `default_action` or
`temporal`), extra YAML documents, duplicate rule names, unresolved variables,
invalid field/operator/value combinations, empty membership lists, and numeric
overflow are rejected. Numeric fields require nonnegative integers (`pid`,
`uid`, `gid`, `flags`: 32-bit; ports: 16-bit); string operators require string
operands. Existing policies relying on ignored keys or scalar `any_of` values
must be corrected before they can load. Run `--rust-only` to inspect generated
conditions, not as a substitute for behavioral tests.

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
