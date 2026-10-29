# Security Posture: Fail-Open vs Fail-Closed

For a security control, *what happens when something fails* matters as much as
what happens when everything works. This document states Warmor's behavior at
each layer explicitly, so operators can choose a posture deliberately.

## The two enforcement layers

Warmor enforces in two places, and they have **different** failure modes by
design.

### 1. Kernel fast-path (BPF-LSM)

Each LSM hook consults the kernel `policy_map`:

- **Explicit `DENY` rule present + enforce mode on** → blocked in-kernel
  (`-EPERM`).
- **No matching rule (miss)** → **allowed**, and the event is emitted to
  userspace for evaluation. This is *allow-on-miss*.
- **Failure to read the subject** (e.g. a `bpf_probe_read` returns nothing) →
  **allowed**. The kernel path deliberately fails *open* on transient read
  errors so a single unreadable argument cannot wedge every `exec`/`open` on the
  host.

> **Async gap (known limitation).** Because the kernel cannot call into the WASM
> policy synchronously, the *first* occurrence of an action that has no rule yet
> is allowed and reported; once userspace evaluates it and writes a `DENY` rule,
> *subsequent* identical actions are blocked. Warmor is therefore not a
> synchronous gate for never-before-seen actions. Mitigations: pre-seed deny
> rules for known-bad patterns, and scope enforcement to specific cgroups so the
> rule set converges quickly.
>
> **Coverage on `main`:** userspace writes rules only for **exec** (exact path)
> and **connect** (endpoint) decisions. `file_open`, `socket_bind`,
> `socket_listen`, `ptrace_access_check` and `sb_mount` never get rules, so
> they never block in the kernel. Pre-seeding deny rules from the compiled
> policy is not implemented yet. See [STATUS.md](STATUS.md).

### 2. Userspace policy (WASM)

When an event reaches the WASM evaluator and evaluation **errors**, Warmor fails
**closed** — the decision becomes `DENY` (`internal/enforcer/enforcer.go`). A
broken or misbehaving policy denies rather than silently allows.

A userspace `DENY` (without `--audit`) is enforced by sending `SIGKILL` to the
process, after the event was observed. This applies in **every** mode below
except `--audit`, including tracepoint-only mode.

WASM evaluation is resource-bounded: each instance is capped at 16 MiB of
linear memory, and each evaluation has a deadline (`--eval-timeout`, default
50 ms). A policy that exceeds either **fails closed** — the decision becomes
`DENY` — rather than hanging the event loop.

## Enforcement modes

| Mode | How to select | Behavior |
|---|---|---|
| **Kernel audit-only** | default (no `--lsm-enforce`, or LSM unavailable), or `--no-lsm` | Nothing is blocked in-kernel. The daemon still `SIGKILL`s processes whose events the policy denies. |
| **Audit** | `--audit` | Would-be denials are logged (`audit` events). Nothing is killed or blocked. This is the only true dry-run mode. |
| **Enforce** | `--lsm-enforce` | Exec/connect `DENY` rules already in the map are blocked in-kernel. All other denies are `SIGKILL`ed. |

The daemon prints a one-line **Security posture** summary at startup so the
active mode is unambiguous in logs.

## Startup fail-safety: `--require-lsm`

By default, if BPF-LSM cannot be established (unsupported kernel, missing BTF,
verifier rejection), Warmor logs a warning and **degrades to observe-only** —
it keeps running so you still get telemetry. This is a *fail-open startup*: good
for rollout and for mixed fleets, but it means "the daemon is up" does not by
itself guarantee kernel enforcement.

For environments that must not run without kernel enforcement, start with:

```sh
warmor-daemon --lsm-enforce --require-lsm ...
```

With `--require-lsm`, the daemon **refuses to start** (non-zero exit) if it
cannot load and arm the LSM programs — a *fail-closed startup*. This is the
recommended posture for production enforcement nodes, typically paired with
`--lsm-enforce`.

| Flag | Default | Effect |
|---|---|---|
| `--lsm-enforce` | `false` | Arm kernel blocking for `DENY` rules. Without it, LSM runs audit-only. |
| `--require-lsm` | `false` | Fail to start unless LSM enforcement loads. Without it, degrade to observe-only. |
| `--no-lsm` | `false` | Skip LSM-BPF loading entirely. Tracepoint-only observe mode — useful for environments where the verifier hangs or LSM is unsupported. |
| `--audit` | `false` | Log would-be denials instead of enforcing them (userspace actions). |

## Policy integrity: `--verify-key`

By default the daemon loads whatever module is at `--policy`, or whatever
the policy server sends. Anyone who can write that file, or impersonate or
compromise the server, controls enforcement. This is a *fail-open* trust
model.

With `--verify-key <ed25519 public key PEM>`, every policy needs a detached
signature (`<policy>.sig`) that verifies, and loading **fails closed**:

| Event | Signature missing / invalid |
|---|---|
| Startup | Daemon refuses to start (checked before BPF loads). |
| SIGHUP / file-watcher reload | Reload refused; current policy stays active. |
| Policy server download | Discarded before it is written to disk; old policy and file kept; error logged; `warmor_policy_signature_failures_total{source="server"}` incremented. |

The daemon verifies the exact bytes it loads: it reads the file once into
memory, checks the signature, and compiles from that buffer. YAML policies are
refused under `--verify-key` because they are compiled on the node. The
private key stays offline: `warmor-server` stores and serves the signatures
of pre-signed uploads and never signs anything itself. `warmor-server
--verify-key` additionally rejects unsigned uploads (defense in depth; agents
still verify on their own).

The signature binds content, not version. A server or anyone else who can
write the policy path can still roll a node back to an *older* module that was
validly signed with the same key. Rotate keys, or use separate keys per policy
line, when an old policy must never return.

The flow and commands are in
[Policy toolchain](policy-toolchain.md#detached-signatures-daemon-and-policy-server).

## Recommended postures

- **Production enforcement node:** `--lsm-enforce --require-lsm --verify-key
  signing.pub`. Fail-closed startup; deny rules blocked in-kernel; no silent
  downgrade; only signed policies load.
- **Rollout / canary:** `--lsm-enforce` (no `--require-lsm`). Enforces where the
  kernel supports it, degrades gracefully elsewhere while you assess coverage.
- **Pure monitoring:** `--audit`. Observe and evaluate, kill and block nothing.
  The defaults are **not** pure monitoring: denied processes are still killed.

See [BPF_COMPATIBILITY.md](BPF_COMPATIBILITY.md) for the kernel requirements
that determine whether LSM enforcement can load at all.
