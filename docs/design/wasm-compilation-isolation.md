# WASM compilation isolation: limitation and release gate

Status: **not implemented in the default enforcer**. An opt-in separate-process
backend now exists; see [its contract and limitations](supervised-policy-host.md).
It is not wired into the concrete enforcer evaluator or release packaging and
does not implement the stronger cgroup/native-compromise boundary below.
Admission limits on the existing path remain defense in depth, not a killable
compilation worker. Do not claim default hard policy-load CPU/RSS or wall-time
bounds, or admit untrusted binary publishers on that premise.

## Why the context is insufficient

Pinned wazero 1.11.0 `runtime.CompileModule` calls `DecodeModule` and
`Module.Validate` without a context, before native compilation/cache lookup.
Its default single-worker wazevo loop does not check cancellation between
functions either. A context is not a way to forcibly interrupt these stages.
`WithCloseOnContextDone` interrupts guest execution, not arbitrary host compiler
code. Switching to the interpreter still decodes and validates the binary.

Warmor passes the initialization context through, rejects an already-canceled
load before wazero, and discards compilation results if the budget has elapsed
when compilation returns. It calls synchronously: a timer race with a goroutine
would return sooner but leave CPU/memory-consuming work alive in the daemon.
This limitation also applies to initial startup and policy replacement, not
only to hot reload. YAML-to-Rust compilation is a separate external-toolchain
boundary; bounding Cargo does not bound subsequent WASM loading.

## Present mitigations and compatibility

`internal/wasm/preflight.go` is a non-recursive, zero-copy framing scan before
**every** binary load, including signatures and compilation-cache hits:

| Input | Admission limit |
|---|---:|
| Module bytes | 64 MiB (existing limit) |
| Sections / name subsections | 256 each |
| Locally defined functions | 8,192 |
| Encoded function body | 64 KiB |
| Total encoded code-section contents | 8 MiB |
| Individual general/name/segment vector | 16,384 entries |
| Total counted vector entries | 65,536 |
| Function parameters / results | 256 each |
| Expanded locals | 4,096 per function; 262,144 per module |
| Sum of initial table elements | 65,536 |

Element initializer vectors are individually capped at 65,536 and share the
aggregate vector budget. Counts are checked before allocating expanded locals
or asking wazero to allocate vectors. Section/body/name lengths must be framed
within their own payloads; duplicate standard sections are rejected. DWARF
decoding is disabled. Instruction bytes remain opaque to preflight; semantic
validation remains wazero's responsibility. Unknown sections, constant forms,
and shared/64-bit limits are rejected rather than guessed.

These limits deliberately reject previously accepted unusually large/complex
modules. Normal YAML-generated modules and the checked-in JSON fixture are
tested. They are not a complete upper bound on compiler RSS, stack usage,
algorithmic complexity, native code size, table growth during execution, or
wall time. An adversarial function below the size cap can still be expensive.
There is no configuration switch that makes the current path isolated.

## Required architecture

A compile-only helper that warms a native-code cache is **not sufficient**:
the daemon still feeds the original binary to wazero to decode/validate it.
Native cache files are not portable trusted serialized `CompiledModule`s;
cache eviction/misses and version/config changes can trigger compilation again.

The defensible gate is to keep **all raw WASM and wazero work in a disposable
policy-host process**, including decoding, validation, compilation, start,
declarations and evaluation. The daemon never calls `CompileModule` on remote
policy bytes. This is an architectural change to pool/evaluator ownership,
host callback data flow, activation lifetime and release packaging, not a
transparent library helper.

Implementation contract:

1. Ship a separately built/versioned policy-host executable. The daemon supplies
   an explicit administrator-configured absolute path; no executable discovery
   from policy input/PATH and no hidden self-exec behavior in the WASM library.
2. Start one candidate host per activation. Before accepting any policy bytes,
   establish OS-enforced memory/CPU/task/file limits. On Linux, use a delegated
   cgroup with `memory.max`, `memory.swap.max`, `pids.max` and CPU accounting,
   process-group supervision and a wall timer; apply appropriate rlimits,
   no-new-privileges and filesystem/network restrictions. A Go memory limit is
   only advisory, and `RLIMIT_AS` alone is not a safe portable Go RSS limit.
   Windows needs a kill-on-close Job Object with memory/process limits; macOS
   needs a separately tested equivalent or must reject isolated-mode startup.
   If limits cannot be established, **fail closed**, never silently fall back.
3. Use inherited anonymous pipes or a local private socket, not a listener on
   a network address. A versioned length-prefixed protocol caps **every**
   request/response before allocation. One bounded module upload (64 MiB max),
   no arbitrary file paths/environment/flags, no inherited credentials or open
   daemon sockets. Bind readiness to the module SHA-256 and protocol version.
4. Workers use private bounded ephemeral caches (or no cache initially).
   Do not expose a shared writable native-code cache to untrusted workers;
   the privileged daemon must not deserialize worker-controlled native code.
   Bound stderr/log bytes and disk writes as well as IPC buffers.
5. Initialization has a supervisor-enforced wall deadline covering upload,
   parsing, compilation, declarations and ready response. On deadline, protocol
   violation, memory/CPU limit, crash, or cancellation, kill the **whole process
   group/cgroup and reap it**. No surviving subprocesses or abandoned goroutines.
   Bound concurrent candidates and queue length; retain last-known-good state.
6. Ready metadata/declarations are bounded typed data, never guest pointers or
   native artifacts. Serialize event/context inputs once; satisfy callbacks
   within the host from that snapshot. Preserve the current ABI versions,
   truncation/unknown semantics, audit results and reason-length validation.
   Evaluations need per-request deadlines; a host that misses one is killed and
   replaced. Old hosts stay alive only until checked-out evaluations drain.
7. The daemon switches routing only after successful ready/verification and
   preserves last-known-good host on failed activation. Bounded retry/backoff
   must prevent crash/restart amplification. Metrics distinguish compile
   timeout, resource kill, protocol error, evaluation timeout and replacement.

## Acceptance tests before calling isolation complete

- Build and launch the **real packaged host**, not a sleeping mock helper.
- Feed actual pathological decode/validation/compiler workloads, including
  count bombs and large single-function control-flow/SSA workloads. Verify an
  external supervisor kills/reaps the host within budget; daemon RSS, threads,
  event handling and last-known-good evaluations remain healthy over retries.
- Kill at every IPC phase; test oversized/truncated lengths, output flooding,
  blocked pipes, canceled uploads, corrupt cache, child exit and missing limit
  delegation. No configuration may fall back to in-process raw-module loading.
- Exercise readiness hashes, reload/drain, worker concurrency caps, callback
  parity, audit behavior, cross-platform packaging and helper-path permissions.
- Check memory/CPU/file limits with OS counters, not just Go allocation stats.

Current tests deliberately pin the limitation by compiling a substantive valid
module (128 functions / about 897 KiB / 131,072 integer adds) with an
already-canceled raw wazero context. Separate admission tests use a compiler spy to prove dangerous count
and size fixtures never enter wazero. These are mitigation tests, **not** the
process-isolation acceptance gate above.
