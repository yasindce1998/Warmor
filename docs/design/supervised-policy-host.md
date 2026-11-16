# Supervised policy host: opt-in backend contract

Status: **implemented and tested as an optional Linux API, not the enforcer's
default backend or a completed isolation release gate**. The experimental
adapter in `supervised-evaluator-integration.md` adds explicit daemon flags and
backend lifecycle ownership; the in-process backend remains the default.
Linux archive/image packaging now includes the opt-in helper; see
`supervised-host-deployment.md`. Actual VM results remain required.

## Ownership and trust boundary

`internal/policyhost` exposes `Stage`, `StageFile`, `New`, `Supervisor.Start`,
`Host.Evaluate`, `Host.Digest` and idempotent `Host.Close`. Its dependency tree
contains neither wazero nor `internal/wasm`. Staging bounds and copies the raw
bytes and verifies an Ed25519 signature before upload. `StageFile` opens regular
files without following symlinks (including directory components) and refuses
special files without blocking on a FIFO. No YAML/Cargo compilation, preflight,
WASM decoding, native-code cache, or guest export runs in the parent backend.
Signatures authenticate content only, **not** assignment, scope or rollback.
The caller must not concurrently mutate supplied inputs while staging/snapshotting.

The parent retains its verified staged snapshot; the upload creates a separate
child-owned buffer. The runtime may retain references to that buffer after load.
Neither dropping a local reference nor garbage collection promises immediate
reclamation or secure erasure; resource enforcement does not depend on either.

Build the dedicated executable separately:

```sh
go build -o /trusted/install/warmor-policy-host ./cmd/warmor-policy-host
```

An administrator supplies a clean absolute `Config.Executable` path and a
required lowercase `ExecutableSHA256`. There is no PATH discovery, daemon
self-exec, `init` interception, test-binary execution mode, policy-selected path/flags or
automatic fallback. On Linux, descriptor-relative `O_NOFOLLOW` opens bind
validation to the inode executed via `/proc/self/fd/3`. Directories and executable
must be owned by root or the supervisor's effective UID; group/other writable
components are refused, except root-owned sticky directories. The file must be
regular, executable, not setuid/setgid, non-group/other-writable and at most
128 MiB. Administrators must trust the effective UID and must not modify installed
executable contents in place; install updates by atomic rename. `/proc` is required.
The executable digest is a trust pin, not remote build provenance verification.

The parent explicitly provides two anonymous IPC pipes, `/dev/null` stderr and
its pinned executable fd. **`exec.Cmd.ExtraFiles` is not an FD allowlist:** any
unrelated non-CLOEXEC parent descriptors can also reach the initial trusted
bootstrap. Before reading configuration or WASM, that bootstrap locks its OS
thread and uses Linux `close_range(3, UINT_MAX, UNSHARE | CLOEXEC)` to create a
private descriptor table and mark all descriptors except 0/1/2 close-on-exec.
It immediately execs the same validated running inode via `/proc/self/exe` with
the fixed internal `--serve` argument and a minimal environment. This is an
explicit two-stage launch of the separate executable, never daemon self-exec.
The second exec closes inherited descriptors (including fd 3 and descriptors
above the later `RLIMIT_NOFILE`) and creates a fresh Go runtime. No live runtime
poll descriptors are closed under an existing Go runtime; unsharing prevents
other threads from introducing descriptors between marking and exec.

Sanitization/exec failure exits before any IPC is accepted; there is no fallback
requiring callers to set CLOEXEC correctly. Linux 5.11+ `CLOSE_RANGE_CLOEXEC` and
`CLOSE_RANGE_UNSHARE` support is required. No forked grandchild is introduced:
both exec stages use the same supervised PID, pipes, deadline and reaping path.
The serving worker starts with only the explicit IPC/stderr allowlist and its
own newly created runtime descriptors. Stderr is not a public pipe, logging
goroutine or daemon log. It receives no daemon environment, tokens, working
directory or writable cache. The sole explicit environment entry is
`GOMAXPROCS=1`. Host callbacks execute **inside the child**
against its event snapshot. WASI receives no mounted files, argv, environment,
network listeners or external command execution capabilities.

## Wire protocol v2

The [declaration metadata contract](policyhost-declarations.md) extends this
checkpoint with a required versioned readiness metadata envelope and an 8 MiB
metadata-frame cap. Protocol 1 workers are incompatible and rejected. Metadata
transport does not by itself authorize optimizations.

Each frame has a four-byte big-endian nonzero length. Lengths are checked before
allocation. Structured frames use the exact canonical JSON encoding of the Go
protocol structs, with all fields present; unknown/duplicate/missing/case-folded
keys, trailing documents and null scalars are rejected. A missing action cannot
become a zero-valued allow. Raw module bytes are a separate frame, not base64.

| Frame | Maximum |
| --- | ---: |
| Configuration / handshake | 4 KiB |
| Raw signed module snapshot | 64 MiB |
| Event | 256 KiB |
| Result | 8 KiB |
| Decoded reason | 1 KiB (current guest ABI returns at most 512 bytes) |

Handshake: `configure(limits,version)` → `limited(limits,version)` → raw module
→ `loading(SHA-256,limits,version)` → `ready(SHA-256,limits,version)`.
The parent checks the digest and exact resource configuration at both milestones.
The child acknowledges `limited` **only after every required OS limit succeeds**,
before reading module bytes. A parent initialization deadline covers all of these
phases, including compilation that ignores Go contexts. After `loading`, a second
required `LoadTimeout` nests within the remaining total budget, so slow uploads
do not make the child-side compilation budget ambiguous.

Evaluation requests/results have monotonically increasing sequence numbers.
No arbitrary paths, guest pointers, native artifacts or arbitrary error strings
cross the boundary. Results carry only action, audit and reason; enforcement
outcomes, cache state, timestamp and latency remain parent-owned. Unknown actions,
audit on a non-deny, oversized reasons and malformed responses are failures,
never decisions. Error returns have a nil result: callers **must fail closed and
must not cache errors**. `Failure.Phase` distinguishes configure/upload/load/evaluate;
`errors.Is` preserves cancellation/deadline classification. A crash/resource kill
currently maps to generic host failure, not a detailed metrics taxonomy.

### Unknown-input law

Transport never truncates, normalizes, silently drops observable input, or replaces
invalid sensor UTF-8. Byte fields use base64 inside JSON so invalid argv reaches
the existing child callbacks unchanged; the current compiler's unknown-input law
still applies. Unknown event types, excessive argument counts and oversized event
snapshots produce errors, not a repaired allow. Nil/empty/missing context is
preserved. The explicit resolved event type is preserved even when other union
members are populated. All currently observable ABI/callback fields are included;
unobservable kernel identity/enforcement fields are deliberately excluded. As in
the existing evaluator, a missing wall timestamp is stamped on a copy; unknown
container start remains unknown. ABI 1–5 serialization, binary truncation rules,
audit translation, reason validation, frees, initialization and declaration reads
are delegated to the existing runtime **only inside the child**.

## Bounds and lifecycle

No resource setting may be zero or silently default to unbounded behavior:

| Configuration | Accepted range |
| --- | --- |
| Address space, `RLIMIT_AS` | 2–16 GiB |
| Cumulative process CPU, `RLIMIT_CPU` | 1–3600 whole seconds |
| Guest linear memory | 1–1024 pages of 64 KiB |
| Process lifetime request count | 1–1,000,000 |
| Initialization wall deadline | >0 to 1 minute |
| Child-load wall deadline | >0 to initialization deadline |
| Evaluation wall deadline | >0 to 5 seconds |
| Concurrent hosts per supervisor | 1–16 |

The worker also sets hard/soft core size and file size limits to zero, open-file
limit to 32 and process dumpability to zero. Failure to establish any required
limit exits without accepting WASM. Linear memory is additionally bounded by
wazero; address space covers host compilation allocations too. CPU budget is
**cumulative for the entire host lifetime**, including startup/compilation, not
per event. Exhausted hosts require a new explicit activation, not auto-retry.

Each supervisor has a bounded host count and no candidate queue. Each host has
one in-flight evaluation and no internal evaluation queue; saturation returns
`ErrBusy`. Hosts do not fork or launch subprocesses. Deadline/cancellation,
protocol error, evaluation failure or `Close` kills only the supervisor-owned
child, closes its private pipes and waits for `cmd.Wait` to reap it before returning.
The wait goroutine and cancellation callback are joined, not abandoned compiler
or I/O goroutines. The final permitted request returns its validated decision and
retires/reaps the host. Normal idle child exits are also reaped promptly.
`Pdeathsig=SIGKILL` provides additional Linux parent-death cleanup; it does not
replace explicit close/reap. Callers own successful hosts and **must close them**.

## Explicit limitations and integration gates

This first backend is a killable resource boundary for **untrusted WASM running
under a trusted wazero/Go host**, not a sandbox for a compromised native worker:

- `RLIMIT_AS` bounds virtual address space, **not a calibrated resident-memory
  quota**. Go reserves substantial virtual address space; low limits may cause
  allocation failure or fatal runtime exit, which is treated as host failure.
  There is no cgroup `memory.max`/swap quota, CPU bandwidth quota, per-host task
  quota, namespace/seccomp boundary, privilege/UID drop or process-tree cleanup.
  Workers cannot create subprocesses through the offered WASM imports, but a
  native runtime exploit could escape that assumption. Current rlimits do not
  satisfy the stronger cgroup/native-compromise threat model in
  `wasm-compilation-isolation.md`.
- This backend supports Linux 5.11+ with `/proc` and the required `close_range`
  flags only. Unsupported/blocked descriptor sanitization rejects startup.
  Windows and macOS reject startup;
  there is no Job Object or tested equivalent. Cross-compilation is not platform
  execution validation. Tests do not install host security hooks or alter parent
  process rlimits.
- Declarations now have an optional bounded metadata API; see its separate
  trust contract above. Caching/default-deny remain disabled by default for the
  supervised backend unless exact declaration digests are independently attested.
  The experimental adapter now consumes only effective trusted methods.
- The adapter drains old hosts with captured generation leases and never
  automatically respawns failed hosts. Whole-daemon supported-kernel VM evidence,
  workload scope and packaging remain required **before making it the default**.
- Linux archives and the daemon image include the helper without enabling it.
  The dedicated VM gate and installed-host trust/upgrade evidence remain required;
  no shipped isolation claim is made by packaging alone.

## Verification

`go test ./internal/policyhost/... ./cmd/warmor-policy-host` builds and launches
the actual dedicated command. Tests cover signed immutable staging, path/digest
trust, no runtime dependency in the parent, binary decisions/audit/unknown time,
guest memory cap, actual Linux rlimits, cumulative CPU kill, loop kill/reap,
non-CLOEXEC descriptors above the worker's NOFILE limit (pipe EOF must occur
while the worker is still alive),
cancellation, crash, bounded capacity/request count and malformed frames. A real
~7 MiB module with 384 functions and 393,216 conditional add/multiply blocks exercises loading
under a 100 ms child-load deadline (within a 5 second total initialization cap)
for repeated candidates, while an independent
known-good host continues returning decisions. `loading` confirms the bytes
arrived in the child; the non-interruptible compiler path is not run in the parent.
These are backend checks, **not the complete packaging/enforcer acceptance suite**.
