# Opt-in kernel policy generations

Status: **experimental opt-in daemon integration; OFF by default**.
`--experimental-atomic-generations --require-lsm` selects the combined enforcer
path for compiled WASM policies. This is not production readiness or a
cross-userspace/kernel/filesystem atomicity claim. See
[generation-activation.md](generation-activation.md) for its commit model,
pending recovery, tests, and remaining whole-daemon VM validation gate.
Without the option the legacy reload path retains its documented clear/rebuild
limitations. Workload selectors are not enabled by this option.

## One pointer, one policy snapshot

`LSMLoader.PolicyGenerations()` returns the loader's single generation manager.
Obtaining it does not change enforcement. `Prepare(id, GenerationSpec)` creates
a fresh unreachable inner `HASH`. `Activate(id)` publishes that **whole map**
with one `BPF_MAP_UPDATE_ELEM` to `active_generation[0]`, an `ARRAY_OF_MAPS`.
There are no separately switched rule/default-deny/ID pointers.

Each inner map contains:

* Exact static rules with the existing 288-byte `PolicyKey`. No security hash,
  basename, wildcard, path normalization, or truncated identity is introduced.
* Complete exec/connect default-deny domains. Scope-specific markers override
  global markers just as scoped exact rules precede global exact rules.
* An immutable nonzero 64-bit generation ID. Family 255 is reserved for markers;
  real string keys have family 0 and supported endpoint keys have family 2/10.
  Event type 255 distinguishes the ID marker from default-deny markers.

A hook snapshots the inner pointer once, before building its operation key.
Its ID, scoped/global exact lookups, and miss/default-deny result all use that
same inner map. A switch between the rule miss and default-deny lookup therefore
cannot combine an old allowlist with new markers or temporarily unmark a
domain. No generation-mode miss falls back to the legacy maps. A complete
candidate may intentionally omit a domain; that is a policy change, not a
reload gap. Preparing/aborting/failing a candidate cannot change active policy.

Generation rule support matches today's exact-key hooks (exec, connect, bind,
mount, ptrace). Only exec and INET connect implement complete default-deny
domains; unsupported domain types are rejected. File basenames, AF_UNIX,
integrity, and other observation-only events are not newly made matchable.
Enforce/audit toggle, cgroup filter, loss config, unix watch, and IMA digest
state are **outside** this transaction. Do not change them concurrently and
claim an atomic policy switch.

The pointer replacement uses longstanding map-in-map support, fixed inner-map
metadata, and no post-6.1 kfuncs or nested map-in-map. Kernel RCU protects a map
held by a non-sleepable policy hook. Linux 6.1's
[`bpf_map_update_value` / `maybe_wait_bpf_programs`](https://github.com/torvalds/linux/blob/v6.1/kernel/bpf/syscall.c)
also waits for the pre-switch non-sleepable programs before returning from the
outer-map update; the pointer replacement itself is an `xchg` in
[`bpf_fd_array_map_update_elem`](https://github.com/torvalds/linux/blob/v6.1/kernel/bpf/arraymap.c).
Do not extend the reader-grace argument to sleepable hooks without revalidation.
Compilation/ELF tests are not verifier or runtime proof. The VM tests must pass
on the supported kernels, including the existing built 6.1 LTS CI kernel.

## API lifecycle and failure contract

```text
legacy (ID 0) --Prepare(1)--> legacy + candidate
             --Activate(1)--> active 1 + retiring legacy
             --AcknowledgeDrain(0)--> active 1

active N --Prepare(N+1)--> active N + candidate
         --Activate(N+1)--> active N+1 + retiring N
         --AcknowledgeDrain(N)--> active N+1
```

* IDs increase strictly for one loader lifetime. A failed/aborted admitted ID
  is consumed; a busy request is not admitted. Zero, stale, wrapped and reused
  IDs are rejected. Do not construct another manager for the same outer map.
* `Prepare` validates all rule identities/actions/modes and rejects duplicate
  exact identities (even identical duplicates). The compiler/integrator must
  resolve first-match policy semantics **before** supplying the spec. The spec
  must include the complete intended static policy/domain set, not a delta.
* Creation/population errors leave the active pointer alone and attempt to close
  the candidate FD. Cleanup failure retains that candidate for `Abort(id)` retry
  and blocks further builds; a partially built/cleanup-attempted candidate
  cannot be activated. Errors are joined, not hidden.
* Failed pointer publication retains the old active map and complete candidate:
  retry `Activate` or `Abort`. Successful publication is the kernel commit
  point. There is no automatic switch-back-to-legacy or post-publication abort.
  A crash after publication needs activation-owner recovery, not an assumption
  that an unpersisted userspace stage means the kernel still uses the old map.
* `SyncEvent(id, event, action, audit)` only writes into the currently active
  generation, under the same mutex as publication. Late old-generation
  writeback returns `ErrStaleGeneration`; never retry it under the new ID.
  Unknown/zero cgroups and incomplete identities are rejected using the same
  exact event-key checks as legacy writeback. Eligibility still requires the
  caller's existing proof that the decision depends only on kernel key fields,
  including all workload identity/configuration lifetime constraints. This
  helper does not make a contextual decision safe to cache.
* Dynamic state is not copied into candidates. Inner maps are non-LRU so
  static denies/allows and default-deny markers cannot be evicted by dynamic
  traffic. A full map returns an error; it does not drop a marker or pretend the
  decision was installed. Caller policy proof must prevent inconsistent dynamic
  writes from overriding static identities in the **same** generation.
* `AcknowledgeDrain(oldID)` is a **caller assertion**, not a reader or kernel
  barrier. It releases the old FD without deleting any entry. The first switch
  also requires acknowledgement for legacy ID 0. Failure blocks a third buffer
  and can be retried. Legacy FDs remain loader-owned and unchanged.
* `Close` is teardown only. Stop readers/workers and detach programs first via
  the loader lifecycle. It releases FDs but never deletes the active pointer;
  closing a referenced inner FD alone must not reopen the legacy policy path.
  Maps are not pinned; restart/adoption of a running pinned policy is not an API
  capability. Shutdown and crash availability semantics are unchanged.

## Required activation-owner sequencing

There is **no cross-userspace/kernel atomic-switch claim**. The manager mutex
only serializes its own kernel writes. The activation owner must agree on and
test a shared ordering with evaluator, dispatch, writeback and durable state.
For the current non-sleepable policy hooks, an implementable sequence is:

1. Compile/validate the complete candidate userspace evaluator and static spec.
   Retain the old evaluator. Call `Prepare(newID, spec)` while old policy stays
   active. Do not call legacy `Clear`/`ClearDefaultDeny` as preparation.
2. Under the activation/dispatch lock, register the new evaluator by ID **before**
   publishing the kernel pointer. Pause new unversioned evaluator acquisitions
   and dynamic writeback/publication as needed. Define a lock order; never hold
   a worker-needed lock while waiting for its completion.
3. Call `Activate(newID)`. On failure, keep old userspace current and retry/abort
   the candidate. On success publish the userspace-current generation under that
   same lock, record the commit outcome, and release the lock. Kernel producers
   do not acquire this lock; queued new-ID events must already have an evaluator.
4. Route each versioned LSM event by **its captured ID**, not by the userspace
   current pointer. `LSMEvent.PolicyGeneration` is preserved through
    `internal/ebpf.Event` and `pkg/api.Event`. The experimental enforcer dispatches
    it using a live `GenerationContext` lease, not a current-pointer relabel.
    Capture a version
   for tracepoint/unversioned work under the same dispatch contract. Do not treat
   every ID-0 observation-only event as old-policy work forever.
5. After successful `Activate` returns (including the kernel's non-sleepable RCU
   wait), call `FlushLSMEvents`. Have the **single** reader continue normal
   generation-aware dispatch until `errors.Is(err, ringbuf.ErrFlushed)` from
   `ReadLSMEvent`. The error wrapping preserves the sentinel. This drains queued
   old-ID samples, including `NO_WAKEUP` records. A sleep, empty-looking buffer,
   wall timestamp, first new-ID event, or userspace-current publication alone is
   not a drain proof. Do not overlap flush requests. Continuous other traffic can
   delay the flush; on timeout retain the old generation, do not guess.
6. Wait for all old-ID dispatch/evaluation/recording/writeback references,
   including work acquired before the switch, to finish. Only then call
   `AcknowledgeDrain(oldID)` and release the old evaluator. This helper rejects
   stale writeback even if a caller errs, but cannot protect a prematurely
   destroyed userspace evaluator. Do not begin another candidate while old work
   remains; the manager enforces that memory/ownership gate.

Durable activation acknowledgements, uncertain-outcome recovery, lock ordering,
reader failure and dispatcher ownership belong to the activation integration,
not a second independent activation mechanism in this package. Before enabling,
add combined tests for failure/crash at each stage, in-flight old/new evaluations,
writer fencing, ring/worker drain, cancellation/shutdown, and acknowledgement
persist failures. Keep fail-closed/default-deny behavior under reload stress.

## Bounded resources

Each inner map has at most 65,536 entries **including** one ID marker and up to
64 domain markers: at most 65,471 rules with all 64 domains present. Reserved
marker keys cannot be written through static/dynamic rule APIs. All generations
use identical key/value/flags/capacity for Linux 6.1 map compatibility.

`BPF_F_NO_PREALLOC` avoids reserving every rule element for empty/small maps (and
for the transient inner template needed to create the outer map). At most two
generation FDs/maps are owned: active+candidate or active+retiring. Failed cleanup
counts toward that bound. There is no build queue or third candidate. Each full
map's key/value payload is `65536 * (288 + 16) = 19 MiB`; two total **38 MiB
payload**, plus hash buckets, allocator/RCU/per-CPU overhead, and existing legacy
maps/ring. This is not a claim of a 38 MiB RSS/memcg ceiling. The kernel can defer
freeing retired allocations; closing an FD is not immediate physical reclamation.
Bound admission/rate at integration and size deployment limits using measurements
on supported kernels. Memory-allocation failures abort preparation without a
policy switch.

Before any validation index allocation or BPF creation, oversized input is
rejected. The temporary userspace index is bounded to 65,536 exact keys/values,
not multiplied by an unbounded cgroup list; it is released after preparation.
Caller-owned policy/spec/evaluator memory is additional. The legacy 65,536-entry
LRU map remains allocated for compatibility until loader teardown, so migration
temporarily pays for it as well; this API does not silently change its capacity.

## Tests and current evidence

Offline unit/race tests cover build/publication/cleanup failure, failed retirement
and retry, two-buffer admission, stale IDs/writeback, exact FNV collision pairs,
scope separation, audit bits, domain modes, validation/capacity limits and every
embedded object's inner/outer ABI. BPF objects are regenerated for both byte
orders. VM-only integration fixtures cover legacy default-deny through prepare,
switch/abort/retire, audit denial tagging with generation IDs, colliding exec and
endpoint identities, and dynamic cgroup/writeback fencing across reload.

The integration fixtures require the existing disposable-vimto identity guard;
they are not host tests. They are included in the existing LSM VM CI suites,
including the built 6.1 kernel. Local compile-only command (no attachment):

```sh
go test -race ./internal/ebpf
go test -tags integration -run '^$' ./internal/ebpf
make -C bpf
go generate ./internal/ebpf
```

A successful local compilation is not a claim that VM CI ran, nor that daemon
reload, userspace evaluation and kernel publication form an atomic transaction.

### Strict VM evidence gate

The broad LSM suites can skip on incompatible BTF or missing optional features;
their successful exit is **not** generation verifier/outcome proof. The separate
`kernel-generations-strict` job in `.github/workflows/lsm-test.yml` uses the built
IMA kernels **6.1.188 and 6.18.53**, regenerates BPF, and runs
`tests/integration/run-kernel-generations.sh`. No matrix entry allows failure.
The runner requires `WARMOR_REQUIRE_BPF_LSM=1`, `WARMOR_REQUIRE_IMA=1`, a guest
fixture verifying those flags and the actual requested kernel minor, and exactly
one top-level PASS for **every** named fixture in its manifest. Any skip (including
a child skip), failure, missing/duplicate PASS, missing final PASS, or nonzero
vimto/test exit invalidates the gate. The manifest's offline tests ensure every
`TestLSM_Generation*` fixture is selected and exercise false-green log cases.

In addition to the sequential fixtures, the strict gate requires:

* Four independently paced UDP-connect producers running through five policy
  pointer replacements, each alternating audited exact allow with default-deny
  miss. UDP supplies an unambiguous syscall success/EPERM oracle without a peer
  server or connection timeout. Per-producer order pairs **every syscall** with
  its emitted generation/verdict. The fixture rejects event loss/duplication,
  mixed generation/verdict pairs, unknown scope/ID, lack of syscall/activation
  interval overlap, and old IDs arriving after flush. Old FDs are retained before
  acknowledgement and verified closed while producers continue making progress
  across retirement. Bounded rates, buffers and waits turn starvation into a
  failure, not a passing sample with no concurrent coverage.
* Seven audited-allow events explicitly queued without a reader, below the
  kernel's 64KiB wakeup threshold (`BPF_RB_NO_WAKEUP`). After switching the pointer,
  `FlushLSMEvents` must deliver **all seven with the old ID and unchanged verdict**
  before `ErrFlushed`; only then is that generation acknowledged.
* Legacy exact/default-deny behavior and sleepable IMA integrity coexistence.
  The latter uses real tmpfs binaries: allowlisted content succeeds until the
  generation policy denies it; unlisted content remains refused despite an
  exact generation allow. It requires both generation-tagged policy events and
  unversioned integrity denial events, real SHA-256 hashing, and zero hash errors.
  Existing legacy collision/audit and integrity-enforcement fixtures must also
  produce non-skipped PASS evidence in the same gate.

The runner executes a prebuilt, hashed test binary **only in the disposable
vimto VM**, with the existing PID-1/private-virtio-port guard before generation
attachments. It retains revision/build information, kernel/binary/BPF input
SHA256s, the required-test manifest and VM output on success or failure. Run
`bash tests/integration/run-kernel-generations.sh --build-only` for local compile
and input-manifest validation without starting a VM or attaching any program.

These are required CI assertions, not a report that CI has already passed. They
do not supply the still-missing combined daemon evaluator/activation/recovery
protocol or authorize enabling the opt-in generation API.

### Clang 21 dormant-map BTF compatibility

Even observation-only hooks include the shared, initially empty
`active_generation` map. Clang 21 can emit an unsized BTF forward declaration for
a named inner `generation_value` struct when that hook never dereferences it
(notably integrity), so bpf2go fails before any verifier can run. The canonical
value is therefore one anonymous struct behind the `generation_value` typedef,
used by both the map declaration and policy lookup helpers. No duplicate layout,
dummy kernel map, policy lookup, security decision or loader fallback is added.
Its members remain `policy_value policy` at byte 0 and `__u64 generation` at byte
8, size 16; C assertions and offline BTF tests enforce this.

`TestGenerationObjectABI` parses all eight hooks in **both** ELF byte orders,
including objects not embedded by the host's build tags. It checks the full
288-byte exact key, 8-byte policy value, 16-byte generation value and 416-byte
event with member types/offsets, the empty single-pointer map and matching inner
map properties. `TestGenerationObjectGoABI` also checks userspace sizes/offsets.
The required BPF compile job regenerates with explicitly selected Clang 18 and
21, matching llvm-strip and `-mcpu=v1`, then runs these tests without loading any
BPF. This repairs common supported compiler compatibility rather than selecting
a newer compiler to conceal the failure. The non-skippable Linux 6.1/6.18 VM
verifier/outcome gates remain required: successful compilation and BTF parsing
are not verifier acceptance, enforcement or combined-daemon proof.

The compile matrix uses Ubuntu 24.04 explicitly. LLVM 18 comes from Noble;
LLVM 21 comes from the versioned HTTPS `apt.llvm.org/noble/`
`llvm-toolchain-noble-21` archive. Before enabling that source, CI verifies its
signing key's primary fingerprint
`6084F3CF814B57C1CF12EFD515CF4D18AF4F7421` (published by apt.llvm.org), scopes
APT trust with `signed-by`, and requires a successful signed index refresh.
No downloaded installer script or unauthenticated APT option is used. Both
compiler entries remain mandatory; package policy and tool versions are logged.

The committed objects were regenerated with Clang 18.1.3, whereas the previous
objects used Clang 23. Their instruction bytes therefore differ with compiler
code generation. The separate **same-compiler Clang 23** old/new source
comparison found identical instructions and map/program contracts across all 16
hook/endian objects; it does not claim old/new committed instruction identity.
Neither that comparison nor ABI checks replace native kernel VM verification.
