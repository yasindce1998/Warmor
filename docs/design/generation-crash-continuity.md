# Generation crash-continuity investigation

Status: **investigation record + bounded-retention clarification. No new crash or
power-loss continuity claim.** The experimental atomic-generation path remains
OFF by default (`--experimental-atomic-generations --require-lsm`) and is not
production readiness. This document records an audit of the existing commit
ordering, resource bounds and out-of-band configuration, and the test evidence
added alongside it. It deliberately leaves every refusal guard (signed
assignments, telemetry, supervised host) untouched: removing any of them needs
combined VM evidence we do not have.

## 1. Exact commit ordering (`activateGeneration` / `finishGeneration`)

Source of truth at this checkpoint: `internal/enforcer/generation.go`
(`activateGeneration` lines 257-342, `finishGeneration` lines 195-249) and
`internal/ebpf/policy_generation.go` (`GenerationManager`).

`activateGeneration(path, commit)` is called with `activationMu` held. Its
ordered steps are:

1. Retry any retained `abortID` cleanup (a failed candidate FD close) before
   doing anything else; a still-failing close aborts the attempt and consumes
   the ID. `ErrStaleGeneration` on retry means no FD was admitted and is
   treated as success.
2. If a `pending` activation exists: reject any *different* immutable path,
   verify the original path's bytes still match the retained digest, call
   `finishGeneration()` to resolve the original commit/drain, and return.
   **No new generation ID is allocated while a revision is pending.** This is
   the userspace half of the retention bound (see §2).
3. Reject ID exhaustion, read/verify the candidate bytes exactly once, build a
   fresh evaluator/runtime/pool/cache, and derive the complete static
   `GenerationSpec`. All of this happens while the old policy stays active.
4. `g.next++`, then `kernel.Prepare(id, spec)` builds an unreachable inner map.
   A prepare failure closes/aborts the candidate and never touches active
   policy. A failed FD close is retained in `abortID` for step 1 of a later call.
5. Under the writer fence order `decisionMu` -> dispatch `g.mu`, register the
   new state in `g.states` **before** publishing the kernel pointer, then call
   `kernel.Activate(id)`. The single outer-map pointer update
   (`active_generation[0]`, an `ARRAY_OF_MAPS` xchg) is the **irreversible live
   kernel commit**, and the only cross-kernel atomic point. On publication
   failure the state is unregistered, the candidate is aborted, and the old
   policy is unchanged (no rollback through legacy/empty maps).
6. While still holding `decisionMu`/`g.mu`: capture `old = g.states[g.current]`,
   set `g.current = id`, store the userspace `policyGen`, then under
   `evaluatorMu` publish the new evaluator/pool/runtime/backend/policyID and
   seal legacy telemetry. Release the locks. New-ID kernel producers never
   need these locks; their lease acquisition waits until registration and
   publication are complete.
7. Record `g.pending = {path, commit, old, digest}`. The `Checkpoint("live")`
   call is instrumentation only; its failure returns `ErrActivationPending`
   but never rolls the kernel back.
8. Call `finishGeneration()`.

`finishGeneration()` (under `activationMu` ownership of `g.pending`):

1. If the durable barrier has not run, invoke `commit()`. A failure returns
   `ErrActivationPending` and **leaves the candidate live** — "active,
   recovery pending", never "old policy retained". `durable` is then set.
2. Take a bounded grace context (`generationDrainTimeout`, default 5s).
   `Checkpoint("before-drain")`, then `kernel.Drain(ctx)` (single reader flush
   through wrapped `ringbuf.ErrFlushed` plus the queue fence).
3. Snapshot `old.refs` / its zero channel under `g.mu` and wait for every
   old-ID dispatch/evaluation/cache/action/reporting/writeback lease to
   finish, or for the context to time out.
4. `kernel.AcknowledgeDrain(old.id)` closes the old kernel FD **without
   deleting entries** (kernel RCU protects already-running non-sleepable
   hooks). A failure blocks a third buffer and is retried.
5. Under `g.mu`, delete `g.states[old.id]`; close the old evaluator/pool only
   if its backend differs from the current one; clear `g.pending`;
   `Checkpoint("retired")`.

**Ordering conclusion.** The kernel commit (activate step 5) precedes the
durable disk barrier (finish step 1) and the ring/worker drain (finish steps
2-3). There is no syscall that atomically commits kernel maps, the Go
evaluator and a filesystem revision; the manager mutex only serializes its own
kernel writes. Any failure after step 5 returns `ErrActivationPending`, keeps
both generations, and retries the *same* immutable revision. It never claims a
rollback. This matches `docs/design/generation-activation.md`.

## 2. Bounded retention (kernel FDs and userspace state)

The comment at `generation.go:193-194` states that a timeout "retains TWO
generations and blocks third-buffer builds." Audit confirms this is the
intended **bound**, not an unbounded leak:

* `GenerationManager` (`internal/ebpf/policy_generation.go`) owns at most two
  inner maps. `Prepare` returns `ErrGenerationBusy` while
  `candidate != nil || retiring != nil`, so a third map cannot be created
  until `AcknowledgeDrain(oldID)` releases the retiring FD. `Activate` moves
  `candidate -> active` and `active -> retiring`; `AcknowledgeDrain` closes the
  retiring FD; `Abort` closes a candidate FD. Creation/population failures
  close the candidate immediately (or retain exactly one `abortID` for retry).
* `Enforcer` mirrors that bound with `g.pending`: while a revision is pending,
  `activateGeneration` resolves it instead of allocating a new ID, and
  `g.states` holds only `old` + `current`. On resolution `finishGeneration`
  deletes `old` from `g.states` and clears `g.pending`. Generation IDs increase
  strictly (a failed/aborted ID is consumed), but consumed IDs are scalar
  counters, not retained FDs or evaluators.

Therefore repeated success/failure cycles do **not** grow live state: kernel
FDs stay at <= 2 (1 at quiescent points) and `g.states` stays at <= 2 (1 at
quiescent points). The bound is structural, not enforced by a GC sweep, and no
new runtime GC is needed or added. Regression tests:
`TestGenerationBoundedStateAcrossRepeatedSuccessFailureCycles` (enforcer,
`internal/enforcer/generation_test.go`) and
`TestGenerationManagerBoundedFDsAcrossRepeatedCycles` (kernel manager,
`internal/ebpf/policy_generation_test.go`) drive many alternating
success/pending-failure/retry cycles and assert the bounds.

**Disk revisions — open gap (not fixed here).** The durable module/signature
revisions are staged by `cmd/warmor-daemon/policyrevision.go`
(`policyRevisionStager.create`, `os.MkdirTemp(root, "revision-*")`), which is
outside the files owned by this sprint and outside the enforcer's generation
locks. Each successful `commit()` repoints `previous` at the old `current`
directory but never deletes superseded `revision-*` directories; `discard()`
only removes an *unpublished* candidate not referenced by `current`/`previous`.
On a long-lived node this directory grows without bound. Bounded disk GC would
require an ownership/lock model shared with the daemon's publication path
(refcounting `current`/`previous`/pending dirs and sweeping the rest after a
durable barrier), which cannot be done safely inside the enforcer's
`activationMu`/dispatch locks. It is left as an explicit open gap.

## 3. Configuration outside the generation transaction

`bpf/warmor_lsm.h` defines `lsm_cfg` (loss config, line 144),
`lsm_cgroup_filter` (line 152), `lsm_enforce` (line 160) and `unix_watch`
(line 368) as maps distinct from `active_generation` (line 278). The hooks read
the generation snapshot and these config maps independently at operation time
(`is_enforce_enabled()` at line 210, `lsm_cfg.on_loss` at line 408).

Userspace writers are also distinct: `lsm_enforce` is written by
`ebpf.SetEnforce`/`LSMLoader.SetEnforceMode`, `lsm_cgroup_filter` by
`SetLSMCgroupFilter`/`LSMLoader.SetCgroupFilter`, and loss config by the loader
at `LoadLSMWithOptions` time. The cgroup filter is additionally reconciled at
runtime by the platform's discovery loop (`ReplaceCgroupFilter`). None of these
writers is part of `platform.PolicyGenerations`, which is the only kernel handle
the enforcer's activation path holds (`Prepare`/`Activate`/`Abort`/
`AcknowledgeDrain`/`SyncEvent`/`Drain`). `GenerationManager.backend.publish`
writes only `active_generation[0]`; the manager has no reference to the config
maps and cannot write them.

**Why no freeze/restore/reject was added.** The activation window is owned by
the enforcer's `activationMu` -> `decisionMu` -> dispatch lock chain. The config
setters live in the loader and the platform cgroup reconciler, in other
packages, under their own locks. Freezing or rejecting changes would require a
shared lock or gate spanning enforcer activation, the platform reconciler and
the loader config setters, with a new documented lock order and failure
semantics (what to do with a rejected reconcile, how to restore on uncertain
commit). That is not a small change and risks lock-order deadlocks; the existing
design explicitly allows automatic cgroup discovery/filter reconciliation to
proceed concurrently and reports scope health through readiness rather than
claiming atomic scope convergence (`generation-activation.md`). We therefore do
not claim an atomic policy switch that includes config state.

Instead we assert the invariant that holds today: **generation activation never
writes the config maps.** Tests:
`TestGenerationActivationDoesNotTouchConfigMaps` (enforcer,
`internal/enforcer/generation_test.go`) drives success, commit-failure/retry
and drain-timeout/retry activations through a fake platform whose config
setters count calls and asserts zero calls; and
`TestGenerationManagerNeverWritesConfigMaps` (ebpf,
`internal/ebpf/policy_generation_test.go`) wires a config spy into the fake
generation backend and asserts zero config writes plus a byte-identical config
snapshot across the full lifecycle and failure/abort paths.

## 4. Startup flush clarification

`kernel-generations.md` (bounded-resource/lifecycle section) and the source
comment at `generation.go:82-83` ("Keep ID 0 until the reader starts and proves
the first flush") suggest startup defers activation until the reader proves
readiness. **Actual behavior differs.** `enableGenerations`
(`generation.go:71-105`) immediately:

* builds the legacy state at ID 0 from the startup evaluator/backend/cache;
* calls `kernel.Prepare(1, spec)` and registers state 1 with the *same*
  startup evaluator/backend (no userspace work is reloaded at startup);
* calls `kernel.Activate(1)`, sets `g.current = 1` and `policyGen = 1`;
* records `g.pending = {durable: true, old: 0}` so that ID 0 is only the
  *retiring* generation.

The initial `finishGeneration()` invoked during `New()`
(`enforcer.go:620-625`) then drains and acknowledges ID 0. So generation 1 is
the live kernel policy from the end of `enableGenerations`; ID 0 is never
"kept" as the current policy pending a flush. The reader flush proves the
*retirement* of the startup (ID 0) samples, not a gate on activating ID 1.
There is no bug in this behavior — it is the documented one-pointer commit
model applied at startup — so no runtime change is made. The discrepancy is
resolved here and the misleading source comment is reworded to describe the
actual sequence.

## 5. Unpinned maps / no restart adoption

`kernel-generations.md:102-106` is confirmed: `GenerationManager` never calls
any pin helper; `Close` releases FDs but never clears the `active_generation`
outer pointer (clearing it could reopen the legacy policy path). On process
death the unpinned programs/maps are not adopted by a new process. Restart
reads the last durable `current` module/signature pair and builds a fresh
manager whose IDs restart from 1; a candidate that was briefly live before a
crash but not durably published is not selected, while a published one is.
Interrupted staging is not selected. A failed rollback/fsync can leave the disk
outcome uncertain until storage recovers, with no success acknowledgement.

**This is not crash-continuous or power-loss-proof.** Keeping a journal cannot
make unpinned maps enforce while the daemon is absent. Startup attachment and
initial generation preparation are not transactional. Combined whole-daemon
VM reload/fault evidence is still required before enabling the option.

## 6. Validation and open gaps

Added tests (see §2 and §3) are unprivileged and attach no BPF. Local checks at
this checkpoint:

* `go test -race ./internal/enforcer/... ./internal/ebpf/...`
* `go test -tags=integration -run '^$' ./tests/integration/...`

Open gaps (deliberately not closed here):

1. No claim of crash/power-loss continuity; unpinned maps and restart adoption
   are a real gap (§5).
2. Disk revision directories have no bounded GC (§2); requires a daemon-owned
   shared ownership/lock model outside this sprint's files.
3. Config (enforce toggle, cgroup filter, loss, unix watch) is not frozen or
   rejected during activation (§3); it is only proven untouched by activation.
4. All refusal guards (signed assignments, telemetry, supervised host) remain
   in place; removing them needs combined VM evidence.
5. Whole-daemon VM reload/fault evidence on both supported kernels is still
   outstanding; unit/race tests are not that evidence.
