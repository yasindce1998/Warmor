# Experimental combined generation activation

Status: **OFF by default; review and whole-daemon VM evidence still required**.
The option is `--experimental-atomic-generations --require-lsm`. Linux BPF LSM
and already compiled WASM candidates are mandatory. Audit/learning normalization
is unchanged. Workload coordinator/selector routing is **not** connected here.
The existing single-map path remains the default and makes no new guarantees.

## Explicit commit model

There is no syscall that atomically commits kernel maps, a Go evaluator, and a
filesystem revision. These are distinct points, deliberately ordered:

1. Read/verify candidate bytes once; build a new runtime, pool, evaluator and
   cache. Build a complete static kernel spec in an unreachable map. Failed
   preparation/publication aborts only the candidate, never clears/unmarks old
   policy. Failed cleanup retains its ID and is retried before another prepare.
2. With `activationMu` held, take `decisionMu` then dispatch mutex. Register the
   new evaluator before `Activate`. The single outer-map pointer update is the
   **irreversible live kernel commit**. Publish userspace current while still
   holding the dispatch mutex. New-ID producers never require a userspace lock;
   their reader acquisition waits until registration/publication completes.
3. Release decision/dispatch locks. Invoke durable revision commit. A failure
   here means **candidate active, recovery pending**, not "old policy retained."
   Return `ErrActivationPending`; keep both evaluators and the original immutable
   revision/callback. Never roll the kernel back through empty/legacy maps.
4. On durable success, request `FlushLSMEvents`. The **existing single reader**
   continues captured-ID dispatch through wrapped `ringbuf.ErrFlushed`. It then
   sends a queue fence, processed by the event loop after all prior samples.
   Wait for every old dispatch/evaluation/cache/action/reporting/writeback lease.
   Only then acknowledge kernel retirement and close the old evaluator/pool.
5. Return success to the fleet client **only after** durability and drain. Failed
   heartbeat persistence retains the server's old snapshot/error behavior from
   PR38; a later heartbeat retries the exact locally acknowledged identity.

This allows old captured work to finish after the new policy becomes current,
using its **old** evaluator and cache, rather than silently evaluating it under
the new policy. This is intentionally different from the legacy full event
barrier, which disallows old userspace actions crossing successful activation.
The new contract is per-event snapshot consistency, not cancellation of all old
actions at the kernel pointer commit. Async sink delivery is outside the lease;
outcome creation and pipeline submission are inside it.

## Routing and lock ordering

`pkg/api.Event.PolicyGeneration` preserves the kernel ID for every LSM hook.
Exec, connect, bind, listen, mount and ptrace use that captured kernel ID,
including legacy ID **0**. A nonnil `GenerationContext{ID:0}` is a valid capture,
never an unset value. Tracepoints and observation-only file, AF_UNIX and integrity
events acquire the current userspace generation at dispatch. They do not remain
attached to ID 0 forever. No tracepoint operation-time kernel-generation claim
is made: its linearization point is the dispatch acquisition after sensor read.
All Linux delivery paths acquire a lease before channel enqueue and release on
delivery cancellation or completion. Live leases/fences are never JSON-replayed.
Unknown versioned IDs are refused/logged, never silently routed as current.

Lock order: activation serialization -> decision writer fence -> dispatch ->
evaluator publication. Event handlers may take event lifetime lock -> dispatch,
but activation never takes event lifetime lock while holding dispatch. Filesystem
callbacks and all reader/worker waits run **without** dispatch, decision, evaluator
or event exclusive locks. No second goroutine reads the ring. Thus a blocked
reader/evaluator can continue while activation waits for its queue fence/lease.
The event loop is currently single-consumer; adding parallel workers requires
retaining queue-fence semantics and lease accounting, not merely closing a fence
when a worker dequeues it.

Dynamic decisions are written only under the decision fence and only if the
evaluating generation is still current. Generation API `SyncEvent(id,...)`
provides a second stale-writer fence. No old dynamic cache is copied forward.
The existing kernel-key fields proof and exact identity checks still apply.
Shared 127-byte process identity eligibility from PR41 is retained. With atomic
mode + `--default-deny`, **both** exec and connect static domains must be complete;
an ineligible candidate is rejected before publication, never silently unmarks
a protected domain. Empty eligible allowlists mean deny-all. This is not the
separate generalized `--require-default-deny` feature from `b6d1819`.

## Bounded grace, uncertain recovery and rollback

Grace waiting has a five-second context bound, not a forced lifetime deadline.
Timeout, cancellation, reader failure or failed FD retirement **retains** old
resources and blocks a third buffer. A ring timeout leaves its one outstanding
flush/fence owned for retry, not overlapped by another flush. Retrying the same
immutable revision finishes its original commit/drain without another prepare
or ID change. A changed mutable standalone path is rejected by digest instead
of falsely acknowledging bytes that are not active. Compile YAML to WASM first.

Daemon revision staging retains the uncertain candidate and retries its exact
path/callback. If desired assignment changes, it first resolves the pending
revision, then activates the new assignment; completing old recovery alone must
not acknowledge the new assignment. Repeated disk commit retries its directory
barrier without replacing `previous` with itself. Existing disk rollback after
fsync failure remains a **disk-only** recovery action, not a live policy rollback.

The fleet client withdraws active identity while the callback runs and keeps it
unknown after an uncertain live commit, with activation error. Ordinary
precommit failures restore the old acknowledged identity. It never claims the
old policy is active once that is known false, and never claims the new revision
active/durable on callback failure. Active identity remains self-reported, not
remote attestation.

Fleet SIGHUP/local reload is rejected **before** enforcer invocation, in both
legacy and generation modes. Only the fleet client's update/recovery owner may
publish live policy. Thus an externally written local B cannot replace an
acknowledged A through SIGHUP and leave A indefinitely acknowledged via 304.
The rejection is logged, not reported as an activation attempt; live A and its
acknowledgement remain unchanged. Standalone SIGHUP behavior is unchanged. The
same ownership prohibition must be retained by explicit signed-mode wiring.

### Signed backend integration request (not wired here)

`Enforcer.ActivatePolicy(immutableModulePath, durableCommit func() error)` is the
backend seam, not permission to run two publication transactions. In explicit
signed mode **agentstore must be the sole publication and rollback authority**.
Do not call PR38 `stagePolicyRevision`/`current` publication in addition to an
agentstore commit, and do not nest one commit inside the other's rollback path.
The unsigned PR38 handler in this branch is not the signed-mode adapter.

The signed adapter must verify/prepare an immutable module-signature-assignment
handle before activation and retain it across failures. Supply the handle's
idempotent agentstore commit as `durableCommit`. The original closure is retained
by the enforcer, so recovery must repair its backend state rather than substitute
a different closure on retry. Hook invocation means live publication succeeded;
it runs after the kernel pointer and userspace current switch and after writer
fencing, with no dispatch/event/decision locks held. It may durably record the
active-or-indeterminate outcome. Every nonnil hook result is conservatively
treated as indeterminate **after live commit**, even when its store knows that
its own disk transaction rolled back. `ErrActivationPending` and its structural
`ActivationUncertain() bool` marker must propagate unhidden to the client.

The backend must preserve previous revision/anti-replay state and candidate
recovery ownership; keep old evaluator references until the SAME pending commit
and ring/worker drain resolve. Do not close old pools on store error or attempt
"compensation" by restoring only `current`, agentstore metadata or client active
identity. New live policy continues enforcing; the node acknowledgement remains
unknown/error, not an old/new success. If required denial cannot be established,
the adapter must reject before publication; pending state is not an excuse to
turn enforcement off. The enforcer does not broaden policy while recovering.

Requested combined follow-up tests for the signed owner: backend commit failure
before/after durable replacement, anti-replay/sequence persistence, reopen after
each crash boundary, changed desired assignment during pending recovery, and
acknowledgement errors while old/new ID events are active. A backend that can
only implement pre-kernel publication or disk-only compensating rollback is
**not compatible** with this seam; keep the signed+generation combination gated
until a shared reviewed commit/recovery model is implemented. Process restart
adopts the sole backend's durable pair; no second PR38 pointer should compete.

### Shared metadata API coordination

This branch deliberately introduces **no** ABI/compiler/posture metadata struct
and does not create or modify `internal/policymeta`. Read-only inspection found
the signed integration's `policymeta.Metadata{Compiler,DefaultAction}` custom
section declaration (`warmor.build.v1`) and the metadata owner's
`policymeta.Module` runtime observations plus `policymeta.Source`. They represent
different trust statements and must be unified by their owners, not guessed from
a third generation-specific metadata document.

Generation spec building consumes the pre-existing structural surface:

```go
type staticRulesSource interface {
    StaticRulesProcess() wasm.StaticDomain
    StaticRulesNetwork() wasm.StaticDomain
}
// wasm.StaticDomain: { Eligible bool; Rules []compiler.StaticRule }
```

The metadata branch aliases `wasm.StaticDomain = policymeta.StaticDomain`, so
these two method signatures remain compatible. Its `policymeta.Source` also
exposes `Metadata() Module`, field/temporal/age queries, and
`DecisionCacheEligible`/`LinuxKernelCacheEligible`. Future supervised evaluator
wiring should use that source's **effective trusted methods**, not raw observed
flags or a signed build declaration as cache authorization. This checkpoint
still stores concrete in-process `*wasm.PolicyEvaluator`, `*wasm.Pool` and
`*wasm.Runtime`; it does **not** claim Host is wired. A reviewed evaluator
evaluation/close/source interface plus backend lifecycle owner is still needed.

PR41's shared `kernelmap.MaxPolicyPathBytes = 127` is retained here in compiler,
runtime static-export and dynamic key validation. The metadata branch's more
general 254-byte JSON observation allowance must not accidentally relax that
shared integration limit without ABI/kernel proofs; its binary limit remains
127. Kernel `GenerationSpec` is an installation input, not module metadata:
`Rules []GenerationRule{CgroupID,EventType,Pattern,Address,Port,Action,Audit}` and
`DefaultDeny []GenerationDomain{CgroupID,EventType,Mode}`. eBPF exports aliases of
these `internal/kernelmap` types, preserving existing generation API callers.
No shared BPF key/event ABI change is made beyond `6060ed2`/PR41.

On process death the unpinned hooks/maps are not adopted. Restart reads the last
durable `current` module/signature pair. A crash before disk publication can thus
restart the previous policy despite the candidate having briefly been live;
after publication restart selects the candidate. Interrupted staging is not
selected. A failed rollback/fsync can leave disk outcome uncertain until storage
recovers: no success acknowledgement is sent. This is **not** a crash-continuous
default-deny or physical power-loss guarantee. Keeping a journal cannot make
unpinned maps enforce while the daemon is absent. A reverse policy change is a
fresh complete generation, after outstanding drain, never fallback to legacy.

## Validation and remaining gates

Combined unprivileged tests use real WASM evaluators and fake kernel publication
boundaries. They cover old/new evaluator and cache routing, ID 0, every LSM hook,
registration before producer dispatch, readers progressing during activation,
ring queue fence ordering, wrapped flush sentinel, no overlapping timed-out
flush, canceled delivery, old lease drain, stale writeback, candidate cleanup,
precommit failure, uncertain disk retry, changed assignments, changed candidate
bytes, shutdown/cancellation and retirement failure. No BPF is attached by them.

Strict generation VM fixtures and non-skippable PASS oracle from `995fde6` are
retained unchanged for Linux 6.1/6.18, alongside PR41 deadline/context harness
fixes. They test kernel/API behavior, **not the combined daemon**. This integration
does not claim they ran locally. Before promoting this option: run the strict
kernel fixtures and add/execute whole-daemon VM reload/failure tests on both
supported kernels, including durable faults, concurrent old/new events/actions,
NO_WAKEUP flush, sustained default-deny, bounded memory and shutdown. Filesystem
fault injection is not physical power-loss validation. Startup attachment before
initial generation preparation and downtime/restart protection are not made
transactional. Configuration outside the generation map (enforce/audit switch,
cgroup filters, integrity, unix watch, loss behavior) is fixed during activation.

Integration branch `feat/generation-atomic-activation` began at PR38 `e4203dc` and
merged main `34a95ea`, PR41 `3bfa8a1`, generation `6060ed2`, dependency main
`173b118`, strict VM tests `995fde6`, PR41 harness `0d56818`, main `2c415c9`, and
refreshed PR38 `782b45e` (empty content merge, preserving ancestry).
No merge conflicts, source-branch edits, pushes, PR creation, host enforcement or
selector enablement were performed. Validation results are recorded in the final
integration report; this document's test inventory is not VM runtime proof.

### Local checkpoint validation

Final code checkpoint `995bab4`, Linux unprivileged, **Go 1.26.11**,
`GOMAXPROCS=2`, test/vet package parallelism `-p 2`:

- `go test -p 2 ./...`: pass.
- `go test -race -p 2 ./...`: pass after all source merges.
- Focused generation/uncertain-activation race tests, ten repetitions: pass.
- `go vet -p 2 ./...`: pass.
- `golangci-lint v1.64.8 run --concurrency 2 --timeout 5m ./...`: pass with
  repository lint configuration (includes errcheck with assertions).
- Integration-tagged ebpf/outcomes packages compiled with `-run '^$'`: pass;
  **no integration test execution** is implied.
- Windows amd64 enforcer and Darwin arm64 daemon test binaries cross-compiled:
  pass. No native Windows/Darwin execution is claimed.
- `git diff --check`: pass. BPF C/embedded objects have no delta from `6060ed2`.
  `go.mod`/`go.sum` have no delta from dependency merge `173b118`; grpc 1.83.2,
  x/net 0.62.0, x/sys 0.49.0, x/text 0.43.0 and x/sync 0.24.0 are retained.

Logs are `/tmp/opencode/generation-activation-{full,race,focused-race,lint,vet,`
`integration-build}.log`. An initial full run exposed the cache test's reflection
walker not handling the new internal channel fence. It now mutates channels and
still compares actual policy serialization; no input-coverage check was skipped.
Subsequent full and race suites pass. No whole-daemon VM, physical crash/power
loss, host-enforcing run, BPF build regeneration, or native cross-platform test
was performed by this integration task.

### Review follow-up: fleet SIGHUP ownership

Review of `22cc85e` found that the signal path invalidated fleet identity only
after a nil reload result. A live generation B followed by failed drain could
therefore leave acknowledged A stuck behind identity-aware 304 responses. The
follow-up chooses explicit prohibition rather than another recovery owner:
`reloadLocalPolicy` rejects fleet-local reload before invoking the enforcer.
Its regression test acknowledges A through a real client/server, stages local B
and supplies a would-be live-B/failed-drain callback; that callback is never
called, live/acknowledged A stays genuine, and subsequent 304s are valid.
Standalone success, precommit error and pending error propagation are unchanged.
The existing normal fleet uncertain-commit and precommit-failure identity tests
also remain passing. Signed-mode wiring must retain this ownership prohibition.

Go 1.26.11, `GOMAXPROCS=2`, `-p 2`: daemon/server/enforcer package tests pass;
focused reload/generation/uncertain/precommit race tests pass ten repetitions;
daemon vet and repository-configured golangci-lint pass. Lint initially found
another session holding its global runner lock; rerunning with
`--allow-serial-runners` passed. Logs: `/tmp/opencode/generation-activation-sighup-`
`{tests,race,lint,vet}.log`. No full-suite rerun or VM execution is claimed for
this focused follow-up. No other owner branch was changed.
