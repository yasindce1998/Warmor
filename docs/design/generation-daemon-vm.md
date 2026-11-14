# Whole-daemon generation outcome gate

Status: **fixtures/build-only verified locally; actual VM CI execution required**.
The feature remains experimental/off by default. This is not signed-mode,
supervised-Host, workload-selector or crash/power-loss proof.

Fixture source branch `test/generation-daemon-outcomes` started at `6efd049`.
The new integration branch `test/generation-daemon-integration` in persistent
`.worktrees/generation-daemon-integration` starts at current PR51 `e3f5b84` and
cherry-picks **only** `3bf1b26`, `2dc6784` and `edfb824` as `c8149c0`, `c8d90e5`
and `73127d5`. Original owner/source branches are untouched. Existing signed
assignment code from the base is retained, including the explicit refusal guard;
no signed/generation or supervised-Host deployment combination is tested here.
BPF C, embedded objects, the 416-byte event and 288-byte key ABI are unchanged.

## Runner and required evidence

`tests/integration/run-generation-daemon.sh` builds and hashes the real daemon,
a separately identified instrumented daemon, exact test/helper executables and
actual Cargo-generated opposing policies. `--build-only` compiles/loads both
modules in the WASM runtime and checks complete exec/connect eligibility without
starting a daemon or touching BPF. Safe tests reject malformed source/artifacts.

Full mode executes only the prepared test binary through vimto and the bounded
`run-vm.sh generation-daemon` wrapper with `/dev/null` stdin. The fixture's first
statement checks explicit selection, actual vimto PID 1, private `ctrl`/`stdio`
virtio ports, root, BPF LSM and the requested kernel minor. Missing selection
**fails**, never skips. There is no host-hook fallback.

The required `kernel-generations-strict` CI matrix also installs the Rust target
and runs this daemon phase on built kernels **6.1.188** and **6.18.53**. Its oracle
requires exactly one PASS for the parent and each named child; any SKIP, FAIL,
panic, no-tests or missing child fails. A success artifact is written only after
daemon/fixture cleanup. The 240-second guest timer and 480-second host startup/
transport deadline are separate; cleanup SIGKILL or timeout is always failure.
Logs/status, hashes, generated policies, markers, metrics, scope/ID/decision and
fault-stage evidence are retained on failure too.

## Whole-daemon operations

Every daemon uses `--experimental-atomic-generations --require-lsm --lsm-enforce
--default-deny` with a private cgroup filter. Helpers run as actual uid/euid 65534.
Allowed execs must run and create unique markers; first denied execs must return
**EPERM**, not missing-file errors, exit codes, later kills or timeouts. Baselines
work without a daemon; a sibling cgroup remains unaffected throughout reload.

1. **Normal compiled daemon reload/LKG/shutdown.** The default, untagged
   `warmor-daemon` binary acknowledges A through the real fleet client, loads B,
   then rejects a compiler-invalid candidate retaining B. First denied execs
   must be EPERM, permitted audited execs must survive real evaluation, and
   sibling scope remains unaffected. No profile control flag or injected seam
   is used. The exact separately hashed binary is the same normal build used
   by existing legacy daemon outcome tests.
2. **Opposing reload, captured association, LKG and idle shutdown.** Hold a real
   generation-1 exec after captured evaluator acquisition. Queue old-ID denial
   and audit samples. The real standalone watcher loads compiled B and publishes
   generation 2. While old work is held, first new deny must be EPERM and first
   new allow must start/remain alive; the reader must capture new ID 2 before old
   work is released. An invariant deny is attempted continuously through switching
   and every attempt must be EPERM. After release, require old audit-DENY
   decisions at ID 1 and opposing new enforced/audit decisions at ID 2, exact PID/path/cgroup
   and kernel-verdict association, and no current-ID relabeling. Cross-check real
   streamed outcomes. Reject a compiler-invalid WASM update in the daemon; B stays
   LKG for new operations. SIGTERM with idle rings must exit zero without a wakeup
   operation. Tracepoint declarations are audited where necessary so their dynamic
   writeback cannot suppress LSM samples used by the ID oracle.
3. **Fleet durable/drain pending recovery, no false acknowledgement.** A real
   client/server acknowledges A. B becomes live generation 3. A named test-only
   error at the real revision directory sync boundary follows live publication;
   disk rolls back to A, B remains enforced, and heartbeats must become unknown/
   error, never old/new success. Clearing that fault exposes a second named
   pre-drain failure, again unknown/error with live B unchanged. Clearing both
   completes the original immutable callback/drain, retires generation 2 and
   acknowledges B's exact hash/version without generation 4 publication.
4. **SIGTERM with worker work.** A real captured LSM exec remains held while
   SIGTERM cancels its event context. Cancellation must release the lease and
   exit the daemon zero within the bound; the harness kill cannot pass.

The VM selects a 2-second evaluation deadline for slow QEMU/TCG; production's
default is unchanged and its latency SLO is not tested. Readers, dynamic writers,
kernel maps, evaluators, drain, disk commit and client heartbeat remain real.
Only scenarios requiring held-worker scheduling/faults or captured-ID evidence
explicitly choose `warmor-daemon-profile`; ordinary cases use `warmor-daemon`.

## Compile-profile-only seams

`--generation-vm-control` and control-file behavior exist only on Linux with
**both** `integration` and `generation_daemon_vm` build tags. Normal builds have
no fault flag/environment parser, only named no-op calls; a test checks the flag
is absent. Even the profile refuses to arm without actual vimto init/private
ports and a VM-local control directory. Environment variables alone cannot arm
the profile or authorize host enforcement.

`internal/generationvm` names these stages:

- `live`: kernel/userspace publication complete, pending recovery owner retained,
  dispatch/writer locks released.
- `event`: hold only an identified captured LSM exec; cancellation-aware.
- `durable-sync`: report an error at the real directory sync boundary following
  pointer rename; existing disk rollback runs. Deterministic syscall-boundary
  injection is **not physical storage or power-loss proof**.
- `before-drain`: return pending before real drain. This does **not** claim a real
  kernel flush timed out; the concurrent held-event test separately exercises the
  real flush/reader/queue/worker wait.
- `retired`: evidence only after old-map acknowledgement and evaluator close.

Capture/decision evidence copies scalar IDs/operation fields at actual boundaries;
it never rewrites IDs, decisions, kernel return values, scope or maps. Evidence
write failure invalidates the gate. Safe offline oracles exercise guards, fault
stage retry/cancellation and bad PASS logs. No new policy metadata API is added.

## Validation and limits

Go 1.26.11, `GOMAXPROCS=2`, `-p 2`: real Cargo build-only preparation passes.
Affected unit/race suites, normal/profile lint and guard/fault/PASS-oracle tests
are run without enforcement. Logs: `/tmp/opencode/generation-daemon-vm-*.log`;
ignored build artifacts: `tests/integration/artifacts/generation-daemon.*`.

At checkpoint `3bf1b26`, the full default `go test -p 2 ./...` suite and affected
package race suites pass. Real Cargo preparation identified that `log` decisions
do not carry the evaluator's audit bit, so the final opposing fixtures use
explicit `deny` plus `mode: audit` for permitted operations. This preserves
nonblocking semantics in both kernel and dynamic writeback and makes the
captured-ID oracle reject wrong-generation enforced/audited decisions. It is
not a relaxation of the required actual EPERM or outcome assertions. A pure
negative-evidence oracle is run on the host and reused for real VM associations.

**Not executed locally:** vimto/QEMU, any privileged/host hook, either supported
kernel's daemon phase, physical crash, signed/Host combination, cross-platform
runtime or BPF regeneration. Publish only after actual non-skipped CI results.
Offline oracles and compilation alone do not establish whole-daemon safety.

### P2 acknowledgement-oracle follow-up

The `2dc6784` oracle incorrectly armed only after an unknown/error heartbeat.
The follow-up checks **every** receipt: B/version 2 before `retired-2` is always
invalid, including B success before the first error heartbeat. A claimed old A
after live publication is invalid independently of whether it carries an error.
Legitimate pre-live A remains allowed.

Atomic checkpoint records now include an actual guest `CLOCK_MONOTONIC` sample.
The server fixture samples that same clock at HTTP ingress, **before** decoding
the request or reading phase records. Validation uses phase time as of ingress:
retirement observed during decode cannot excuse early B, and publication after
ingress cannot invalidate pre-live A. Final transcript reconciliation handles a
phase record whose atomic rename raced the handler's first read. Neither control
files nor heartbeat fields supply phase timestamps, future timestamps fail, and
the checkpoint and its timestamp are published in one atomic record.

Offline negative transcripts include the exact early-B → first pending error →
retirement → B-success counterexample; old-A/no-error after live; early B decoded
after retirement; late-live-record reconciliation; and the valid pre-live-A →
pending → retirement → B-success sequence. This is an oracle fix, not a pipeline
snapshot/lease fix or evidence that the VM phases have executed.

Follow-up validation: Go 1.26.11, `GOMAXPROCS=2`, `-p 2`; normal affected package
tests, gate race oracles (10 repetitions), profile guard/timestamp/fault race
oracles (10 repetitions), normal/profile lint and profile vet pass. The tagged
integration fixture compiles with `-run '^$'`; no VM/host hook was run. Logs:
`/tmp/opencode/generation-daemon-vm-p2-*.log`.

### PR51 integration prerequisite: recording ownership

Read-only source review of PR51's `54d9ea5` found a necessary fixture change not
present in this branch's old `6efd049` base: `outcomeFixture.recordings` is created
by `createOutcomeRecordings(f.work)` on the guest filesystem. Daemon recordings
must go there, **not** to `f.dir` in the shared host-user-owned checkout, since
the enforcing daemon is guest root and PR39's private-path checks must stay on.
`exportOutcomeRecording` runs only after daemon wait/forced cleanup completes,
retaining partial evidence without weakening source recording ownership.

The new PR51 integration retains `54d9ea5`: all `FileSink` recordings are made
inside guest-root-owned `work/recordings` (0700), never the host-owned artifact
checkout. Validation before every daemon start requires that exact directory,
no symlink, mode 0700 and the daemon's effective UID. No ownership repair or
chmod bypass is performed. `stopOnce`/explicit stop waits before cleanup exports
the closed recording once, and export failure still fails an already-failed
subtest. Unit oracles reject shared/public recording paths, missing/failed
exports, nonzero wait, SIGKILL cleanup and timeout even if cleanup returns nil.
Generation-specific control directories also live under guest-only
`/var/tmp/warmor-generation-*` mode 0700, with status/evidence files mode 0600;
the fixture copies them to host artifacts after daemon cleanup. Those deliberate
exports are not the live daemon recording directory. The first fixture cherry-pick
had conflicts only in main startup and daemon cleanup. Both startup checks and
private-recording post-wait export were preserved; later picks applied cleanly.
No edit or merge was made to the PR51 owner branch. Actual VM CI on both kernels remains required after
combining the fixtures; local oracle passes do not prove private recording or
whole-daemon execution under that newer main.

### Final PR51 integration validation

Code checkpoint `ae16720` on `test/generation-daemon-integration`, Go **1.26.11**,
`GOMAXPROCS=2`, `-p 2` where applicable. The complete normal test suite and complete
race suite were run **once each, sequentially**, not concurrently:

- `go test -p 2 ./...`: pass.
- `go test -race -p 2 ./...`: pass.
- Repository-configured golangci-lint, normal full tree: pass.
- Profile-tagged golangci-lint for fixture/seam/daemon packages: pass.
- Root actionlint v1.7.7: pass (`-shellcheck=` because shellcheck is unavailable;
  shell syntax separately checked with `bash -n`).
- Real Cargo `run-generation-daemon.sh --build-only`: pass; normal/profile
  daemon binaries, all exact helper inputs and generated A/B artifacts hashed.
- Profile guard/timestamp/fault race oracles, ten repetitions: pass.
- Normal-build control-flag absence passes with no tags, `integration` alone,
  and `generation_daemon_vm` alone. Both tags remain necessary to include it.
- Profile-tagged vet and compiler-invalid artifact oracle: pass.
- Whitespace checks: pass. No BPF source/embedded object, ABI, `go.mod` or
  `go.sum` changes relative to `e3f5b84`.

The strict daemon matrix retains hard dependencies on the **entire Clang 18/21
compiler matrix** and built IMA kernel job; neither compiler nor 6.1.188/6.18.53
daemon outcomes may continue-on-error. Offline workflow tests enforce these
dependencies. Local logs are `/tmp/opencode/generation-daemon-integration-*.log`;
latest build-only inputs are in ignored `artifacts/generation-daemon.P9BAQk`.
No QEMU/vimto execution, BPF attachment, host enforcement, pushes or original
branch edits occurred. CI must actually execute all required phases without
skips on both kernels before merging; the feature stays experimental.
