# Whole-daemon generation outcome gate

Status: **fixtures/build-only verified locally; actual VM CI execution required**.
The feature remains experimental/off by default. This is not signed-mode,
supervised-Host, workload-selector or crash/power-loss proof.

Branch `test/generation-daemon-outcomes`, worktree `.worktrees/generation-daemon-vm`,
starts at PR51 source `6efd049`. Original owner branches/worktrees are untouched.
No signed/main integration is merged here. BPF C, embedded objects, the 416-byte
event and 288-byte key ABI are unchanged.

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

1. **Opposing reload, captured association, LKG and idle shutdown.** Hold a real
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
2. **Fleet durable/drain pending recovery, no false acknowledgement.** A real
   client/server acknowledges A. B becomes live generation 3. A named test-only
   error at the real revision directory sync boundary follows live publication;
   disk rolls back to A, B remains enforced, and heartbeats must become unknown/
   error, never old/new success. Clearing that fault exposes a second named
   pre-drain failure, again unknown/error with live B unchanged. Clearing both
   completes the original immutable callback/drain, retires generation 2 and
   acknowledges B's exact hash/version without generation 4 publication.
3. **SIGTERM with worker work.** A real captured LSM exec remains held while
   SIGTERM cancels its event context. Cancellation must release the lease and
   exit the daemon zero within the bound; the harness kill cannot pass.

The VM selects a 2-second evaluation deadline for slow QEMU/TCG; production's
default is unchanged and its latency SLO is not tested. Readers, dynamic writers,
kernel maps, evaluators, drain, disk commit and client heartbeat remain real.

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
