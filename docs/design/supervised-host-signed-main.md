# Supervised host: signed/manifest main conflict integration

This refresh starts at PR53 review checkpoint `5010198` on
`feat/supervised-host-activation`, in `.worktrees/supervised-host-integration`.
`git fetch origin` resolved current main to **`98d2b90`**, including PR49 signed
activation and PR46 workload manifests. Merge **`d0e1144`** has exactly those two
parents. No edits are made to the separately owned
`.worktrees/supervised-host-vm` packaging/test worktree or any frozen source branch.

Status remains **experimental/off by default**. This merge does not run or claim
whole-daemon Host VM validation, deployment receipts, signed-generation atomicity,
packaged host readiness or production native-compromise sandboxing.

## Actual conflicts (nine paths)

- `cmd/warmor-daemon/main.go`: retain both signed and supervised validation-mode
  refusals, main's signed bootstrap/recovery/restore/client startup, Host/atomic
  options, and fleet sole-owner SIGHUP rejection. Signed startup still selects
  agentstore only; no PR38 pointer publication is chained into its commit.
- `internal/enforcer/enforcer.go`: combine main's embedded platform injection and
  `SignedAssignment` mode with reviewed backend ownership, effective initialized
  blocking status, cancellation-before-activation-lock shutdown and generation
  activation. Remove the conflicting duplicate in-process load block: Host mode
  must never construct or invoke a parent runtime while loading bytes.
- `internal/enforcer/signed_assignment.go`: checks use canonical
  `policymeta.Source.Metadata().MatchArtifact`, not a second raw-module parser.
  Preserve effective source static/cache methods and initialized blocking checks.
- `internal/policybuild/metadata.go`: keep the canonical strict custom-section
  codec, including UTF-8/control-character validation. No competing metadata type
  or permissive parser is introduced.
- `internal/wasm/{runtime,pool}.go`: retain one runtime digest/build-claims state
  and pool-captured identity. Main's `CheckAssignment` checks actual ABI, including
  absent=0, against captured module/build data; replacements use the captured
  compiled module and reject changed ABI. Canonical observations capture that
  same identity and remain independent of future runtime reloads.
- `internal/compiler/schema.go`: preserve compiler **7**, add main's immutable
  `Identity = "warmor-yaml/7"`. Main's compiler adds canonical build claims before
  signing and preserves context-aware builds/cleanup.
- `docs/{POLICY_SERVER_STATE,SIGNED_POLICY_ASSIGNMENTS}.md`: replace obsolete
  library-only descriptions with main's real standalone signed operation and add
  the explicit combined-backend gate. Do not describe an unimplemented combined
  transaction as supported.

Manifest code initially merged unchanged, revealing main's PR46 compiler-6 pin
incompatibility with PR49 compiler 7. The full manifest suite correctly refused
every candidate. Review of the 6-to-7 compiler delta found only canonical build
claim appending/identity plus cancellation checks; codegen/fields and deny-first
ordering are unchanged. Separate compatibility commit **`809a3ad`** pins explicitly to 7,
still rejects 6/future versions, and verifies actual compiled ABI, build claims,
deny-first, audit/temporal and namespace isolation. It remains a library/protocol
surface, not automatic selector routing or host-wide controller enforcement.

## Supported modes and early rejection

The default in-process mode and existing artifact-signed Host mode are unchanged.
Host standalone/unsigned-fleet and experimental unsigned-intent generations retain
zero parent WASM decode/compile, exact trusted declaration pins, relative policy
`Abs` before resolution, strict signature/file staging, readiness and reader
close-before-join/host-reap ordering. Private recording output checks and removal
of live lease/fence pointers from snapshots remain intact. Process identity is
still bounded to **127 bytes**, with **288-byte exact policy keys**.

Main's `--signed-assignments` is supported only with its standalone in-process
legacy-map activation model. Its manager verifies artifact plus deployment intent,
fresh trust/clock/declaration pins, stages immutable revisions, and uses exactly
one **agentstore** callback/record for startup and publication. Generic reload,
watcher and SIGHUP bypasses remain refused. Existing bootstrap, restart, renewal,
rollback, replay and publication fault tests are retained.

Untested combinations fail before side effects:

- Signed daemon + Host (with or without generations): refused before opening
  state, outputs, monitors or child processes.
- Signed assignment + atomic generations: refused in both daemon configuration
  and enforcer startup/activation, before policy I/O, kernel Prepare or callback.
- Main's `Options.SignedAssignment` and the prior embedded metadata seam
  `Options.ExpectedAssignment` cannot both be supplied. The latter retains its
  reviewed source-validation API but does not enable signed-daemon Host support.

Required signed default-deny needs a real initialized `LSMBlocking()` status,
effective blocking request, `RequireLSM`, a capable map and complete effective
domains. Loaded-but-audit-only hooks still cannot satisfy the claim.

## Integration regressions retained/added

- Real signed daemon/HTTP/store tests exercise sole-agentstore bootstrap,
  activation, restore, renewal, rollback and failures on the common backend seam.
- Public CLI rejects signed+Host/atomic configurations before privilege or
  assignment-state/output setup; bootstrap tests use a nil manager and invalid
  bundle to prove the gate precedes decode/store access.
- Enforcer tests refuse unsupported combinations before injected platform/policy
  I/O and refuse signed activation before generation Prepare/commit.
- Pool assignment checks and canonical source observations remain bound to their
  original digest/ABI/build data after runtime reload and member replacement.
- The Host compiler parity test now checks **compiler-produced** canonical build
  claims against `compiler.Identity`; it no longer appends a duplicate section.
  Build label, signature or assignment digest still does not grant cache trust.
- The imported signed failed-drain test uses the existing checked in-process
  test accessor for its timeout; no evaluator interface method was broadened.

## Separate Clang 18/21 generation fix

PR53 carries the exact generation-map implementation affected by Clang 21's BTF
forward-declaration loss. Reviewed **`f4bafce`** and **`6efd049`** apply without
conflict as separate commits **`b1afd97`** and **`1612018`**. They preserve the
canonical 16-byte generation value, 288-byte key and 416-byte event layout while
using the complete anonymous typedef, importing reviewed regenerated objects and
testing every little/big-endian object without loading BPF.

The Clang **18/21** CI matrix, authenticated LLVM 21 package provisioning, strict
VM oracle and failure artifact requirements are retained. No kernel gate is
removed or silently changed into a skip. This environment has Clang 23, not the
requested 18/21 executables; offline object ABI validation is not claimed as local
18/21 regeneration or live VM evidence. No BPF objects were regenerated ad hoc.

## Validation record

Validation uses **Go 1.26.11**, `GOMAXPROCS=2`, `-p 2`, Cargo required for real
compiled policies. Results and log paths are appended after the settled full/race
checks. Early focused tests overlapped active work elsewhere and saw ordinary
50ms evaluation/initialization deadline failures; no production deadlines were
relaxed and no failed run is counted as passing evidence. Lint initially found
another runner's global lock and was rerun using `--allow-serial-runners`, not
by disabling the lock or changing another worktree.

Settled code checkpoint **`809a3ad`**:

- `WARMOR_REQUIRE_CARGO=1 go test -count=1 -p 2 ./...`: pass, fresh full execution
  after the manifest compatibility correction; no passing claim for the earlier
  compiler-pin failure.
- `WARMOR_REQUIRE_CARGO=1 go test -race -count=1 -p 2 ./...`: pass on the same
  settled code checkpoint, including standalone signed and Host/manifest tests.
- Focused signed relay/bootstrap/gates, pool identity, compiler claims, real Host
  compile deadline and metadata parity tests under `-race -count=3`: pass.
- Complete manifest tests with `WARMOR_REQUIRE_CARGO=1 -race -count=1`: pass after
  the explicit compiler-7 compatibility review; no composition tests are skipped.
- Full `go vet -p 2 ./...` and configured golangci-lint v1.64.8 (concurrency 2,
  serial runner lock, Go 1.26.11 selected): pass. The lint binary reports its own
  build toolchain as Go 1.27.2, not the analyzed repository toolchain.
- Native builds of all commands: pass. Windows amd64 enforcer and Darwin arm64
  daemon test binaries cross-compiled: pass (not native OS execution).
- Integration-tagged ebpf/outcome packages built with `-run '^$'`: pass.
  Offline strict generation/VM harness oracle tests under the race detector:
  pass. No enforcing fixture or VM is run by these commands.
- Both-endian embedded ELF/Go generation ABI checks: pass. Reviewed objects and
  BPF source match `f4bafce` exactly, with no ad-hoc regeneration or weakened gate.
- `git diff --check`: pass. No `go.mod`/`go.sum` delta; the host path, generation
  lifetime, shutdown, cache-trust, private outputs and snapshot lease-clearing
  implementations are retained from the reviewed source checkpoint.

Logs: `/tmp/opencode/supervised-signed-main-{full,race,focused-race,manifest-race,`
`object-abi,gates,vet,lint,build,windows,darwin,integration-build}.log`.
No push, PR/main coordination action, source-branch edit, VM-owner worktree edit,
live cluster, host-wide enforcement or native cross-platform execution occurred.

## Refresh to externally merged PR41 main `ce1d5ab`

Merge **`3fa712a`** has parents `745231f` and **`ce1d5ab`** (PR41 exact checkpoint
`1ea758e`). Four manifest files conflicted: `README.md`, `bundle.go`,
`cargo_test.go`, and `manifest.go`. Resolution retains main's explicit compiler-7
static identity/ABI/deny-first review and compiled path/endpoint boundary tests,
plus this branch's canonical `policybuild` claims assertion and explicit
old/future-version refusal. The two imports required by those separate checks
are both present. The compiler remains 7; exact policy paths/keys stay 127/288.

Main's private guest recording helpers and event-outcome VM fixtures, and its
scheduling-independent cache/statistics tests, are imported. Two new test-only
`e.evaluator.SetTimeout` calls are adapted in **`162587d`** to the existing checked
in-process accessor because this branch uses the common evaluator interface.
Their five-second fixture budgets/assertions are unchanged; production limits
and Host behavior are untouched.

There is **no production code delta** from `745231f` in Host metadata/trust,
signature/absolute-path staging, effective initialized blocking, signed mode
guards/sole-agentstore commit, private-output snapshot clearing, readiness,
generation old-host leases, reader Stop/Close or BPF layouts. The separately
reviewed Clang/BTF fixes remain included without duplication. No gate is removed.

External PR41 kernel/VM results reported by its owner are not a local Host
whole-daemon result. Local validation remains unprivileged tests and offline
gate/oracle checks; the separate Host VM packaging owner keeps its own worktree
and review pin. No edits are made there.

Validation is one **sequential** run of fresh full tests, full race tests, vet
and lint, with Go **1.26.11**, `GOMAXPROCS=2`, package parallelism **`-p 2`** and
Cargo required. The two test accessor edits landed before the run built the
enforcer package; the remaining race/vet/lint phases use settled code `162587d`.
No production code changed during validation. Logs use
`/tmp/opencode/supervised-ce1-{full,race,vet,lint}.log`.

- Sequential phase 1, `WARMOR_REQUIRE_CARGO=1 go test -count=1 -p 2 ./...`:
  pass, including the imported compiler-7 static identity and private evidence
  helper tests. No skip/timeout assertion or production limit was relaxed.
- Sequential phase 2, `WARMOR_REQUIRE_CARGO=1 go test -race -count=1 -p 2 ./...`:
  pass, including signed mode, real Host deadlines/shutdown, private recordings
  and manifest tests.
- Sequential phase 3, `go vet -p 2 ./...`: pass.
- Sequential phase 4, configured golangci-lint v1.64.8 with
  `--allow-serial-runners --concurrency 2 --timeout 5m ./...`: pass.
  The complete sequential pipeline exited successfully; no overlapping local
  validation pipeline was started and no kernel/Host VM execution is implied.
