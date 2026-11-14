# Supervised evaluator integration with main PR40

Status: **experimental, off by default, not production sandbox readiness**.

Worktree `.worktrees/supervised-evaluator-main`, branch
`feat/supervised-evaluator-main`, starts at reviewed source `cee01e7` and merges
the pinned main commit `09fdce9`. Merge commit `02c8258` has exactly those two
parents. The source branch/worktree remains unchanged at `cee01e7`; this is not a
merge into main or remote publication. See `supervised-evaluator-integration.md`
for the underlying evaluator and signed/atomic combination gates.

## Actual textual conflicts

There were **eight** conflicted paths:

- `internal/enforcer/enforcer.go`: conflicting imports around main's metrics bind
  address support. Retain `net`/`strconv`, new cgroup/runtime options, metrics
  readiness wiring, and the supervised backend lifetime owner.
- `internal/platform/linux.go`: combine main's exact cgroup scope and injectable
  monitor readers with the generation capture/single-reader drain state. Preserve
  readiness notification on real reader failures; normal wrapped `ErrFlushed`
  remains a queue barrier, not a capture failure. Main's shutdown reader
  interruption closes readers without detaching protection, while activation
  still uses `FlushLSMEvents` and the existing single-reader fence.
- `internal/policyhost/{host.go,protocol/protocol.go,protocol/protocol_test.go,`
  `worker/worker.go}`: add/add from main's older PR45 implementation versus the
  reviewed protocol-v2 metadata backend. Keep the reviewed source versions,
  including digest trust, bounded canonical metadata readiness and terminal host
  health; no downgrade to v1.
- `docs/design/{supervised-policy-host,wasm-compilation-isolation}.md`: keep the
  explicit experimental integration status and limitations, not main's stale
  statement that no enforcer adapter exists.

`internal/compiler/build.go`, `internal/ebpf/policy_map.go`, and daemon flag
wiring **did not conflict textually**. The compiler Context/cancellation and
failed-crate cleanup code is identical to main. The policy-map change relative
to reviewed source is only main's safe cgroup filter replacement; the existing
**288-byte exact keys** and **127-byte policy-path contract** remain unchanged.
There is no BPF C/embedded-object or dependency-file delta from `cee01e7`.

## Semantic integration fixes and combined regressions

Main's `Enforcer.Ready` initially required a nonnil `*wasm.Pool`, incorrectly
rejecting every valid supervised host. It now accepts a live host without a
parent runtime/pool, rejects a terminal host, and still requires an active event
loop, uncanceled context and healthy optional platform readiness source. Legacy
in-process readiness retains its pool check. Protocol-v2 child readiness and
HTTP/runtime readiness are separate APIs: neither is remote exact-digest node
attestation or proof of durable assignment acknowledgment.

One newly imported failed-reload test directly called `e.evaluator.SetTimeout`;
the evaluator is now an interface. It uses the existing checked test-only
in-process accessor, preserving its bounded setup deadline and assertions.

All four Linux monitor paths preserve raw kernel timestamp and scope filtering
**before** acquiring a generation lease. Combined tests check outside-scope
events never acquire leases; LSM IDs survive capture while tracepoints capture
current at dispatch; and delivered leases complete exactly once. A dedicated
scope-churn/drain test verifies:

- rejected reconciliation keeps the previous accepted userspace scope and
  withdraws platform readiness;
- successful reconciliation restores readiness without relabeling/releasing
  already queued old-generation work;
- empty scope filters subsequent samples but cannot swallow a dispatch fence;
- a normal wrapped flush does not withdraw readiness;
- a real reader failure both withdraws readiness and wakes/fails generation
  drain, without starting another flush.

The existing old-host lease drain, compile-heavy child kill with concurrent
generation work, terminal noncached failures, immutable retry/uncertain commit,
fleet sole-owner local-reload rejection, and signed+atomic rejection tests remain
enabled. Main's cgroup discovery/root/reconciliation options reach platform and
container resolution; metrics bind configuration and HTTP readiness are retained.

## Limits retained, not solved

Dynamic cgroup filter replacement is not atomic across the tracepoint/LSM maps
and the accepted userspace scope. Discovery lag, partial-map errors, obsolete
kernel IDs until retry and lack of selector routing remain main's documented
limitations. A sample already admitted to the userspace queue keeps its captured
scope/generation lifetime even if later discovery removes that cgroup. This is
not a new atomic policy-and-scope transaction, instantaneous pod coverage, or
crash-continuous protection.

Compiler Context support is preserved for callers that pass one (including the
controller). Existing callers that omit it, such as legacy daemon YAML builds,
remain unbounded by that option; this integration does not silently claim a new
compiler-process boundary. Supervised mode still requires compiled signed WASM
and never routes module decoding/compilation through the parent.

The separately owned signed-mode daemon/PR49 integration is not imported by the
main pin `09fdce9`. Signed-assignment + atomic-generation startup/activation
remains explicitly rejected, including host mode. Release packaging for the host,
whole-daemon supported-kernel VM evidence and the stronger native-compromise/RSS
sandbox architecture remain open. No host-wide hooks, cluster or live enforcing
daemon are used in this integration's validation.

## Security review follow-up from source `cee01e7`

The source reviewer identified two blockers; fixes live only on this main merge
branch, leaving the review pin unchanged:

1. **Loaded hooks were mistaken for blocking posture.** `Capabilities.LSMEnforcement`
   means loaded hooks, not that `--lsm-enforce` was enabled. Required signed
   default-deny now requires both the normalized operator request and the optional
   platform `LSMBlocking()` status. Linux publishes that status only after scope
   installation and a successful enforce-toggle write. Initialization failures
   fail Load, never report blocking, and fail readiness when blocking was
   requested. A real-child/fake-platform regression reproduces the loaded,
   `RequireLSM=true`, `LSMEnforce=false` bypass with trusted complete metadata and
   rejects it before any default-deny map preparation. Tests also cover missing
   initialized status, failed toggle initialization, and successful blocking.
2. **Relative policy paths failed strict staging.** `EvalSymlinks` can return a
   relative path while `StageFile` intentionally requires a clean absolute path.
   Supervised preparation now calls `filepath.Abs` before resolving revisions,
   including candidate signature path resolution. Real-child tests cover relative
   regular paths, relative parent revision aliases and reload. Strict no-follow
   staging still rejects parent aliases introduced after resolution and symlinked
   detached signatures; the fix does not weaken the staging boundary.

Focused re-review target: reviewer session `ses_e252e37beffephzaWPKFIMdC7h`.
Fix commit `ac64c64`; follow-up `6b53f74` adds relative generation-path coverage
and removes the misleading loaded-hooks "kernel enforcement active" log. These
are ready for focused re-review; this document does not claim reviewer approval.

## Validation record

Code checkpoint `6b53f74`, Linux unprivileged, **Go 1.26.11**,
`GOMAXPROCS=2`, package parallelism **`-p 2`**:

- `WARMOR_REQUIRE_CARGO=1 go test -count=1 -p 2 ./...`: pass after both security
  fixes and the relative generation-path follow-up. This is a fresh, uncached
  test execution; actual compiler-generated policy tests are required, not skipped.
- `WARMOR_REQUIRE_CARGO=1 go test -race -count=1 -p 2 ./...`: pass on the same
  settled code checkpoint, including the real child compiler-deadline tests.
- `go vet -p 2 ./...`: pass.
- `golangci-lint v1.64.8 run --concurrency 2 --timeout 5m ./...`: pass with the
  repository configuration and Go 1.26.11 selected. The lint binary itself was
  built using Go 1.27.2, as reported by its version command.
- Focused scope/readiness/security regressions under `-race -count=5`: pass in
  enforcer/platform. The pattern includes `TestSupervisedRequiredDefaultDeny`,
  `TestSupervisedRelativePolicy`, `TestSupervisedReadiness`, `TestLSMBlocking`,
  `TestGenerationScopedQueue`, and `TestLinuxMonitorsPreserve`.
- Windows amd64 enforcer and Darwin arm64 daemon test binaries cross-compiled
  at this checkpoint: pass. No native non-Linux execution is claimed.
- Integration-tagged `internal/ebpf` and `tests/integration` packages built with
  `-run '^$'`: pass; no integration test or host-hook execution is implied.
- `git diff --check`: pass. No BPF C/object or dependency-file delta from
  `cee01e7`; PR41's 127-byte contract and 288-byte exact keys are retained.

Initial overlapping focused runs caught the imported concrete-evaluator test
call described above. One early CPU-rlimit host test lost its wall-budget race
under concurrent compilation (deadline instead of CPU-kill classification);
the fresh full run passed without relaxing that assertion or its limits. Those
early failed runs are not counted as validation. An initial optional integration
build used nonexistent `tests/outcomes`; the corrected existing package is
`tests/integration` and builds successfully.

Logs use `/tmp/opencode/supervised-main-{full,race,vet,lint,review-fixes,`
`review-repeated,cross-windows,cross-darwin,integration-build}.log`.
No original source/main changes, pushes, PR actions, live cluster deployment,
whole-daemon VM run or host-wide enforcing run was performed.
