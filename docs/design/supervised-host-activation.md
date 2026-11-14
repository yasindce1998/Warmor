# Supervised host activation: current-main integration

Status: **working experimental opt-in, off by default, Linux only**. This is a
candidate integration for review, not a production sandbox, packaged-isolation
release, or whole-daemon VM readiness claim.

## Branch and review ancestry

Persistent worktree `.worktrees/supervised-host-integration`, branch
`feat/supervised-host-activation`, starts at reviewed shutdown checkpoint
`31fcc38`. `git fetch origin` confirmed current main at **`be15f27`** (PR50,
following PR39 privacy and PR40 scope, PR42 release and PR45 host). Merge
`2ad532a` has exactly parents `31fcc38` and `be15f27`.

There were **no textual merge conflicts**. Earlier integration merges already
preserved the canonical metadata/protocol-v2 host and PR40/PR45 ancestry. Main's
actual delta was privacy/recording/tool contracts and generic framing; no reviewed
backend, generation, blocking-status, platform-reader or BPF file changed in this
merge. Original review branches remain at `cee01e7`, `9d7183f` and `31fcc38`.
No rebase/squash removed that history.

## Working opt-in configuration

Build the separate trusted host explicitly (example destination only):

```sh
go build -o /trusted/install/warmor-policy-host ./cmd/warmor-policy-host
sha256sum /trusted/install/warmor-policy-host
```

The runtime invocation shape is below; these commands were **not** used to run
host-wide hooks during integration tests:

```sh
warmor-daemon --policy /physical/revision/module.wasm \
  --verify-key /physical/trust/artifact.pub \
  --experimental-supervised-policy-host \
  --policy-host /trusted/install/warmor-policy-host \
  --policy-host-sha256 <lowercase-sha256-of-installed-host>
```

The compiled policy must have a valid detached `<policy>.sig`. The host must have
a clean absolute executable path, trusted owner/mode/parent directories and an
exact digest pin. Updates install by atomic rename, not in-place modification.
There is no PATH search, shared compilation cache, daemon self-exec, unbounded
worker retry/respawn or in-process fallback. Relative policy paths/revision aliases
are converted to absolute **before** resolution and then strictly staged;
that policy-input handling does not apply to recording output paths.

Standalone reload retains its existing explicit activation behavior. Unsigned
fleet deployment intent can still carry artifact-signed candidates through the
single fleet publication owner; fleet local SIGHUP reload is refused before its
enforcer callback. The separate experimental generation path adds
`--experimental-atomic-generations --require-lsm` without changing the default
legacy activation path. It preserves captured old-event leases, single-reader
flush/fence, durable pending callback ownership, and old-host drain/reaping.

Kernel *blocking* additionally needs `--lsm-enforce`; `--require-lsm` only requires
loaded hooks. Signed required-default-deny checks require both the effective
blocking request and successfully initialized `LSMBlocking()` status. Enforcer
readiness accepts a live supervised host without a parent pool, but still checks
event-loop/capture/scope health. Worker protocol readiness is a separate bounded
metadata handshake, not remote deployment acknowledgment.

`--policy-declaration-digests` is optional administrator-owned attestation for
exact deterministic/exhaustive module declarations. Default empty disables
supervised decision/kernel caches and static default-deny authorization. Never
derive these pins from downloaded assignments, signatures or raw metadata flags.
Effective `policymeta.Source` methods, not `Metadata()` observations or compiler
display labels, authorize optimizations. Exact process paths remain **127 bytes**
and kernel policy keys remain **288 bytes**. No arbitrary module decode, custom
section parse, validation or compilation runs in the parent host-mode path.

`Options.ExpectedAssignment`/`ActivateAssignment` consume actual child-observed
ABI/build metadata. The separate signed-mode daemon/client is not imported here;
**signed-assignment + atomic-generation combinations remain explicitly rejected**,
including supervised mode. Detached artifact signatures with unsigned fleet
intent are not that gated combination. `--validate-policy` is still explicitly
the legacy in-process validator and refuses every supervised backend flag rather
than silently loading the candidate in the parent.

## Privacy/framing interaction and regression

Main's private output contract remains unchanged: private file recordings retain
full replay inputs, default stdout/JSON webhook exports omit `policy_input`, and
0600/0700 owner/no-follow checks apply to recording files/directories. Recording
outputs never use policy-input `EvalSymlinks` normalization. Symlink parents,
hard-linked/nonregular files and unsafe owners/layouts remain rejected. Windows
NTFS owner/DACL/reparse behavior is main's implementation, not native execution
evidence from this Linux integration.

One semantic interaction was found despite the conflict-free merge: main's new
owned replay snapshot shallow-copied `GenerationContext` and `DispatchBarrier`.
Their `json:"-"` tags protected serialized output, but custom in-memory sinks could
retain or complete a live lease or signal a fence. Follow-up `0fb1632` explicitly
clears both pointers in the snapshot while retaining numeric `PolicyGeneration`,
and tests that original ownership and mutable argv isolation remain intact.

A combined real-host/fake-kernel test captures an old generation event, processes
it in the new generation's durable callback, and records both the old allow and
new audited denial. Private rotation must preserve full argv with 0600 files;
default loopback webhook export must redact it without rewriting historical
decisions/outcomes. The test also proves no live lease/fence is JSON-replayed.
Additional tests preserve the no-follow output-parent rejection and ensure main's
framing-first multi-document rejection reaches the legacy policy validator.
Supervised mode still rejects YAML rather than invoking that parser/toolchain.

## Remaining release gates

Actual whole-daemon **Host** VM coverage must be added and run separately on
supported kernels. It must include clean SIGTERM/reader shutdown from `5aa4556`,
generation drain with active old/new work, child compilation timeout/crash,
fail-closed/default-deny and pending durable activation recovery. Cleanup SIGKILL,
unprivileged fake-platform success, or separate kernel API fixture success must
not substitute for that gate. No VM execution is claimed here.

Host release/container/service packaging, signed+atomic commit/recovery integration,
native non-Linux host support, calibrated RSS/cgroup limits and native-worker
compromise sandboxing remain outside this checkpoint. Dynamic cgroup discovery
still has lag and non-atomic multi-map updates; this integration does not add an
atomic policy-and-scope transaction. Review details remain in
`supervised-evaluator-integration.md`, `supervised-evaluator-main.md` and
`supervised-evaluator-shutdown.md`.

## Local validation record

Code checkpoint `0fb1632`, Linux unprivileged, **Go 1.26.11**, `GOMAXPROCS=2`,
package parallelism **`-p 2`**:

- `WARMOR_REQUIRE_CARGO=1 go test -count=1 -p 2 ./...`: pass, fresh execution;
  actual compiled-policy tests are required rather than skipped.
- `WARMOR_REQUIRE_CARGO=1 go test -race -count=1 -p 2 ./...`: pass on the same
  settled code checkpoint, including the merged recording/privatefile tests.
- `go vet -p 2 ./...`: pass.
- All supervised host, scope/drain/shutdown regressions under
  `go test -race -count=5 -p 2 ./internal/enforcer ./internal/platform
  -run 'TestSupervised|TestGeneration.*(Stop|Cancel|Scoped)'`: pass.
- Actual child compiler-heavy deadline tests in enforcer and policyhost under
  `-race -count=3`: pass. The active generation continues evaluating during
  candidate compilation; the killed child is reaped and bounded host capacity
  is reusable. No sleeping/mock worker substitutes for compiler work.
- `golangci-lint v1.64.8 run --concurrency 2 --timeout 5m ./...`: pass with Go
  1.26.11 selected; the lint executable itself reports a Go 1.27.2 build.
- Windows amd64 enforcer and Darwin arm64 daemon test binaries cross-compiled:
  pass. This is build validation, not native Windows/macOS execution or ESF proof.
- Native Linux daemon/host builds and Windows amd64 privatefile test-binary
  cross-compilation: pass. No binaries were installed or run with security hooks.
- Integration-tagged ebpf/outcome packages built using `-run '^$'`: pass, with
  no enforcing test execution.
- `git diff --check`: pass. Backend/Source trust, initialized blocking status,
  path normalization, readiness, reader shutdown and generation ownership code
  have no source delta from `31fcc38`; only combined tests are added there.
  No BPF C/object or dependency-file delta from that review pin.

Logs use `/tmp/opencode/supervised-host-{full,race,focused-race,merge-focused,`
`real-compile-deadline,vet,lint,native-build,cross-windows,cross-darwin,`
`cross-privatefile,integration-build}.log`. No original review/source/main edits,
pushes, PR actions, host-wide hooks, cluster deployment or VM execution were made.
