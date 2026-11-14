# Supervised host packaging/outcome checkpoint

Base: PR #53 `feat/supervised-host-activation` at **5010198** (preserved;
includes main conformance **be15f27**). Work lives on
`test/supervised-host-outcomes` in `.worktrees/supervised-host-vm`.

## Implemented

- Linux archive helper/public digest metadata; Docker daemon copies the helper
  from the same build stage to a physical root-owned libexec path. No backend
  default change, embedded key, secret, publish operation or release tag.
- Explicit bounded `--policy-host-load-timeout` (5s default, positive through
  10s) for real compiler/initialization failure tests, not a sleeper fixture.
- Optional signed whole-daemon host fixture and separate legacy/atomic CI matrix.
  Existing allow/first-exec EPERM/audit/nonroot actual-SIGKILL oracles remain;
  extra probes cover LKG during/after rejected child loads, candidate reaping,
  terminal-host cached-allow refusal and watcher-load SIGTERM cancellation.
- Exact prepared binary hashes, same embedded revision/toolchain/architecture,
  installed host pin, reviewed test-only declaration digests, ephemeral in-memory
  signing keys, strict nested PASS counts and the existing VM guard/launcher.
- Old-host leases/maps-until-Close continue to be checked by deterministic real
  host/fake-kernel tests; process-level VM tests do not claim to instrument every
  kernel teardown instant. Helm wiring deliberately deferred to its signed
  configuration owner; no new hostPath or default-on chart feature.

## Local validation (Go 1.26.2, Linux amd64)

Passed:

- Offline Python release/package/mock build tests: **24 tests**.
- `bash -n` for edited runners/packaging and actionlint for the new workflow.
- Focused normal tests for supervised enforcer/host and real init-loop deadline.
- Focused race tests (`GOMAXPROCS=2`, `-p 1`) for `TestSupervised*` and
  `TestInitializationLoopDeadline*` across harness, daemon, enforcer and host.
- Tagged integration compile and offline workflow/VM-guard tests; tagged and
  untagged affected-package golangci-lint.
- Signed host **build-only** preparation in legacy and atomic modes, retaining
  daemon/host binaries, signatures/public key, module fixtures and hash manifests.
- Windows amd64 and Darwin amd64 daemon test-binary cross-compilation only.

The broad normal suite failed two existing in-process NetFilter policy-evaluation
tests; broad race execution also failed existing in-process evaluation deadlines
and host CPU/load-phase deadline tests during substantial concurrent machine
load. No race-detector warning was observed in that output. The two normal-suite
failures and CPU/compile deadline cases passed a smaller serial race recheck.
These broad runs remain **failed**, not retrospectively green; no deadline,
assertion, existing #41/#51 gate or BPF source/object was relaxed to hide them.
Earlier 120s tool-command limits also interrupted broad/cross builds; longer
cross-build reruns completed successfully.

Go 1.26 VCS discovery ignored the worktree `.git` file and initially stamped the
outer checkout revision. The build-only provenance assertion rejected it. The
runner now explicitly binds `GIT_DIR`/`GIT_WORK_TREE` to its own checkout and the
same-revision assertion passes; it is not weakened or bypassed.

## Not yet established

**No VM or enforcing daemon was run locally.** CI must execute both real signed
host map modes, retain successful non-skipped outcomes and review failures before
any acceptance/default-backend claim. No Docker image build/runtime, native
arm64 host bootstrap, blocked-seccomp/container matrix, atomic install/upgrade
deployment, native Windows/macOS execution, native-compromise sandbox, sustained
resource/event-loss or power-loss continuity evidence is supplied here. Existing
#41 and #51 VM requirements stay independent; packaging cannot replace them.
