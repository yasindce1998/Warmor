# Clean supervised Host handoff after Git fixture isolation

Status: **experimental, off by default; actual legacy and atomic Host VM CI still
mandatory before merge**. Older in-process/kernel VM successes are not Host proof.

## Clean ancestry and scope

Persistent worktree `.worktrees/supervised-host-final`, branch
`feat/supervised-host-final`, starts at reviewed **`d942187`**. It does not reset,
rewrite, or remove the old Host worktree/history/evidence. In particular,
accidental empty fixture commits `713981c` and `48295bb` are **not ancestors** of
this branch and remain preserved on the old line. Reviewed remote PR53 checkpoint
`5ed1817` is an ancestor, so a coordinator-verified ordinary fast-forward push is
possible; no force update or push is performed here.

Merge **`8469c53`** has exactly parents `d942187` and pinned main **`971471e`**
(PR47 telemetry, PR54 compiler-7 compatibility, PR55 status, PR56 deterministic
WASM fixtures). Two files conflicted:

- `internal/enforcer/enforcer.go`: reproduce only the semantic resolution from
  preserved old merge `5664f02`, retaining Host backend and legacy telemetry
  publication behavior plus unsupported overlapping-generation attribution guards.
- `internal/workload/manifest/cargo_test.go`: keep main's nil-safe canonical build
  claim checks and main's actual ABI/pool-assignment coverage. No compiler-version,
  key-size, path-size, namespace selection or artifact validation guard is dropped.

At merge time all four enforcer telemetry files matched `5664f02` exactly. Separate
commit **`7f8b35c`** makes generation + telemetry startup options explicitly reject
before platform/policy/child setup rather than silently removing the collector.
Signed mode retains main's collector seal/disable behavior. A focused regression
checks early refusal; telemetry activation under generations also refuses before
Prepare/commit, generic generation switches seal any stale collector, and old
captured work never enters the legacy single-activation collector. Legacy
drained activation still installs a prepared snapshot only at the evaluator
publication boundary, counts finalized cache hits/quality correctly, seals on
out-of-band activation and preserves snapshot sequence ownership. No deployment
evidence is inferred retroactively.

Test-only **`686eb8a`** adapts one newly imported main `SetTimeout` test call to
the existing checked evaluator accessor. The existing bounded test budget is
unchanged; no production timeout or assertion is relaxed.
Test-only **`cdb10ac`** updates the existing prepared-kernel-binary source-shape
assertion to the scoped `go_with_worktree_vcs test -c` invocation. The initial
full run found that stale literal; exact binary/object/PASS requirements are not
removed. That failed run is superseded only by a settled sequential rerun.

## Hermetic fixture and scoped VCS override

Reviewed real isolation delta `d94534b` is cherry-picked as **`e33e198`**. It is
not a merge of polluted Host history. It changes only:

- `tests/release/test_release.py`: strip inherited `GIT_*`, disable external Git
  config/templates, verify owned Git/common/worktree directories before mutations,
  restrict file remotes to a private temporary root, and test an external sentinel
  against hostile ambient redirection.
- `tests/integration/run-outcomes.sh`: scope VCS `GIT_DIR`/`GIT_WORK_TREE` to
  individual Go build/test compilation commands. Never export these across a
  complete validation runner or into unrelated release fixture processes.
- `tests/integration/policy_host_workflow_test.go`: assert that scoped provenance
  shape and forbid global Git override exports.

The independently reviewed main-based generic fixture branch (`554ab91`) can
land separately; this branch does not change its review source or import the
old accidental commits. Python packaging tests here run **only in an external
copied tree**, from an owned cwd, with sanitized subprocess environment and
`PYTHONDONTWRITEBYTECODE=1`. Before/after hashes cover the common Git config,
HEADs/indexes and refs to prove no shared repository mutation during the tests.
No shared config, user identity, or tracking refs are repaired by this task.

## Reviewed Host contracts retained

The packaging/phase-proof source `d942187`, original `399f605` and `aaf328e`
owner branches/worktrees stay frozen. The clean branch retains:

- the required legacy/atomic artifact-signed Host workflow matrix and strict
  no-skip/exact-PASS/failure-evidence oracles;
- held-load proof with an attributed uncached allow and fresh confirmation before
  worker release, plus independent real compilation/init deadlines and reaping;
- test-only phase controls excluded from normal/release/Docker builds;
- initialized blocking **and** effective operator request, relative policy Abs
  before resolution, strict no-follow signature/executable/private output checks;
- canonical Source trust pins/ABI/build claims and zero parent WASM decode/compile;
- signed daemon + Host/generations refusal and sole-agentstore standalone signed
  publication, unchanged from the main port;
- terminal-child cached-allow refusal, old-generation leases, reader close before
  join, maps/hooks until Close, and owned Host reaping before resource teardown;
- 288-byte exact keys, 127-byte policy paths, private guest recordings and export
  only after daemon Wait, no live lease/fence pointers in recording snapshots.

No local VM, host attachment, Docker publication, release/tag, push or native
Windows/macOS execution is used by validation. Cross-compilation and build-only
artifact preparation must not be promoted to a claim of actual outcomes.

## Validation

Settled code checkpoint **`cdb10ac`**, Go **1.26.11**, `GOMAXPROCS=2`, `-p 2`,
Cargo required. A single sequential pipeline performs fresh full normal/race,
vet/configured normal+phase lint, tagged real-worker phase race tests,
integration compile-only, external hermetic Python packaging, shell/actionlint,
legacy+atomic Host build-only preparation, normal-binary phase-marker exclusion
and Windows/Darwin test-binary cross-compilation. Results/log hashes are recorded
after completion, not inferred from earlier dirty-history runs.

Focused telemetry/signed race tests pass. Exact Go 1.26.11 formatter reports all
112 changed Go files formatted. Initial focused compilation caught the imported
concrete-evaluator timeout call fixed in `686eb8a`; that failed run is not counted
as validation and no deadline semantics were changed.

Logs use `/tmp/opencode/supervised-host-final-*.log`; sequential statuses are in
`supervised-host-final-validation-status.json`, and external packaging before/
after Git hashes are in `supervised-host-final-git-metadata-proof.json`.

### Completed local result

The settled **`cdb10ac`** pipeline completed successfully, sequentially:

- Fresh full normal and full race suites, Cargo required: pass.
- Full vet, repository-configured normal lint and
  `integration,policyhost_phaseproof` affected-package lint: pass.
- Tagged real-worker phase-proof release/cancel/deadline/reap race tests: pass.
- Integration-tagged ebpf/outcome packages with `-run '^$'`: pass, compile only.
- External-copy Python packaging: **26 tests pass**. All **171** captured shared
  Git metadata hashes are identical before/after; no HEAD/config/index/ref was
  mutated. Bytecode writing was disabled and subprocess Git environment sanitized.
- Shell syntax/actionlint and both **legacy and atomic Host build-only**
  preparations: pass. Exact same-checkpoint binary/profile/helper pin assertions
  passed; artifact directories are recorded in the build logs.
- Normal Linux daemon/helper builds: pass; test-only phase environment and
  held/confirm/release protocol byte markers are absent from both binaries.
- Windows amd64 enforcer and Darwin arm64 daemon test binaries cross-compiled:
  pass. This is not native OS execution or fresh-head CI evidence.

These results do not satisfy the mandatory actual legacy+atomic Host VM matrix.
The old 36-test legacy in-process daemon result is not substituted. No local VM,
host attachment, Docker/release publication, push or shared-repository repair was
performed. The old branch still contains the preserved incident evidence/empty
commits and must not be used as the clean publication source.
