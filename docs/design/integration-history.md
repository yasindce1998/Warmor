# Integration and review history

This page consolidates historical, frozen integration and review records. They
are **audit evidence**, not current design specifications: each entry is pinned
to an old commit, records conflict resolutions and validation results at that
point, and must not be read as a claim about current main or as a production or
CI clearance. Current contracts live in [STATUS.md](../STATUS.md) and the live
design docs it links (for example [generation activation](generation-activation.md),
[supervised host activation](supervised-host-activation.md),
[authenticated node receipts](authenticated-node-receipts.md) and
[policy activation](policy-activation.md)).

Log paths under `/tmp/opencode/...` are ephemeral historical artifacts; the
narrative and pins below are the durable evidence.

## Index

| Area | Source | Base → head / reviewed pins | Evidence status |
|---|---|---|---|
| Compiler subprocess / signed main | PR #52, #60 | `98d2b90` → `33151a5`; `ce1d5ab` → `4290664`; `fd83a1d` → `dd38e91` | Local tests/lint passed; fresh remote CI still required |
| Controller / Kubernetes safety | PR #31, #32, #30, #34 | `9ea4594`, `1e49aa7`, `78471f6`; merge `1ffc00f` | Clean sequential runs passed; no cluster or live BPF |
| Durable fleet and activation | PR #31, #38 | `9ea4594` → `1e49aa7`; review `b80dfef` | 74.9% coverage; Windows/macOS native reruns still required |
| Signed assignments onto main | PR #49, #40 | `9297209`; `8634b22` → `09fdce9`/`061685e` | Local tests and cross-compiles passed; no native OS execution |
| Node receipts onto `971471e` | PR #57, #47 | `40de5eb` + `971471e` | Local full/race/lint and 10 repeated race runs passed |
| Supervised host clean handoff | PR #53 | `d942187` + `971471e`; merge `8469c53`; `cdb10ac` | 26 packaging tests, 171 hash comparisons; VM matrix still mandatory |
| Supervised host outcome packaging | PR #53 | `5010198`; `399f605` lineage | Broad normal/race runs **failed** under load; no VM/enforcing daemon |
| Held-load concurrency proof | PR #53 | `399f605` → `5ed1817` | Focused probes only; no broad-green or VM claim |

---

## 1. Compiler subprocess / signed-main integration

### Review scope and conflicts

- Merge `fd83a1d` into `dd38e91` contained only main's status/readiness docs and
  PR #56 WASM fixture changes. The single conflict was the equivalent comment
  above `TestPoolReplacementPinnedToOriginalModule`; main's entire
  `initialization_test.go` was kept, including its stricter allocator-specific
  assertions. No production or timeout-budget changes.
- Merge `ce1d5ab` into `4290664` was automatic (no textual conflicts), bringing
  main's kernel/manifest integration, the compiler-7 manifest pin and
  timing-fixture corrections. The earlier compiler-pin blocker below is
  historical and resolved by main.
- Merge `98d2b90` into compiler tip `33151a5` had one textual conflict: the
  `internal/compiler/build.go` import block. `policybuild` from main was
  retained and the old `time` import dropped, because process ownership and pipe
  deadlines live in the subprocess helper. The signed-main metadata append
  merged without conflict.

### Preserved contracts

- `BuildOptions.Context`, bounded target discovery, the shared captured-output
  budget and the pre-publication cancellation check remain active: a timed-out
  or over-output Cargo process cannot become a successful artifact by writing a
  valid WASM file and exiting zero.
- `Build` appends `policybuild.Metadata{Compiler: Identity, DefaultAction: ...}`
  after Cargo succeeds and before returning success. `Version` is `7`,
  `Identity` is `warmor-yaml/7`.
- Production subprocess helpers are byte-for-byte unchanged from `33151a5`:
  Linux/Darwin own a fresh process group, use non-reaping `waitid`, check
  ownership before signaling and signal before reaping; Darwin's zombie-only
  `EPERM` and auto-reap checks remain. Windows remains parent-only.
- Signed assignment verification, allowed compiler/digest checks, durable
  authorization, activation/publication and pool-captured artifact identity come
  from main. Metadata is an artifact-signed declaration, not proof of trusted
  compiler provenance.

### Test adjustment and validation

The injected fake Cargo was changed from emitting the invalid string
`fake wasm` to a valid empty WASM module; flood/slow-output fixtures also write
valid WASM so their "destination untouched" assertion is stronger. Main's
`TestCompiledAssignmentRetainsBuildContextSafeIdentifierAndMetadata` loads the
built artifact, constructs a pool and checks digest, ABI 3, compiler-7 identity
and deny posture.

Validation used Go 1.26.11 with `GOMAXPROCS=2`, package parallelism `-p 2` and
`WARMOR_REQUIRE_CARGO=1` for tests:

```sh
GOTOOLCHAIN=go1.26.11 GOMAXPROCS=2 WARMOR_REQUIRE_CARGO=1 go test -p 2 -count=1 ./...
GOTOOLCHAIN=go1.26.11 GOMAXPROCS=2 WARMOR_REQUIRE_CARGO=1 go test -race -p 2 -count=1 ./...
GOTOOLCHAIN=go1.26.11 GOMAXPROCS=2 GOFLAGS=-p=2 golangci-lint run --concurrency=2 --timeout=5m
```

Native Darwin regressions and actual Cargo/WASM contracts passed for `d05496b`
(26 checks); `33151a5` had 26 checks before this merge. Those are historical
results, not evidence that the merge commit passed native CI. The focused
signed/Cargo/metadata selection passed three times with real Cargo. An initial
run without a `GOMAXPROCS` cap hit unrelated 30/50 ms WASM initialization and
evaluation deadlines under host load; no deadline settings were changed.

### Historical blocker (resolved by `ce1d5ab`)

At `98d2b90`, `manifest.SupportedCompilerVersion` was pinned to `"6"` while
signed main had bumped `compiler.Version` to `"7"`, so the full manifest suite
rejected setup with `unsupported manifest version, generation, compiler,
composition or posture`. This integration did not weaken the fail-closed check;
the workload owner reconciled the explicit pin. A full non-race run also hit
`TestHandleEvent_PolicyLog`'s 50 ms evaluation deadline and
`TestCPURlimitKillsOwnedWorker`'s wall-clock deadline under shared-host load.
No production or test deadlines were edited.

---

## 2. Controller / Kubernetes safety integration

Starts at `origin/main` `9ea4594`; after combining the controller and Kubernetes
tasks, main `1e49aa7` (PR #31 signaling/outcomes) was incorporated. Worktree
`.worktrees/controller-k8s-integration`, branch
`fix/k8s-controller-safety-integration`; no push, PR or main merge was part of
this work.

### Imported commits

| Original | Cherry-pick | Purpose |
|---|---|---|
| `625c4ba` | `46a6f0e` | Compiler subprocess cancellation and failed-crate cleanup |
| `5c76e19` | `6d1c695` | Durable accepted-source journal and verified publication |
| `d68b86e` | `c4918df` | Controller restart/failure/identity tests |
| `7389eed` | `33444b5` | Publication-only status and recovery documentation |
| `ee96d4d` | `63ca5b3` | Immutable publication, snapshot privacy and scope tests |
| `a2bea94` | `52d4b42` | Exact pod cgroup reconciliation and local runtime readiness |
| `a7a29f0` | `7577fb9` | Validated chart posture and selected-policy binary deployment |
| `1da0e2c` | `5e6ae44` | Scope recovery and cluster-free deployment guard tests |

All eight applied without textual conflicts. Merge `e25546c` incorporated
`1e49aa7` cleanly. Merge `1ffc00f` incorporated main `78471f6` (PR #32 isolated
sinks, PR #30 dashboard safety, PR #34 canary analysis); its only conflict was
the daemon flag declaration block — both dashboard bind/auth flags and the
metrics/cgroup flags were retained.

### Follow-ups and resolutions

- Kind applies the additive CRD before controller upgrade and waits for both
  `phase=Published` and `Published=True`, never `Applied=True`. The aggregate
  audit-decision counter is a smoke signal, not authenticated digest evidence.
- CRD migration contract tests check serialized status field types, retained
  legacy fields/phases, condition enum and status subresource. No live admission
  or pruning migration was run.
- A real cargo/WASM test serializes the accepted-source journal, restarts with
  an invalid update and unproven legacy application status, evaluates retained
  deny semantics, then recompiles with another source and checks that deny.
- Real YAML/WASM deploy-helper tests validate exact artifact bytes, the
  content-addressed ConfigMap, mount reference, validator and daemon paths using
  kubectl **client** dry-run and Helm rendering. They never deploy a DaemonSet.
- Controller port 9091 serves real liveness, recent-successful-local-reconciliation
  readiness and private-registry metrics; probes, pod scraping and ingress are
  wired separately from daemon metrics. Reconcile failures, staleness and
  shutdown withdraw readiness; a healthy controller is not node-applied proof.
- The daemon projection includes only `policy.wasm`, not accepted-source history.
- Any non-nil selector (including `{}`) stays Pending; tests cover new sources
  making no contribution and restart retention of an old accepted unscoped
  generation. This does not enable selector enforcement.
- All four Linux monitor loops retain raw `KernelTimestampNS` through delivery;
  missing timestamps remain zero. Independent review found wrapped `ENOENT`
  misclassified by `os.IsNotExist` after `ResolveCgroupID`; discovery now uses
  `errors.Is(err, fs.ErrNotExist)`.

### Validation and boundaries

Runs used `GOMAXPROCS=2`, `GOFLAGS=-p=2`, `TMPDIR=/tmp/opencode` and
`WARMOR_REQUIRE_CARGO=1`, with `go test`, `go test -race`, `go vet`, `bash -n`
on the three scripts and four strict `helm lint` profiles (default, controller,
enforcement values, controller+enforcement). The only Helm advisory was the
recommended chart icon. Final settled-tree runs passed and were rerun after
merge `1ffc00f`; an earlier background race invocation overlapped the requested
main merge, produced mixed-tree build failures and is **superseded**, not counted
as passing evidence. No cluster was created/contacted and no live daemon/BPF
enforcement ran. Real-node CNI, cgroup inode identity, PID signaling and LSM
outcome gates remained unverified.

### Coordinator handoff / unresolved work

- Node acknowledgement: no authenticated per-node exact-digest ack path;
  `Applied=Unknown`, no `nodesApplied`/`lastApplied`, no active digest.
- Signing: mutable controller ConfigMaps are unsigned; SHA-256 is integrity, not
  writer authentication. Cache eviction and leader election remained open.
- Scoping: auto includes Warmor/system pods and has discovery lag; selectors stay
  Pending; source namespacing is not workload isolation and map updates are not
  atomic across maps.
- Activation was excluded from this integration and had to be re-tested against
  its overlapping daemon/enforcer changes.
- Independent owner review reported no new severe controller blockers, not an
  unconditional clean bill of health.

---

## 3. Durable fleet and activation integration

Branch `fix/durable-policy-activation`, worktree
`.worktrees/fleet-activation-integration`; started at `9ea4594`, then merged
`1e49aa7` (PR #31). No source task branch was changed; no push, PR, main merge,
live cluster or host-enforcing daemon was used.

### Cherry-picks

| Source | Integrated | Subject |
|---|---|---|
| `5874b6e` | `d4d8374` | Atomic fleet persistence and runtime binding ownership |
| `3e39f07` | `a613533` | Durable state and TLS in production startup |
| `d917c14` | `091cc8e` | Full revision identity and activation retry |
| `ba5e6ba` | `396785a` | Drain evaluator generations before activation/retirement |
| `dff3491` | `c7a3bb2` | Publish immutable policy/signature pairs after activation |
| `8beb77f` | `76eda82` | Revision, drain and pair regression tests |
| `9265fca` | `0568fd8` | Revision acknowledgement/store integration |
| `a60f59d` | `11b3fa0` | Durable acknowledgement tests |
| `724decb` | `e1a91fa` | Reject ambiguous conditional revision matches |

Two conflicts were confined to the heartbeat implementation in
`internal/policyserver/store.go`; the combined implementation routes the legacy
heartbeat through `HeartbeatRevision`, retaining full-identity semantics and the
fleet transaction boundary. Follow-up commits: `9792dd7` (remove temporary
adapters, direct `RegisterAgentChecked`/`mutateLocked`), `06f006c` (durable tests,
capacity/write errors, restart recovery, signed-pair retry, new default-deny API
assertions), `5376e41` (merge main `1e49aa7`), `3e7019b` (bound new
acknowledgement fields, reject unbootable fleet YAML), `f206fe1` (process-action
drain/outcome preservation, metadata rollback, YAML rejection, post-replacement
recovery).

### Verified contracts

- The client compares `(policy_id, version, wasm_hash)`, verifies downloaded
  bytes and advances active identity only after the activation callback succeeds.
- Registration failures return HTTP 503, not `200 null`; capacity and
  re-registration failures are checked at the handler.
- Heartbeat success requires persistence of active identity and activation
  error. A failed snapshot rolls the acknowledgement back and leaves the prior
  identity/error on disk after restart; a successful retry does not reactivate.
- A post-replacement fault refuses further registration/acknowledgement success
  until reopen — a fail-stop test, not emulated physical power loss.
- Legacy version-only heartbeats clear unknown ID/digest instead of fabricating
  a combination. Signed immutable pairs remain loadable after interrupted
  staging; fleet `.yaml`/`.yml` publication paths are rejected before mutation.
- Activation drains cache hits, evaluation, process action, outcome creation and
  pipeline submission before publication/retirement; a blocked action cannot
  cross a successful activation. Asynchronous sinks are not awaited.

### Validation

Toolchain `go1.27.4-X:nodwarf5 linux/amd64`, `GOMAXPROCS=2`, `-p 2`. Full tests,
full race tests (aggregate statement coverage **74.9%**) and `go vet` passed;
changed Go files passed gofmt and `git diff --check`. `errcheck` and
`staticcheck` reported only pre-existing findings in unchanged files. The
configured golangci-lint v1.64.8 could not decode this toolchain's export format
(version 5 vs analyzer maximum 2), so the complete CI lint binary was **not**
validated locally. An earlier concurrent run hit existing 50 ms evaluator
deadlines; the serialized runs passed and no deadlines were weakened. Privileged
BPF/VM, real cluster, Rust artifact-required gates, Windows and macOS execution
were not performed.

### API migration and remaining limits

- `ClientConfig.OnUpdate` now returns `error`; embedded callers must wait for
  actual activation and durable publication. `ActivatePolicy(path, commit)` is
  the daemon's activation boundary.
- Ephemeral `NewStore`/uninjected `NewServer` remain supported; production CLI
  startup requires TLS, authentication and `--state-file` unless `--insecure`.
  Historical snapshots without the new identity fields restore with unknown
  ID/digest.
- Full identity is authenticated **self-report**, not attested activation. The
  in-place kernel map was not generation-atomic: default-deny misses could allow
  during rebuild, rollback could not restore dynamic entries transactionally and
  queued kernel events lacked generation tags.
- Immutable revision directories had no bounded GC; symlink/directory-fsync and
  an exclusively owned writable fleet path were required. Fleet snapshots are
  single-writer, local and rewritten on every mutation; post-replacement sync
  failure remains indeterminate across power loss.

### Independent review blockers (follow-up at `b80dfef`)

Two disk-publication blockers were found despite a clear runtime-generation
review. Legacy migration now resolves the module once, reads its actual sibling
signature and verifies the copied immutable recovery pair with the configured
key before changing public aliases. Every staging attempt repeats the
public-alias parent-directory fsync, even when both aliases already have the
expected targets; failed barriers cannot be bypassed by retrying. Deterministic
tests cover absent/unrelated signatures, interrupted staging, publication and
verification failure, and two successive injected parent-fsync failures followed
by recovery. Full tests, full race, repeated focused security tests under race,
daemon vet and staticcheck passed in the follow-up. These are filesystem
call-boundary tests, not physical power-loss validation.

### Native CI corrections

- **Windows** run `43607531593`, job `132485312235`, failed on directory fsync
  (`Access is denied`) and a POSIX mode-bit assertion; it did not establish a
  Windows atomic publication backend. The correction makes Windows `--server`
  fail explicitly before fallback seeding, monitor setup or client registration,
  and direct publication/staging fail before any mutation. POSIX durable-publication
  tests are build-constrained to that backend; Windows runs explicit rejection
  tests instead. The snapshot test uses a private inheritable DACL fixture on
  Windows. Windows test binaries cross-compile and Windows publication rejection
  tests pass under race via a Linux source overlay — **not native Windows
  execution**; a native rerun was still required.
- **macOS** run `43609771669`, job `132492027223`, failed only
  `TestPolicyRevisionConcurrentPairConsistency` with `readlink ... invalid
  argument` during rapid symlink replacement. The verified reader now retries
  path resolution on Darwin at most four times, only for a readlink `EINVAL`
  whose entry is still a symlink per `Lstat`; bytes are read only after a
  successful resolution. Other errors fail closed and signature verification is
  never retried or bypassed. Ten repeated race runs passed; a native macOS rerun
  was still required.

---

## 4. Signed assignment integration onto main

Starts at main `9297209` (PR #38 durable activation, PR #45 supervised host/FD
bootstrap, PR #42 release gates) and applies only reviewed assignment commits
`17b7adf`, `f54480a` and `3d3e78d`. Generation-atomic activation and shared
metadata were **not** imported. See [SIGNED_POLICY_ASSIGNMENTS.md](../SIGNED_POLICY_ASSIGNMENTS.md).

### Conflicts and decisions

- Conflicts were limited to compiler version/identity, runtime load admission
  and pool initialization/replacement. Main's preflight complexity limits before
  build-section parsing remain; debug-info decoding stays disabled; bounded
  initialization, actual allocation validation, strict ABI/action/UTF-8
  semantics, pool deadline/closed checks, anonymous instances and captured
  module replacement remain.
- Pool build claims/digest are captured alongside the same compiled module, not
  looked up from a runtime that might later load another module; a regression
  test reloads the runtime then replaces an old pool member and verifies its
  original identity.
- The default-deny fixture allocates declaration tables separately from its
  persistent event buffer, satisfying main's strict nonaliasing allocator
  contract. Compiler cache identity advances from 6 to 7 because signed build
  sections change final WASM bytes.
- `assignment.json` remains signed mode's **sole** durable publication/startup
  authority; no independent PR38 `current` pointer is chained. Signed daemon
  SIGHUP is refused before any reload callback and generic enforcer activation
  is disabled. Later generation combination must also retain the owner's
  `359c75c` out-of-band-reload prohibition.

### Validation and PR40 refresh

With Go 1.26.11 and `-p 2`: full tests, race tests, vet, configured golangci-lint,
changed-file gofmt/diff and repeated signed-focused race tests (count 3) passed;
real-Cargo input/unknown-posture/temporal and all initialization-deadline
entry-point checks ran and passed. Every `cmd/...` command built natively and
cross-compiled for Darwin arm64 and Windows amd64 with CGO disabled; this is not
native execution or a live BPF test. Standalone staticcheck passed for affected
packages; its full-tree run reported 16 findings in unchanged main files.

The subsequent refresh from signed checkpoint `8634b22` imported main `09fdce9`
(PR40 `061685e`) with three conflicts:

- `cmd/warmor-daemon/main.go`: one `enforcerOpts` shared by ordinary, signed
  bootstrap/recovery and restored-state startup, adding PR40's cgroup
  root/reconciliation interval and metrics-bind fields. Signed config validation,
  trust/time checks, sole-agentstore commit and SIGHUP refusal remain.
- `internal/enforcer/enforcer.go`: retain signed candidate validation and test
  injection while forwarding dynamic cgroup settings to the real platform; keep
  PR40's active-loop flag, capture readiness and metrics readiness callback.
- `internal/compiler/build.go`: retain cancellable toolchain checks/Cargo
  subprocesses, wait bounds, context propagation and failed-crate cleanup, then
  append signed build claims before success. Compiler identity stays 7.

Controller selector-Pending behavior, last-known-good publication, dynamic
cgroup discovery, chart probes and deploy preflight were imported unchanged. No
kernel-generation or policy-host routing combination was enabled. Full tests,
race, vet, configured lint, module verification, native builds and cross-compiles
passed for this merge as well.

---

## 5. Node receipts reconciliation onto `971471e`

- Frozen reviewed PR #57 head: `40de5eb82b3244d69f515fb7a48f14d011851c74`.
- Main merged here: `971471e2ff0b257fd58a695651aa7d67b451a3f0` (telemetry #47,
  deterministic fixtures #56, status #55, compiler compatibility #54).
- Branch/worktree: `fix/node-receipts-main971` / `.worktrees/node-receipts-main971`.
  The original reviewed branch remains frozen. Old-head green checks do not
  establish new-head CI success or production readiness.

Only `internal/enforcer/enforcer.go` conflicted, at the successful evaluator swap:
receipt capture of committed activation and main's replacement/sealing of
optional acknowledged-decision telemetry were both retained under
`activationMu`, event drain, `decisionMu` and `evaluatorMu`, after kernel prepare
and durable commit succeeded. Receipt capture reads `Pool.Identity`, never the
supplied telemetry snapshot. No assignment-checker conflict occurred.

Invariants: receipt daemon mode allocates **no** telemetry collector or fleet
lease; `--receipt-controller` plus `--server`/`--signed-assignments` fails before
trust files, TLS or capture. An owned fake-HTTPS activation test runs with and
without an embedded collector; the collector path supplies a deliberately
different telemetry hash and still requires the committed pool's real signed
digest/ABI/build claims. It covers signature failure, drift withdrawal, failed
kernel rollback, failed durable commit, fresh recovery, telemetry sealing on
generic reload and publication ABA. Failed candidates advance neither the
collector revision nor the evaluator identity. Node receipt code, controller
publication epochs, RBAC/Helm trust gates and compiler-7 artifact claims are
unchanged.

Review the delta with `git diff 40de5eb -- internal/enforcer/enforcer.go
internal/enforcer/signed_assignment.go internal/enforcer/receipt_test.go` and
compare inherited telemetry to pinned main; the full feature is
`git diff 971471e`. The earlier
[`node-receipts-integration-review.md`](node-receipts-integration-review.md)
records the original `40de5eb` reconciliation onto `ce1d5ab`; its pins and
validation are historical, not evidence for this later merge.

Validation used `GOTOOLCHAIN=go1.26.11 GOMAXPROCS=2`: full tests, race tests,
golangci-lint, `helm lint` and ten repeated race runs of receipt activation
(both collector modes), telemetry failure/sealing and signed-mode refusal all
passed, as did `git diff --check` and byte-preservation comparisons. These are
local results, not fresh remote CI, a live-cluster gate, attestation or release
clearance.

---

## 6. Supervised host clean handoff after Git fixture isolation

Status at the time: **experimental, off by default; actual legacy and atomic
Host VM CI still mandatory**. Older in-process/kernel VM successes were not Host
proof.

- Worktree `.worktrees/supervised-host-final`, branch `feat/supervised-host-final`,
  starts at reviewed `d942187`. Accidental empty fixture commits `713981c` and
  `48295bb` are **not ancestors** and remain preserved on the old line. Reviewed
  PR53 checkpoint `5ed1817` is an ancestor, allowing an ordinary fast-forward.
- Merge `8469c53` has exactly parents `d942187` and pinned main `971471e`.
  Conflicts: `internal/enforcer/enforcer.go` (reproduce only the semantic
  resolution from old merge `5664f02`, retaining Host backend, legacy telemetry
  publication and unsupported overlapping-generation guards) and
  `internal/workload/manifest/cargo_test.go` (keep main's nil-safe canonical
  build-claim checks and ABI/pool coverage).
- `7f8b35c` makes generation+telemetry startup options reject early rather than
  silently removing the collector; signed mode retains main's seal/disable
  behavior. `686eb8a`/`cdb10ac` were test-only adaptations; no production
  timeout or assertion was relaxed.
- Hermetic fixture isolation `e33e198` changes only `tests/release/test_release.py`
  (strip inherited `GIT_*`, owned Git directories, private file remotes, hostile
  sentinel test), `tests/integration/run-outcomes.sh` (scope `GIT_DIR`/
  `GIT_WORK_TREE` to individual Go commands) and
  `tests/integration/policy_host_workflow_test.go` (forbid global overrides).
  Python packaging tests run only in an external copied tree with sanitized
  subprocess environment and `PYTHONDONTWRITEBYTECODE=1`.

Retained Host contracts: full artifact-signed legacy/atomic workflow matrix with
strict no-skip/exact-PASS oracles; held-load proof with attributed uncached allow
and fresh confirmation before worker release; independent compile/init deadlines
and reaping; test-only phase controls excluded from normal/release/Docker builds;
initialized blocking and effective operator request, relative policy `Abs`,
strict no-follow checks; canonical source trust pins and zero parent WASM
decode/compile; signed daemon + Host/generations refusal; terminal-child cached
allow refusal, old-generation leases, reader close before join, maps/hooks until
Close; 288-byte exact keys and 127-byte policy paths.

Validation at settled checkpoint `cdb10ac` (Go 1.26.11, `GOMAXPROCS=2`, `-p 2`,
Cargo required) ran one sequential pipeline: full normal and race suites, vet,
normal and phase lint, tagged real-worker phase race tests, integration
compile-only, external Python packaging (**26 tests**, **171** identical Git
metadata hashes before/after), shell syntax/actionlint, legacy+atomic Host
**build-only** preparation, phase-marker exclusion in normal binaries, and
Windows amd64/Darwin arm64 test-binary cross-compiles. All passed. These results
do **not** satisfy the mandatory actual legacy+atomic Host VM matrix; no local
VM, host attachment, Docker publication, release/tag or push occurred. The old
branch with the preserved incident evidence must not be used as the clean
publication source.

---

## 7. Supervised host packaging/outcome checkpoint

Base: PR #53 `feat/supervised-host-activation` at `5010198` (includes main
conformance `be15f27`); branch `test/supervised-host-outcomes` in
`.worktrees/supervised-host-vm`.

Implemented: Linux archive helper/public digest metadata with Docker copying the
helper from the same build stage to a root-owned libexec path; explicit bounded
`--policy-host-load-timeout` (5 s default, positive through 10 s) for real
compiler/initialization failure tests; an optional signed whole-daemon host
fixture and separate legacy/atomic CI matrix; exact prepared binary hashes with
matching revision/toolchain/architecture and installed host pin; strict nested
PASS counts; old-host lease/maps-until-Close checks via deterministic real-host
tests. Helm wiring was deliberately deferred.

Local validation (Go 1.26.2, Linux amd64) passed 24 offline Python packaging
tests, `bash -n`, actionlint, focused normal and race tests, tagged integration
compile and offline workflow/VM-guard tests, tagged lint and legacy/atomic Host
**build-only** preparation, and Windows/Darwin test-binary cross-compilation.

The broad normal suite **failed** two existing in-process NetFilter
policy-evaluation tests; broad race execution also failed existing in-process
evaluation deadlines and host CPU/load-phase deadline tests under substantial
concurrent load, with no race-detector warning. The failures passed a smaller
serial race recheck but the broad runs remain **failed**, not retrospectively
green; no deadline, assertion, #41/#51 gate or BPF source/object was relaxed.
Go 1.26 VCS discovery initially stamped the outer checkout revision because it
ignored the worktree `.git` file; the runner now binds `GIT_DIR`/`GIT_WORK_TREE`
to its own checkout and the same-revision assertion passes.

No VM or enforcing daemon was run locally. CI must execute both real signed host
map modes, retain successful non-skipped outcomes and review failures before any
acceptance or default-backend claim. No Docker build/runtime, native arm64 host
bootstrap, seccomp/container matrix, atomic upgrade, native Windows/macOS
execution, native-compromise sandbox, sustained loss or power-loss continuity
evidence was supplied.

---

## 8. Held-load concurrency proof (follow-up to `399f605`)

This follow-up fixes the P2 oracle gap of frozen checkpoint `399f605`: the old
fixture allowed 20 seconds to observe an uncached ALLOW while candidate loading
timed out in 500 ms, so a dispatcher blocked for the whole load could pass after
rejection. PID visibility and an eventual ALLOW were not concurrency evidence.

The proof uses an explicit test profile, not a production bypass: only
`run-outcomes.sh --policy-host` builds daemon and helper with
`-tags policyhost_phaseproof`. Normal, release and Docker builds omit it;
tagged/untagged pairs fail protocol validation rather than falling back. No
production deadline, signature check, resource limit, action, cache rule, kernel
map or enforcement oracle changes.

The tagged real worker acknowledges the signed module upload, sends a
`test-load-held` receipt over its owned pipe and waits for release **before
compilation**. The tagged supervisor forwards a receipt bound to its child PID,
exact module digest and limits over a guest-local Unix socket. Only the selected
compile-heavy/init-loop digest is held; other loads are released immediately.
The fixture completes its uid-65534 helper, observes its PID/path-attributed,
uncached file ALLOW, and only then requests a fresh held-load confirmation; the
worker is released after that confirmation. Rejection, exit, EOF, wrong receipt
or missing ALLOW fails. A blocked dispatcher cannot pass later: once rejected,
the load's socket is closed and cannot supply a fresh receipt.

Negative probes: a shared offline oracle forces `eventMu`-until-rejection
ordering; an enforcer probe holds the **real eventMu**, rejects a real
artifact-signed init-loop candidate, then unlocks and observes a real uncached
last-known-good ALLOW — the oracle must reject it by EOF, not a wall timeout;
tagged real-worker tests check release, cancellation, total deadline, mismatched
release rejection, capacity release and owned-child reaping; normal-build tests
check the profile is inert. "Artifact-signed" means detached module signatures,
**not** signed deployment. The VM workflow was pinned to Go 1.26.11 (the
`399f605` checkpoint used 1.26.2). Focused probes passed, but no actual VM
result, broad-green claim or native OS execution is claimed. The original
`399f605`/`aaf328e` checkpoints remain frozen; see
[`supervised-host-outcomes-integration.md`](supervised-host-outcomes-integration.md)
for the later combined validation.
