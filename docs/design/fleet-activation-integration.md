# Durable fleet and activation integration report

## Scope and history

Integration branch: `fix/durable-policy-activation`, persistent worktree
`/home/yasin/Warmor/.worktrees/fleet-activation-integration`.
Started at main `9ea4594` (foundation parser/audit follow-ups), then merged main
`1e49aa7` (PR #31 pidfd identity checks and actual enforcement outcomes).
No source task branch was changed. No push, PR, main merge, live cluster, or
host-enforcing daemon was performed by this integration task.

Task-only cherry-picks, in order:

| Source | Integrated | Subject |
| --- | --- | --- |
| `5874b6e` | `d4d8374` | Atomic fleet persistence and runtime binding ownership |
| `3e39f07` | `a613533` | Durable state and TLS in production startup |
| `d917c14` | `091cc8e` | Full revision identity and activation retry |
| `ba5e6ba` | `396785a` | Drain evaluator generations before activation/retirement |
| `dff3491` | `c7a3bb2` | Publish immutable policy/signature pairs after activation |
| `8beb77f` | `76eda82` | Revision, drain and pair regression tests |
| `9265fca` | `0568fd8` | Revision acknowledgement/store integration |
| `a60f59d` | `11b3fa0` | Durable acknowledgement tests |
| `724decb` | `e1a91fa` | Reject ambiguous conditional revision matches |

Two cherry-pick conflicts were confined to the heartbeat implementation in
`internal/policyserver/store.go`. The combined implementation routes the legacy
heartbeat through `HeartbeatRevision`, retaining full-identity semantics and the
fleet transaction boundary. Additional commits:

- `9792dd7`: remove temporary interface/fallback adapters; registration calls
  `RegisterAgentChecked` directly and revision heartbeats call `mutateLocked`.
- `06f006c`: default-on durable tests, HTTP capacity/write errors, acknowledgement
  restart recovery, signed-pair boot/publication retry, kernel boot recovery, and
  assertions for the newly error-returning default-deny API.
- `5376e41`: merge main `1e49aa7`; enforcer merged cleanly. Process identity,
  actions, event timestamp and streamed outcome implementations match main.
- `3e7019b`: bound/account for new acknowledgement fields, reject fleet YAML
  publication paths that would be unbootable, remove obsolete private helpers.
- `f206fe1`: test actual process-action drain/outcome preservation, metadata
  rollback, YAML-path rejection and post-replacement-fault recovery.

Dashboard changes outside main are not included. No pending task ancestry was
merged wholesale. Foundation parser/code-generation files are unchanged from
main, and the existing audit-posture tests remain enabled.

## Verified integration contracts

- The client compares `(policy_id, version, wasm_hash)`, verifies downloaded
  bytes, and advances active identity only after the activation callback succeeds.
- Registration failures return HTTP 503, not `200 null`. Capacity, failed new
  registration and failed re-registration are checked at the HTTP handler.
- Heartbeat success requires persistence of active identity and activation error.
  A failed snapshot returns HTTP 503/client error, rolls back the acknowledgement,
  and leaves the prior identity/error on disk after restart. Successful retry
  records the exact identity without unnecessarily reactivating the module.
- A post-replacement fault refuses further registration/acknowledgement success
  until reopen. The regression test injects this fail-stop state; it does not
  claim to emulate physical power loss or every filesystem's durability behavior.
- Legacy version-only heartbeats clear unknown ID/digest instead of leaving a
  fabricated combination. New metadata is bounded and snapshot-accounted.
- Signed immutable pairs remain runtime-loadable after interrupted staging and
  publication failure. Publication retries preserve the previous bootable pair.
  Fleet `.yaml`/`.yml` paths are rejected before mutation.
- Activation drains cache hits, evaluation, process action, outcome creation and
  pipeline submission before publication/retirement. A blocked process action
  cannot cross successful activation; its original timestamp and actual refusal
  fields survive. This does not wait for asynchronous sinks to finish delivery.

The independent fleet review reported the legacy unchecked-registration handler
as a blocker. The integrated direct checked API and HTTP capacity/snapshot-failure
tests address that finding. This report is not an independent security sign-off
and does not assert there can be no further reviewer findings.

## Validation (Linux, unprivileged)

Toolchain: `go1.27.4-X:nodwarf5 linux/amd64`; all Go runs use
`GOMAXPROCS=2`, with test/vet package parallelism `-p 2`.

- `go test -p 2 ./...`: pass on the final code tree.
- `go test -race -p 2 -coverprofile=... ./...`: pass on the final code tree,
  aggregate statement coverage **74.9%**.
- `go vet -p 2 ./...`: pass.
- Changed-Go-file `gofmt -l` and `git diff --check`: pass.
- `go run github.com/kisielk/errcheck@v1.30.0 -asserts ./...`: executed and
  compared with the foundation baseline. No new CI-relevant diagnostics after
  the configured golangci-lint v1 default cleanup/print exclusions. Raw errcheck
  still reports pre-existing unchecked assertions in
  `internal/ebpf/policy_map_test.go` and a channel error receive in
  `internal/enforcer/kernel_verdict_test.go`, as well as cleanup/print calls.
  Those unrelated files are unchanged; this is not a claim of a globally clean
  raw errcheck run.
- `go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...`: only the pre-existing
  unused `defaultDenyMap` field at `internal/ebpf/lsm_loader.go:178` remains. That
  file matches main; newly unused rollout-store helpers were removed here.
- Installed golangci-lint v1.64.8 could not decode this toolchain's export format
  (export version 5, analyzer supports at most 2). Therefore the complete CI lint
  binary was **not** validated locally; standalone current tools were used above.
- An earlier concurrent full/race/analyzer run hit existing 50 ms evaluator
  deadlines under CPU contention, without a race report. The final serialized
  full and race runs passed; no production deadlines were weakened.

Logs/coverage are outside the repository under
`/tmp/opencode/fleet-activation-{full-tests,race,vet,errcheck-full,staticcheck}.log`
and `/tmp/opencode/fleet-activation-coverage.out`.
Privileged BPF/VM, real cluster, Rust artifact-required build gates, Windows and
macOS execution were not performed. A passing Go suite may skip unavailable
optional build artifacts.

## API migration and remaining limits

- `ClientConfig.OnUpdate` now returns `error`: embedded callers must wait for
  actual activation and durable publication rather than launch asynchronous work.
  `ActivatePolicy(path, commit)` is the daemon's activation boundary.
- Ephemeral `NewStore`/uninjected `NewServer` remain supported. Production CLI
  startup requires TLS, authentication and `--state-file` unless explicitly
  using development `--insecure`. Embedded users must open/inject/close the
  durable store and pass the verification key on open to verify restored data.
- Legacy registration and stale-agent wrappers cannot report errors. Network
  registration does not use the legacy wrapper. Historical snapshots lacking
  the optional new identity fields restore with unknown ID/digest.
- Full identity is self-reported by authenticated agents, not attested activation.
  Signed assignment metadata/anti-replay and compiler/ABI/effective-posture
  identity remain separate follow-ups. A daemon restart starts its client with
  unknown identity and reconciles by polling rather than trusting disk metadata.
- The in-place kernel map is not generation-atomic: default-deny misses may allow
  during rebuild, rollback cannot restore dynamic entries transactionally, and
  queued kernel events lack generation tags. Failed rollback reports degraded
  enforcement; readiness/require-default-deny integration is not added here.
- Immutable revision directories are retained without bounded garbage collection.
  Symlink/directory-fsync support and an exclusively owned writable fleet path
  are required. Unsupported storage/platform behavior fails activation rather
  than silently publishing a nontransactional pair.
- Fleet snapshots are single-writer, local and rewritten on every mutation,
  including heartbeats. This is not HA, replicated storage or a fleet-scale
  throughput claim. Post-replacement sync failure remains indeterminate across
  power loss: requests fail and further mutations stop until restart.

See [policy-activation.md](policy-activation.md) and
[POLICY_SERVER_STATE.md](../POLICY_SERVER_STATE.md) for recovery procedures and
operational boundaries.

## Independent review publication blockers (follow-up)

Review pinned at `b80dfef` identified two disk-publication blockers despite the
runtime-generation review being clear. The follow-up preserves subsequent main
merges through `78471f6` and changes only daemon publication/wiring/tests/docs:

- Legacy migration now resolves the module once, reads its actual sibling
  signature, and verifies the copied immutable recovery pair with the daemon's
  configured verification key before changing public aliases. It does not use
  an unrelated signature alongside a module-only symlink. Recovery from an
  interrupted migration validates its existing recovery pair before finishing
  alias replacement.
- Every staging attempt repeats the public-alias parent-directory fsync, even
  when both aliases already have the expected targets. Failed barriers cannot
  be bypassed by retrying or recreating the in-memory stager.

Deterministic tests cover a signed legacy module symlink with its real sibling
signature (including an absent or unrelated alias-side signature), interrupted
staging, candidate load/publication failure, verification failure before alias
changes, and two successive injected parent-fsync failures followed by recovery.
The fsync test checks the parent call count on each attempt and that no failed
attempt reaches activation or returns an acknowledgement; all previous signed
startup pairs are validated in the actual WASM runtime. Fault injection is local
to a stager, not a process-global hook. These are filesystem call-boundary tests,
not physical power-loss or privileged infrastructure validation.

Follow-up validation (`GOMAXPROCS=2`, `-p 2`): full `go test ./...`, full
`go test -race ./...`, repeated focused security tests under race, and daemon
`go vet` all pass. Daemon staticcheck v0.8.2 passes. Daemon errcheck v1.30.0 with
`-asserts` reports only the existing cleanup/print exclusions, with no unchecked
assertions or new persistence-error findings. Changed files pass gofmt and diff
whitespace checks. Follow-up logs are `/tmp/opencode/fleet-blockers-*.log`.

## Native Windows CI correction

Windows run `43607531593`, job `132485312235`, failed on directory fsync
(`Access is denied`) in the POSIX publication tests and a POSIX mode-bit
assertion against the server snapshot. It did not establish a Windows atomic
module/signature publication backend. The correction does not ignore sync errors
or substitute two unrelated file replacements:

- Windows `--server` fails explicitly before fallback seeding, monitor setup or
  client registration. Direct publication/staging also fails before any mutation,
  even if a test stager supplies a successful sync hook.
- POSIX durable-publication success/recovery tests are build-constrained to that
  backend. Windows instead runs explicit tests for repeated failure, unchanged
  signed local startup files, no revision-directory creation, no activation
  callback and no active ID/version/hash acknowledgement in error heartbeats.
  CLI, signature verification, local policy load, watcher, generic client and
  server recovery tests remain enabled; this is not a blanket package skip.
- Server snapshot storage remains supported by its separate Windows write-through
  replacement. The restart/cohort/signature test now uses a platform permission
  assertion: POSIX keeps the mode-0600 check, Windows sets a private inheritable
  DACL fixture and checks each inherited ACE through repeated snapshot replacement.
  Production Windows deployments must provide that private parent DACL.

Validation: Linux full tests and full race tests passed; Windows daemon/server
test binaries cross-compile, Windows vet passes, and the Darwin daemon test binary
cross-compiles. Windows publication rejection tests also pass repeatedly under
race using a Linux source overlay selecting only the Windows rejection backend;
this is **not native Windows execution** or validation of Windows DACL behavior.
Windows native rerun is still required. Current standalone staticcheck passes for
the changed Linux packages; its Windows analysis reports only the pre-existing
`startPolicyWatcher` helper used by Unix tests. Errcheck with assertion checking
reports only existing cleanup/print exclusions. No CI threshold, durability
barrier, permission boundary or supported-backend recovery assertion was weakened.
See [PLATFORM_WINDOWS.md](../PLATFORM_WINDOWS.md#policy-distribution-and-durable-activation).
