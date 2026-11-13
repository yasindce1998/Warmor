# Warmor production-readiness plan

## Recommendation

Make Linux and Kubernetes enforcement trustworthy before expanding the feature
surface. The next milestone should be **a safely deployable, workload-scoped
Linux/Kubernetes beta**, not more intelligence features or a cross-platform GA.

This plan is based on a repository review at `b1cbb53` on 2026-11-13. It covers
the daemon, BPF programs/loaders, WASM/compiler/cache, policy tools, fleet server,
Kubernetes controller/chart, event pipeline, intelligence, platform adapters,
and build/release workflows. It is not an exhaustive security audit.

### Evidence and limits

- `go test ./...`: passed.
- `go test -race -coverprofile=... ./...`: passed, 73.6% aggregate statement coverage.
- `go vet ./...`: passed.
- Helm lint and a rendered controller + LSM/default-deny configuration: passed.
- Local, unprivileged reproductions confirmed the policy typo, argv compilation,
  learner/compiler incompatibility, agent-identity, and invalid-verdict problems
  below. Reproduction files were kept outside the repository.
- No live cluster was changed. No host-wide enforcing daemon was started.
- Privileged kernel/IMA tests, real Kubernetes enforcement, Windows drivers,
  macOS ESF, ARM64 execution, and dependency/image vulnerability scanning were
  not run as part of this review. Some Rust-crate tests can skip missing build
  artifacts; a passing local Go suite is not evidence that every crate ran.

## What is already working

### Implementation progress (first safety batch)

Implemented after the initial review: strict YAML/operand/variable validation;
real argv and network-operation compilation via ABI 5 callbacks; rejection of
invalid WASM verdicts in both ABIs without persistence; global audit/learning
kernel safeguards including integrity and static preloads; audit-first Helm
defaults; and JWT-subject/certificate-CommonName binding for agent APIs and
assigned-revision downloads. Regression tests and migration notes accompany
these changes. Historical findings below describe the reviewed baseline, not
claims that every listed defect remains unchanged.

Still outstanding: exact kernel identities, verified process targeting,
transactional activation, runtime binding authorization/attested labels,
controller last-known-good/workload isolation, and the remaining release gates.

- Linux tracepoint monitoring, LSM loading, bounded WASM evaluation, decision
  caching, signed-policy verification, and kernel default-deny for an eligible
  exec/connect allowlist subset exist.
- Reload clears kernel decisions and guards against stale in-flight writes;
  kernel-sync errors are observable and field-dependent decisions are gated.
- The Helm chart is runnable and has a kind CI path. The WarmorPolicy controller
  renders, merges, compiles, publishes, and updates CR status.
- Fleet authentication, versioned policy distribution, manual percentage
  rollouts, event sinks, learning/simulation CLIs, escape detection, and
  intelligence flags have implementations and substantial unit tests.
- Windows ETW has a real-runner smoke test; Linux LSM/IMA has VM test workflows.

Several README/operations/status claims predate these implementations. Do not
create work items to reimplement fixes that are already present.

## Priority definitions

- **P0:** fix before recommending enforcement on production nodes; security
  decisions can be wrong, safeguards misleading, or unrelated workloads harmed.
- **P1:** required for a credible Kubernetes/fleet beta; rollout, scoping,
  recovery, and deployment verification.
- **P2:** scale, operational maturity, and coverage expansion after correctness.
- **P3:** additional platforms/features after the Linux/Kubernetes release gate.

These are engineering priorities, not CVSS ratings. Code-confirmed defects are
distinguished from risks needing privileged reproduction.

## Findings and work packages

### A. Policy semantics and enforcement safety — P0

**Confirmed problems**

1. **A policy typo can fail open.** `compiler.Parse` uses permissive YAML
   unmarshalling. A file with `default_actoin: deny` passes `--validate` with
   `default_action=allow`. See `internal/compiler/parser.go:19` and
   `internal/compiler/schema.go:56`.
2. **YAML argv rules do not evaluate argv.** `fieldToRustBinary("args", ...)`
   returns `path`. A compiled deny for `args contains --dangerous` allows
   `/usr/bin/tool --dangerous` through the real WASM evaluator. Network
   `operation` is accepted by validation but has no variable in the generated
   binary network evaluator. See `internal/compiler/codegen.go:325,524`.
3. **Kernel matching uses only a 32-bit FNV hash for the operation identity.**
   Distinct exec paths can share an allow/deny entry in the same scope. A local
   collision was reproduced; a complete kernel bypass was not attempted.
   See `bpf/warmor_lsm.h:40`, `bpf/lsm_exec.bpf.c:25`, and
   `internal/ebpf/policy_map.go:168`.
4. **Unknown WASM verdicts are accepted.** A module returning 99 produces
   `Action=UNKNOWN, error=nil`; the action handler's error is ignored, and
   kernel synchronization treats a non-DENY action as allow. See
   `internal/wasm/policy.go:77`, `internal/wasm/context.go:82`, and
   `internal/enforcer/enforcer.go:860`.
5. **Audit is not centrally authoritative.** `--audit`, `--lsm-enforce`, and
   integrity enforce mode are passed independently. Static-rule preload does
   not fold global audit into every entry. Configuration combinations can
   therefore leave kernel blocking active during an intended dry run. This
   follows from the wiring; confirm all combinations in a VM. See
   `cmd/warmor-daemon/main.go:250`, `internal/platform/linux.go:126`, and
   `internal/enforcer/defaultdeny.go:119`.
6. **Termination targets only a numeric PID on Linux.** Event time is ignored;
   delayed events, PID reuse, and nested PID namespaces need explicit handling.
   Termination failures are logged but not represented as failed enforcement.
   See `internal/enforcer/actions_linux.go:11` and `actions.go:56`.

**Implementation**

- Introduce one strict, typed policy model shared by compiler, controller,
  generator, merge, diff, simulator, and CLI validation. Reject unknown fields,
  unresolved variable references, duplicate identifiers, invalid operator/type
  combinations, and numeric overflow. Define literal `$` escaping explicitly.
- Reject unsupported semantics immediately; then implement real argv and
  operation transport with a versioned ABI. Do not alias unsupported fields.
- Unify identity/length/truncation semantics across sensors, WASM, cache, and
  kernel. The binary ABI currently carries 128 path bytes while sensors/kernel
  can use longer strings. Distinguish complete, truncated, and unknown inputs.
- Replace hash-only security matching with exact structured endpoint keys and
  full path/identity verification. Choose file/exec identity semantics explicitly
  for mount namespaces, symlinks, relative paths, and renamed files.
- Validate the action enum before caching/syncing/enforcing. Invalid values must
  become evaluation errors and transient fail-closed denials, never allow entries.
- Normalize configuration into a single effective posture before loading hooks.
  Audit must suppress all blocking and termination, including integrity and
  preloaded rules. Reject contradictory options instead of guessing intent.
- Use pidfds plus verified process lifetime/namespace identity where available;
  define a safe fallback. Record attempted/succeeded/failed enforcement separately.

**Acceptance**

- Every supported field/operator has a real compiled-WASM behavioral test.
- Typos and unsupported fields fail validation and deployment with field paths.
- Deliberate hash collisions cannot share verdicts in privileged kernel tests.
- Unknown verdicts cannot enter either cache or kernel maps as allows.
- Audit-mode matrix produces zero EPERM and zero kills, with all security flags.
- Stale/reused/wrong-namespace PID tests never terminate an unrelated process.

### B. Transactional policy activation — P0/P1

**Confirmed problems**

- The fleet client tracks only a version number, not policy identity + version +
  digest. Reassignment between two policies at version 1 can be mistaken for no
  change. It advances the version before `OnUpdate`, which cannot return an error;
  disk-write/load failures can still be reported as applied. See
  `internal/policyserver/client.go:138` and
  `cmd/warmor-daemon/policyverify.go:103`.
- Reload swaps the evaluator before rebuilding its kernel state and retires the
  old runtime without a full in-flight evaluation lifetime protocol. Generation
  checks protect persistence but not every cache-hit/action boundary. Default-deny
  rebuilding intentionally allows misses temporarily and logs some activation
  failures without failing the reload. See
  `internal/enforcer/enforcer.go:1004` and `defaultdeny.go:44`.
- Signature and module are separate file replacements; interruption can leave a
  pair that fails verification on restart. The watcher uses increasing mtime,
  rather than active content identity, and does not acknowledge reload success.

**Implementation**

- Model desired/downloaded/validated/active states using policy ID, revision,
  digest, compiler/ABI version, and effective posture.
- Stage and validate exact bytes, prepare kernel state, atomically activate a
  generation, then acknowledge success. Keep a durable last-known-good revision.
- Use reference-counted evaluator generations or an equivalent drain protocol;
  retire runtimes only when no event uses them.
- Design double-buffered/generation-addressed kernel state where supported;
  explicitly document restart/unavailable-daemon behavior rather than claiming
  continuous protection. Add a require-default-deny option for operators who
  cannot accept degradation.
- Store module/signature/metadata as one immutable revision directory and switch
  an active pointer atomically. Retry failed activations and report their cause.

**Acceptance**

- Same-version policy reassignment applies correctly.
- Full disk, invalid module, bad signature, map-write failure, and interrupted
  activation preserve the previous usable revision and never report success.
- Reload-under-load tests show no stale cache/map repopulation, no use of closed
  runtimes, and no undocumented protection window.

### C. Kubernetes deployment safety — P0/P1

**Confirmed gaps / deployment risks**

- Chart defaults use `auditMode: false` and an empty cgroup filter: the daemon can
  SIGKILL denied host/workload processes even with LSM enforcement disabled.
  This is not a monitoring-only default. See `deploy/helm/warmor/values.yaml:9`.
- The agent drops all capabilities and adds BPF-related ones, but not CAP_KILL.
  UID 0 without CAP_KILL cannot generally signal another UID's process. Validate
  non-root-workload termination in the actual pod security context, not only a
  same-user Go child-process test. See `templates/daemonset.yaml:114`.
- `--cgroup-filter=auto` discovers a one-time set during load. Newly created pod
  cgroups are not added. Filtering is exact-ID, so listing only a parent is not
  sufficient for children. See `internal/platform/linux.go:63` and
  `internal/ebpf/cgroup.go:50`.
- Host `/sys` is mounted at `/host/sys`, while consumers use `/sys/fs/cgroup`.
  Cgroup namespace/root visibility must be proven in a real container runtime.
- `/health` and `/ready` always return 200. They cannot distinguish an active
  event loop, degraded enforcement, stale policy, or a disconnected reader. See
  `internal/metrics/server.go:71`.
- hostNetwork exposes metrics on the node; Kubernetes NetworkPolicy behavior
  for host-networked pods is CNI-dependent. A rendered NetworkPolicy is not proof
  of access restriction. Agent RBAC also includes unused CR status writes.
- The metrics Service selector also matches controller pods, which do not serve
  the metrics port. Webhook templates exist without a handler.

**Implementation**

- Ship an explicit audit-first profile and a separately selected enforcement
  profile. Require confirmation for node-wide policies and protect Warmor/system
  workloads through a documented, tested scope model.
- Add a node preflight/diagnostic command: kernel/BTF/LSM/IMA, effective
  capabilities, namespace visibility, cgroup mode, and hook coverage.
- Implement dynamic cgroup reconciliation with clear empty-set behavior,
  capacity/error reporting, and consistent host mount paths.
- Derive readiness from the configured posture and active generation; keep
  liveness focused on process health to avoid restart loops during API outages.
- Audit capabilities empirically: supply only those necessary for the selected
  mode, including safe signaling where required. Reduce unused mounts/RBAC and
  token exposure; offer bind-address configuration for HTTP endpoints.
- Add `values.schema.json`, option-combination checks, immutable image digest
  support, Linux/architecture scheduling, controller metrics/probes, and bounded
  writable storage. Fix component selectors. Remove or reject webhook enablement
  until a real handler is available.

**Acceptance**

- Default install observes without killing or blocking any process.
- On supported real nodes, selected non-root pods are terminated/prevented as
  documented; unrelated pods and host processes are not affected.
- Pods created after startup are covered; deletion/recreation removes old state.
- Readiness fails for a required-but-inactive posture, without claiming that
  readiness itself prevents Kubernetes from scheduling unrelated workloads.
- Test supported CNI/network policies, host PID/cgroup namespaces, capability
  restrictions, node restarts, and chart upgrades/uninstalls.

### D. WarmorPolicy controller and workload isolation — P1

**Confirmed problems / limitations**

- Policies are merged node-wide. Nonempty pod selectors are held Pending; there
  is no implemented workload-scoped policy execution path.
- Invalid CRs are excluded from the merge. Invalidating an existing deny CR can
  remove its protection; if no valid CR remains, the baked default is substituted.
- `Active`/Ready means publication, not per-node load or enforcement. Compile or
  publication failures return before useful per-CR status updates.
- ConfigMap drift checks trust the source-hash annotation without checking its
  binary content or compiler identity. Editing binaryData while retaining the
  annotation is not healed by that check. Compiler upgrades can also be skipped.
- All-namespace mode prefixes variables/rules with CR name only, not namespace
  or UID, so same-named CRs can collide. Adding a second CR also changes rule
  ordering from single-policy first-match to global deny-first.
- Compiles lack a context deadline, the controller has one writer/no leader
  election, and controller-published policies are unsigned.

Sources: `internal/controller/controller.go:224,328,394`,
`internal/controller/render.go:61,203`, `internal/compiler/build.go:88`,
and `deploy/helm/warmor/templates/controller.yaml`.

**Implementation**

- Preserve each CR's last successfully accepted generation on invalid updates;
  distinguish explicit deletion from invalidation. Persist the accepted snapshot
  so controller restarts preserve this guarantee.
- Report separate Validated, Compiled, Published, and Applied conditions with
  desired/active digest and node counts. Surface failures even when publication
  fails; node reports must be authenticated and scoped.
- Hash actual artifact bytes and include compiler/codegen/ABI identity in desired
  content. Use immutable revision objects, ownership checks, and conflict retries.
- Define policy composition independently of object count: explicit cluster
  baseline, namespace/workload additions, exceptions, and deny precedence. Key
  source identity by namespace + UID, not just display name.
- Implement real runtime identity using CRI/containerd gRPC plus Kubernetes pod
  metadata. The existing `containerd_monitor.go` speaks HTTP JSON `/events` to a
  Unix socket; it is not a native containerd event subscription to wire in as-is.
- Map cgroup -> container -> pod UID/namespace/labels/image digest; use that to
  select policy generations in userspace and kernel. Retain Pending for selectors
  until end-to-end isolation is verified. Keep broad watch mode admin-only.
- Bound and sandbox compilation, validate/escape generated source/TOML inputs,
  limit rules/artifact size, clean build/cache files, and honor cancellation.
  Keep ConfigMap's object-size limit in the artifact budget; larger policies need
  another transport. Add signing and rotation without assuming signing alone
  protects against an authorized controller issuing a harmful policy.
- Add lease-based leader election only after activation/idempotency are reliable.

**Acceptance**

- Invalid edit leaves prior protection active; explicit deletion has documented
  behavior; errors are visible on the CR.
- Tampered binaryData is detected even with unchanged annotations; compiler
  upgrades rebuild when output semantics change.
- Two namespaces using the same CR name cannot share variables or affect each
  other's workloads. Label changes and pod restarts converge correctly.
- Applied status requires actual node acknowledgement of the exact digest.
- Controller/API outage leaves the last-known-good policy active on agents.

### E. Fleet control-plane trust and durability — P0/P1

**Confirmed problems**

- Authentication checks roles but does not bind JWT subject/certificate identity
  to the requested agent ID. A local test with subject `attacker` successfully
  heartbeated as `victim`, changing its reported policy version. Registration and
  policy queries also trust client-supplied identity/labels. See
  `internal/policyserver/auth.go:69` and `server.go:241`.
- Store, policy revisions, rollouts, and registrations are in memory. Restart
  loses management state. Selection ties depend on map order. See
  `internal/policyserver/store.go:15,288`.
- TLS is not mandatory for bearer-token mode, request-body limits are not
  consistently enforced, and signed module bytes do not bind deployment
  assignment/version to an anti-replay policy. Auto-rollback is not wired.

**Implementation and acceptance**

- Bind principals to agent/node identities and allowed labels/assignments;
  explicitly authorize runtime and admin actions. Cross-agent tests must return
  403. Require TLS outside an explicit development mode; rotate credentials.
- Persist immutable revisions, active assignments, rollout state, and audit
  history transactionally. Restart/restore tests must preserve policy identity
  and rollout cohorts. Make priority ties deterministic.
- Verify download digest and signed assignment metadata; design authorized
  rollback separately from replay protection. Bound requests and retained state,
  add backoff/jitter/re-registration, and expose activation failures.
- Use acknowledged policy/reason/outcome telemetry for canary analysis. Enable
  auto-rollback only after telemetry is attributable, sufficiently sampled, and
  resilient to offline agents. Rollback must use the same activation protocol.

### F. Policy-tool and event-schema contracts — P1

**Confirmed problems**

- `warmor-learn` emits process/file conditions named `filename`, rejected by the
  compiler, which expects `path`; it also emits unsupported standalone event
  types for bind/listen/mount/ptrace. IPv6 endpoint splitting is string-based.
  See `internal/learner/synthesizer.go:71`.
- Recorded events omit argv, parent comm, operations, and file flags needed to
  reproduce policy inputs. Replay reconstructs only a subset; simulation can
  therefore disagree with live evaluation. See `internal/streaming/event.go`
  and `internal/simulator/replay.go:125`.
- Policy diff compares rules but not effective default action, variable values,
  or rule-order changes; a clean-looking diff is not a semantic equivalence
  proof. Merge strategies use separate schema/semantics.

**Implementation and acceptance**

- Use the common typed model and validation in every output-producing tool.
  Test `record -> learn -> validate -> compile -> replay` in CI, not just YAML
  shape tests. Every advertised generated policy must compile and decide its
  own observed examples as intended.
- Version the event schema; preserve complete policy-visible input with unknown
  and truncation markers. Address argv/secret redaction deliberately: replay
  must report incomplete evidence rather than claim equivalence after redaction.
- Make diff report defaults, variables, order, modes, and temporal semantics.
  Define merge operators over decisions, not merely identical rule fingerprints.
- Test YAML and Rust policy outcomes against a shared fixture corpus, including
  IPv6, long paths, missing metadata, Unicode/raw path bytes, and audit rules.

### G. Event reliability, performance, and intelligence — P2

- Count loss at every boundary: tracepoint rings, LSM rings, decode/read failures,
  daemon queues, enrichment, and each sink. Current LSM counters do not cover all
  tracepoint or userspace losses. Persistent read errors must not become busy
  retry loops while health remains green.
- Separate detection/enrichment from slow sink delivery. Pipeline fan-out is
  serial; TCP syslog writes have no deadline and can stall every sink and
  shutdown. Use bounded per-sink queues, deadlines, retry budgets, and optional
  durable spooling; define ordering and delivery guarantees.
- Correlate tracepoint/LSM observations so incomplete duplicate events are not
  independently treated as equivalent full-context policy inputs. Preserve actual
  socket protocol and hook operation rather than inferring TCP from IP family.
- The event loop evaluates serially while allocating `runtime.NumCPU()` WASM
  instances. Make worker/pool/cache/lineage sizes configurable and cgroup-aware;
  benchmark before adding concurrency that could break ordering or stateful policy
  assumptions. Fix generated allocator/null-pointer contracts and bound all
  initialization/export calls, not just steady-state evaluation.
- Make fields-read declarations cover the current ABI before opting Rust crates
  into caching. The cache's ABI-coverage helper currently exercises version 0/3,
  not all version-4 fields. Undeclared ABI-4 modules conservatively bypass caching,
  so do not add declarations as a performance-only change without soundness tests.
- Feed process/container exits into lineage and graph cleanup. Bound graph,
  fingerprint, and metric cardinality; use comparable rolling drift windows and
  real workload image identity. Add remote/volume resolution before presenting
  blast radius as complete.
- Default the optional dashboard to loopback, add an explicit remote access/auth
  model and HTTP timeouts, and keep policy/event secrets out of public endpoints.

**Acceptance:** sustained/burst load and sink outage tests meet published CPU,
RSS, latency, and loss budgets; shutdown is bounded; long-running pod churn does
not grow state indefinitely. Budgets must be measured in the deployed pod limits,
not inferred from an idle-laptop throughput result.

### H. Platform support and supply chain — P1/P3

- **Linux/Kubernetes first:** extend privileged tests to the whole daemon and
  real workloads, not just BPF attach/map helpers. After correctness, add safe
  file identity and additional synchronous deny domains. Keep detect-then-kill
  distinct from prevention; adding hooks alone does not close the async gap.
- **Windows:** maintain ETW as experimental until end-to-end outcome tests pass.
  Build native eBPF programs against a pinned SDK, then test on isolated driver-
  capable runners before advertising kernel blocking. Validate audit behavior
  independently; eBPF hook loading currently differs from Linux's enforce flag.
- **macOS:** compile the actual cgo/ESF path on a native runner first. Audit SDK
  symbols, AUTH deadlines/responses, executable selection, lifecycle, and time
  conversion. Current releases disable cgo, and AUTH responses allow. Either ship
  signed/notarized, runnable experimental artifacts or omit the nonfunctional
  daemon from supported release downloads. Do not label capability intent as
  verified enforcement.
- **Release integrity:** gate publication on the same tested commit/artifacts;
  releases currently run independently of CI completion. Version chart/app/image
  consistently instead of shipping `latest` with fixed chart versions. Pin build
  tools/actions/base images, verify regenerated BPF corresponds to shipped objects,
  and test ARM64 artifacts on ARM64 nodes.
- Add Go/Rust/image vulnerability scanning, SBOMs, provenance, release/checksum
  signatures, and a vulnerability-reporting policy. Reconcile the linter/toolchain
  versions and workflow path filters so ABI/platform/compiler changes run the
  relevant kernel tests.

## Delivery sequence and dependencies

Use small, reviewable changes with a regression test first. Effort is relative:
S = focused change; M = cross-package change; L = architectural/integration work.
These are not calendar estimates; kernel and multi-runtime validation dominate.

| Order | Deliverable | Priority | Effort | Depends on |
|---|---|---|---|---|
| 1 | Strict parser; reject unsupported argv/operation; invalid verdict fail-closed | P0 | M | None |
| 2 | Central audit/posture invariants; audit-first chart; truthful outcome metrics | P0 | M | None |
| 3 | Exact kernel identities and collision tests | P0 | L | Policy/input identity contract |
| 4 | Principal-bound fleet authorization and negative tests | P0 | M | None |
| 5 | Verified PID/pidfd targeting and deployment capability tests | P0 | M | Outcome semantics |
| 6 | Shared revision identity + transactional activation/acknowledgement | P0/P1 | L | 1–3 |
| 7 | Controller last-known-good, artifact integrity, failure status | P1 | M | 1, 6 |
| 8 | Round-trip learning/simulation/diff contracts and complete event schema | P1 | M | 1, policy/input contract |
| 9 | Dynamic cgroup/CRI identity and per-workload policy selection | P1 | L | 3, 6, 7 |
| 10 | Kubernetes probes, least privilege, chart schema, secure transport/signing | P1 | M/L | 2, 5–7 |
| 11 | Fleet persistence, restart recovery, reliable canaries | P1 | L | 4, 6, outcome telemetry |
| 12 | Load/loss/soak budgets and bounded sink/intelligence lifecycle | P2 | M/L | Accurate telemetry |
| 13 | Expanded synchronous coverage and native platform release gates | P2/P3 | L | Core conformance suite |

Testing, release provenance, and documentation updates accompany every item;
they are not a final cleanup phase. Correct existing docs immediately where they
could lead an operator to use an unsafe posture.

## Required release gates

### Gate 1: trustworthy standalone Linux enforcement

- All P0 items have regression coverage; default/audit/deny/require modes are
  unambiguous and accurately reported.
- VM tests cover complete daemon startup, first/repeat operations, unknown/long
  inputs, collisions, PID reuse, reload pressure, failure injection, and restart.
- Allowed actions succeed; denied actions have an asserted kernel errno or
  verified termination result. A deny counter alone is insufficient.

### Gate 2: Kubernetes beta

- Multi-node tests on BPF-LSM-capable VM nodes, plus an unsupported-node
  degradation test. kind remains a fast installation/reconciliation smoke test.
- Existing kind tests increment a global deny counter using a marker on the
  shared host and explicitly cannot verify the process was killed. Replace that
  as an enforcement claim with workload-level side-effect/outcome assertions.
- Test new pods after startup, non-root UIDs, selectors, namespace isolation,
  controller restart, API outage, invalid CR updates, node restarts, rollback,
  mixed node capabilities, chart upgrades, and CRD upgrade procedures.
- Include supported Kubernetes versions, containerd and CRI-O, cgroup v2 with
  systemd/cgroupfs, at least the supported CNIs, and AMD64/ARM64 in the test plan.
- Readiness and policy status identify exact active digest, intended scope,
  available hook coverage, and degraded nodes. Document that enforcement agents
  being unready does not automatically gate workload admission/scheduling.

### Gate 3: production fleet candidate

- State survives server/controller/agent restarts and backup restoration.
- Policy provenance and assignment authorization survive tamper/replay tests.
- Canary failure and rollback are verified with loaded-policy acknowledgements.
- Load/soak/failure tests meet published budgets and all delivery losses are
  observable. No critical verdict relies only on unsigned client-reported labels.
- An operator can diagnose missing enforcement and restore the last-known-good
  policy using documented, noninteractive procedures.

## Explicitly defer

- More dashboards, Rust threat-policy crates, and intelligence features until
  policy meaning and deployment feedback are reliable.
- Broad multi-tenant Kubernetes claims until namespace/workload isolation passes.
- Automatic rollback until applied-state and enforcement-outcome telemetry work.
- Cross-platform enforcement parity until native backend tests prove it.
- Additional hook coverage before identity, audit, and reload correctness.

**Next actionable batch:** implement orders 1, 2, and 4 as independent focused
changes, while designing the exact kernel identity and revision-activation
contracts that orders 3 and 6 require.
