# WarmorPolicy Controller

The `WarmorPolicy` custom resource (`warmorpolicies.warmor.io`, shipped in
the chart's `crds/` since the chart existed) had no controller: applying a
CR did nothing. The controller now validates, compiles and publishes policy.
Publication alone does **not** prove that a node loaded or enforced it.

## Architecture

```
WarmorPolicy CRs ──▶ warmor-controller ──▶ ConfigMap ──▶ DaemonSet mount ──▶ agents
 (validate+compile)   (effective policy)   (policy.wasm)  (file watcher hot-reload)
```

A new binary, `cmd/warmor-controller`, runs as a single-replica
Deployment in the chart (`controller.enabled`, off by default). It:

1. **Watches** WarmorPolicies — by default in its own namespace
   (`--all-namespaces` merges every namespace; single-tenant clusters
   only, since any namespace then affects every node).
2. **Validates** each CR individually by rendering it to the daemon's
   policy format and running it through `compiler.Parse` — the same
   check the daemon performs at load time.
3. **Merges** the accepted CRs into one *effective policy*.
4. **Compiles** it to WASM with the Rust toolchain the controller image
   carries.
5. **Publishes** the module in a ConfigMap (`<release>-effective-policy`,
   key `policy.wasm`, under `binaryData` — a WASM module is not valid
   UTF-8) that the DaemonSet mounts at `/etc/warmor/policy.d`.
6. **Reports** separate validation, compilation and publication outcomes.
   `Applied` remains `Unknown` until authenticated exact-digest node
   acknowledgements exist; `lastApplied` and `nodesApplied` are not asserted.

Agents pick changes up through the mtime-polling policy watcher that
already exists on every platform: a ConfigMap update lands as a file swap
in the mounted volume, the watcher sees a new mtime, and the daemon
reloads — no restarts, no SIGHUP.

### Why the controller compiles (and the agents don't)

The agent image is distroless and cannot compile YAML policies (compiling
generates Rust and runs cargo). The chart's pre-controller answer was to
compile out of band ("run warmor-compile on a machine with the Rust
toolchain and reference a ConfigMap"), which made WarmorPolicy
declarative-in-name-only. The controller image instead carries the Rust
toolchain (`rust:1.82-slim` base) and compiles on reconcile. Two
properties make this cheap:

- the generated policy crates are **dependency-free** (no `[dependencies]`
  in the generated `Cargo.toml`), so compiles are offline and take
  seconds, not minutes;
- compiles are **cached** — keyed by policy YAML, compiler/build profile,
  generated Rust and Cargo manifest — and skipped only when source/build
  identity matches **and** the SHA-256 of actual artifact bytes matches
  the artifact checksum.

`--compile-timeout` defaults to two minutes and must be positive. Cancellation
reaches the Rust target check and cargo subprocess; failed builds and temporary
output files are cleaned. This is not a CPU/memory/process sandbox: deploy with
resource limits and bounded writable storage. Rust child processes may briefly
outlive a killed cargo process; untrusted multi-tenant compilation is unsupported.

The tradeoff is image size (~900 MB with the toolchain vs ~30 MB for the
agent). It is one replica in the control plane, never on nodes.

### Why a hand-rolled Kubernetes client

The repo carries no Kubernetes Go dependencies, and pulling in client-go
for five REST calls (list/watch a CR, create/update a ConfigMap, PUT a
status subresource) would add ~100 transitive modules. `internal/kube`
speaks the REST API directly over `net/http`: in-cluster service account
credentials (token re-read per request, so hourly token rotation needs no
restart), a minimal kubeconfig loader for dev/kind, and a streaming watch
helper. The loop is level-triggered — any event or the resync timer
(`--resync-period`, default 10m) triggers a full re-list and reconcile —
so missed events heal, and a hand-edited ConfigMap is overwritten back.
Two mechanisms bound a silent watch, because a watch can outlive its
client-side cancellation when the pod network blackholes: the resync
timer cancels the context, and every watch request carries
`timeoutSeconds` (half the resync period, 1–10 minutes) so the API
server closes the stream itself — the same belt-and-braces client-go's
reflector uses. Dials also carry an explicit 10s timeout, so a blackholed
connect fails fast instead of waiting out the kernel's SYN retries while
the controller looks hung.

## Merge semantics

Several CRs are concatenated into one module, so their interactions need
defining:

- **Rule order**: most-restrictive-first (`deny`, then `log`, then
  `allow`), because the compiled policy is first-match-wins. Without this
  ordering an `allow` rule from one CR could silently shadow a `deny`
  from another. This applies to a **single** CR too: adding a second CR
  cannot change the first CR's precedence. Within an action class, order
  is namespace/name, then rule order as written. An allow is not an exception
  to a matching deny. Users relying on old single-policy first-match exceptions
  must rewrite their conditions before upgrade.
- **Default action**: the strictest across the merged CRs
  (`deny` > `audit` > `allow`). Merging can never quietly open a hole.
- **Variables**: namespaced per CR (injective namespace/name/UID encoding,
  followed by the variable name) with `$`
  references rewritten to match, so two policies defining `blocked_bins`
  cannot bleed into each other's rules.
- **Rule names** are prefixed `<namespace>/<policy>/<UID>/<rule>` so reasons stay
  attributable after merging.
- CRs fully define the effective policy — applying one
  *replaces* the baked default rather than extending it. With **no CRs at
  all**, or only new invalid/selector-scoped CRs, the controller publishes the
  default baked at image build from `deploy/default-policy.yaml`. This is a
  publication fallback, not proof of active node protection.

### Vocabulary

The CRD's action enum is `allow`/`deny`/`audit`; the daemon's policy
schema is `allow`/`deny`/`log`. Rendering translates `audit` → `log`
(audit *is* what the daemon calls logging).

## Status

| spec/state | phase | conditions |
|---|---|---|
| effective artifact published | Published | `Validated`, `Compiled`, `Published=True`; `Ready=False/AwaitingNodeAcknowledgement` |
| render or parse failure | Error | `Validated=False/InvalidPolicy`; old accepted generation retained if available |
| compile failure | Error | `Compiled=False/CompilationFailed`, `Published=False` |
| API publication failure | Error | `Compiled=True` if completed, `Published=False/PublicationFailed` |
| nonempty `spec.selector` | Pending | `Validated=False/SelectorNotSupported`; any old accepted generation retained |

`observedGeneration` describes the desired spec; `acceptedGeneration` is the
generation committed with the published artifact. An invalid update is **not
deletion**: its previous accepted spec stays in the composition, including across
restarts and unrelated CR changes. A new invalid CR has no accepted contribution.
Only a successful atomic publication advances acceptance; failed compiles or
writes cannot become the fallback for later edits.

`desiredRevision` identifies effective source plus compiler/codegen/build identity;
`desiredDigest` is artifact SHA-256 after compilation (or verified reuse). These
describe the effective composition, including retained snapshots, not a promise
that an invalid desired spec compiled. `publishedDigest` and `lastPublished`
describe publication, never node activation. There is no `activeDigest` assertion.
`Applied=Unknown/NoNodeAcknowledgements` and `Ready=False` remain until a real
acknowledgement path exists. `Active` is retained in the CRD enum for compatibility
but is no longer emitted.

**Upgrade:** apply the updated CRD separately (Helm does not upgrade `crds/`).
Consumers waiting for `phase=Active` must instead inspect `Published=True` for
publication only; they must not interpret publication as enforcement.

```bash
kubectl --context dedicated-test-cluster apply -f deploy/helm/warmor/crds/warmorpolicy-crd.yaml
kubectl --context dedicated-test-cluster wait --for=condition=Established \
  crd/warmorpolicies.warmor.io --timeout=60s
# Upgrade the controller/chart only after the new status schema is established.
```

The served/storage version remains `v1alpha1`; the migration is additive.
`Active`, `lastApplied` and `nodesApplied` remain readable for old clients, but
the controller clears unacknowledged application claims on reconciliation.
Schema contract tests cover every serialized status field, integer generation
types, string-valued condition statuses and legacy phase compatibility. They
do not replace testing admission/pruning against a real API server.

### Controller probes and metrics

The controller serves `/health`, `/ready` and `/metrics` on `--metrics-address`
(default `:9091`, separate from daemon port 9090). The chart supplies real HTTP
startup/liveness probes against `/health` and readiness against `/ready`, scrape
annotations and controller NetworkPolicy ingress. The daemon metrics Service
still selects only `component: daemon`; controller scraping uses pod annotations,
not that Service or its ServiceMonitor. Port 9091 is unauthenticated operational
telemetry; restrict access with cluster/CNI policy. Probes do not prove that a
particular CNI permits scraping.

`/health` means the HTTP process is responsive, not that reconciliation progresses.
`/ready` requires a completed successful local reconciliation, fails after a
reconcile error or controller shutdown, and expires when the last success is
older than `max(resync period, 2m) + compile timeout + 1m`. It therefore withdraws
readiness for stalled work after a bounded age without using liveness restarts to
"repair" API or policy outages. A successful retention of last-known-good sources
after an invalid desired edit is locally ready; inspect each CR's validation and
accepted/observed generations to distinguish that state from desired-spec success.

Metrics are `warmor_controller_ready`,
`warmor_controller_reconciliations_total{result="success|error"}`,
`warmor_controller_last_success_timestamp_seconds` and
`warmor_controller_last_reconcile_duration_seconds`. They contain no CR names,
policy operands or raw API/compiler errors. These are **local reconciliation**
signals only: none changes `Applied=Unknown`, asserts an active digest, or proves
node loading, evaluation, kernel prevention or termination.

### Durable snapshots and recovery

The managed ConfigMap contains `data.accepted-sources.json` alongside
`binaryData.policy.wasm`. One Kubernetes write commits both. The versioned snapshot
contains only accepted policy specs, namespace/name/UID and generation, plus watch
namespace. It excludes CR annotations, labels, status and credentials. Specs and
compiled constants must **not contain secrets**: ConfigMap access is not Secret
access. Restrict ConfigMap writers/readers accordingly.

Each source is limited to 64 KiB and 512 rules before parsing/codegen; the effective
composition is limited to 2048 rules. Snapshots have a 256 KiB budget. Combined
snapshot plus artifact has a 900 KiB budget below Kubernetes' 1 MiB data limit,
also leaving wire-format headroom. Oversized publications fail without replacing
the previous publication; larger policies need another transport. Cache writes
use atomic renames; cache eviction and signing remain follow-up work.

Explicit CR deletion drops only that UID's contribution; deleting the final
accepted source restores the baked default. Delete/recreate with the same name
does not inherit the deleted UID's snapshot. Adding a selector to an accepted
node-wide CR stays Pending and retains the old node-wide contribution: explicitly
delete the CR to remove it. Namespacing prevents source collisions, **not workload
isolation**: all accepted unscoped CRs still affect every watched node.

The controller checks a managed-by label before overwriting an existing object
and uses resourceVersion for writes. Conflicts trigger a fresh list/read on retry,
not a stale blind overwrite. Run one writer; there is no leader election.
Publications are mutable ConfigMaps, not immutable signed revision objects.

A missing/corrupt snapshot or changed watch scope retains the previous ConfigMap
and reports `SnapshotUnavailable`. Restore accepted state from a trusted backup;
do not erase it just to clear status. Legacy publications without snapshots migrate
on a valid reconcile. If a legacy source is already invalid, the complete old
publication remains until that source is repaired or explicitly deleted: its old
spec cannot be reconstructed. Deleting the ConfigMap itself loses durable accepted
history; back it up.

Artifact drift is detected by hashing actual bytes, even with unchanged source
annotations. Compiler/profile, generated Rust and Cargo manifest changes alter
desired identity and cause rebuilding. Snapshot/artifact checksums detect accidental
or unchanged-annotation tampering; they do **not authenticate** a writer replacing
both content and checksums. That writer remains inside the trust boundary until
signed immutable revisions exist.

### Selectors

`spec.selector` cannot be honored yet: enforcement is node-wide, and
applying a pod-scoped policy beyond its scope would be dangerous in both
directions (a scoped *deny* would block unrelated pods; a scoped *allow*
would be broader than intended). Selector-carrying CRs are therefore held
`Pending` with an explanatory condition instead of being silently
mis-applied. They become meaningful when per-workload policies land (the
OCI hook container bindings are the planned identity source).

## Failure modes

- **Controller down**: the last-published ConfigMap persists and agents can
  continue using their loaded policy. New changes wait for controller recovery;
  the controller cannot attest node activation or continuity.
- **Fresh install ordering**: the DaemonSet may start before the
  controller's first sync. The ConfigMap volume is `optional: true`, so
  agents crash-loop briefly (the controller publishes within seconds of
  starting) rather than hang.
- **Bad CR**: `Error`; its last accepted spec remains in the merge. If never
  accepted, it contributes nothing; other valid sources still publish.
- **Tampered artifact**: healed on the next event or resync if recompilation
  and publication succeed. Corrupt snapshots require trusted recovery instead.
- **NetworkPolicy**: the chart's default policy selects pods by the
  release labels, which before the controller existed meant "the daemon
  pods" and their needs (metrics ingress, DNS + 443 egress). The
  controller carries the same labels but needs API-server egress
  instead. The chart now scopes that policy to `component: daemon` pods
  and emits a controller policy allowing DNS and 443/6443 egress — 443
  for real clusters (pre-DNAT service VIP), 6443 for kindnet, which
  evaluates the post-DNAT node port. Without this, the controller's
   watches are silently dropped on kind and no CR gets published.

## Security posture

- Controller-mode policies are **unsigned**; agents in this mode must not
  run `--verify-key` (the same stance as `--policy-fallback`). Signed
  controller policies are a follow-up (the ed25519 machinery from
  `warmor-policy-bundle` would slot into the publish step).
- Default RBAC is a namespaced Role: warmorpolicies
  get/list/watch + status update, and configmaps in the release
  namespace. `controller.watchAllNamespaces` switches the CR access to a
  ClusterRole — opt-in because it lets every namespace affect every node.
- The controller runs as non-root (uid 1000); it needs no privileges
  beyond the RBAC above.

## Files

- `internal/kube/` — minimal REST client (in-cluster + kubeconfig, watch)
- `internal/controller/` — CR types, renderer, merge, reconcile loop
- `cmd/warmor-controller/` — the binary
- `deploy/Dockerfile` — `controller` target (rust:1.82-slim + default
  policy)
- `deploy/helm/warmor/templates/controller.yaml` — Deployment + RBAC
- `scripts/kind-e2e.sh` — explicitly migrates the CRD and waits for
  `phase=Published` plus a true `Published` condition (publication only)

## Testing

- `internal/kube`: httptest coverage of CRUD, error decoding, watch
  streaming and context cancellation.
- `internal/controller`: render/merge unit tests (vocabulary translation,
  namespace/UID namespacing, count-independent deny-first ordering)
  and full Reconcile tests against a fake API server with the compiler
  stubbed — covering status transitions, ConfigMap create/update/skip,
  invalid-edit/restart retention, failed compile/publication/conflicts, selector
  holding, snapshot loss/tampering, same-name cross-namespace CRs, budgets,
  deadlines, ownership and unchanged-annotation artifact healing. A real
  cargo/WASM integration test round-trips the ConfigMap journal, restarts with
  an invalid desired edit, evaluates retained bytes, adds another source and
  evaluates a newly compiled composition containing the recovered deny.
- `deploy`: CRD wire-shape migration, real compilation/validation → ConfigMap
  client dry-run → Helm binary mount contracts, executable selected-policy
  semantics, publication wait predicate and controller probe/render contracts.
  No cluster access or host enforcement is involved in these tests.
- `scripts/kind-e2e.sh`: end-to-end — controller compiles a CR in-cluster
  (real cargo, real WASM), publishes the ConfigMap and the agent
  hot-reloads it. The audit test observes decisions by exec'ing a marker binary
  under a path only the CR's rule covers (`/var/tmp/warmor-cr-*`; the
  baked default blocks only `/tmp/**`) and watching the daemon's
  `warmor_events_total{action="DENY"}` counter tick up. The counter, not
  the daemon's log, is the signal: auto scope discovers pod/container cgroup
  IDs, and the test creates a non-root probe pod after startup and retries
  across discovery and ConfigMap propagation lag. The pod must survive in
  audit mode. An aggregate deny counter may include unrelated denies and is
  not authenticated per-node, exact-digest evidence. This tests policy
  decisions, **not** successful
  termination, kernel prevention, workload isolation, or acknowledged activation.
