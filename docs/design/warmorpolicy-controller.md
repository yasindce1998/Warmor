# WarmorPolicy Controller

The `WarmorPolicy` custom resource (`warmorpolicies.warmor.io`, shipped in
the chart's `crds/` since the chart existed) had no controller: applying a
CR did nothing. This design closes that gap — `kubectl apply` a
WarmorPolicy and every node enforces it, without restarting anything.

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
6. **Reports** per-CR status (`phase`, `observedGeneration`, a `Ready`
   condition, `lastApplied`).

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
- compiles are **cached** — keyed by a hash of the policy YAML, the
  compiler version and the generated Rust source — and skipped entirely
  when the ConfigMap already carries the content hash.

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
  from another. Within an action class, order is CR name, then rule order
  as written.
- **Default action**: the strictest across the merged CRs
  (`deny` > `audit` > `allow`). Merging can never quietly open a hole.
- **Variables**: namespaced per CR (`<policy>__<name>`) with `$`
  references rewritten to match, so two policies defining `blocked_bins`
  cannot bleed into each other's rules.
- **Rule names** are prefixed `<policy>/<rule>` so deny reasons stay
  attributable after merging.
- **A single CR passes through** unchanged (apart from the effective
  policy name); CRs fully define the effective policy — applying one
  *replaces* the baked default rather than extending it. With **no CRs at
  all**, the controller syncs the cluster default baked at image build
  from `deploy/default-policy.yaml`, so an empty cluster is a protected
  cluster.

### Vocabulary

The CRD's action enum is `allow`/`deny`/`audit`; the daemon's policy
schema is `allow`/`deny`/`log`. Rendering translates `audit` → `log`
(audit *is* what the daemon calls logging).

## Status

| spec/state                        | phase   | Ready condition                          |
|-----------------------------------|---------|------------------------------------------|
| renders and parses                | Active  | `True`, reason `Compiled`                |
| render or parse failure           | Error   | `False`, reason `InvalidPolicy`          |
| carries `spec.selector`           | Pending | `False`, reason `SelectorNotSupported`   |

A CR that fails validation is reported on that CR and **excluded** from
the effective policy — one bad CR never blocks the fleet. `nodesApplied`
is not set: the controller has no per-node feedback loop (that is the
policy server's job via agent heartbeats).

### Selectors

`spec.selector` cannot be honored yet: enforcement is node-wide, and
applying a pod-scoped policy beyond its scope would be dangerous in both
directions (a scoped *deny* would block unrelated pods; a scoped *allow*
would be broader than intended). Selector-carrying CRs are therefore held
`Pending` with an explanatory condition instead of being silently
mis-applied. They become meaningful when per-workload policies land (the
OCI hook container bindings are the planned identity source).

## Failure modes

- **Controller down**: agents keep enforcing the last-synced ConfigMap
  (ConfigMaps persist); new CR changes just don't roll out until it
  returns.
- **Fresh install ordering**: the DaemonSet may start before the
  controller's first sync. The ConfigMap volume is `optional: true`, so
  agents crash-loop briefly (the controller publishes within seconds of
  starting) rather than hang.
- **Bad CR**: excluded from the merge, `Error` on its status, the
  remaining CRs still sync.
- **Tampered ConfigMap**: overwritten on the next event or resync tick.
- **NetworkPolicy**: the chart's default policy selects pods by the
  release labels, which before the controller existed meant "the daemon
  pods" and their needs (metrics ingress, DNS + 443 egress). The
  controller carries the same labels but needs API-server egress
  instead. The chart now scopes that policy to `component: daemon` pods
  and emits a controller policy allowing DNS and 443/6443 egress — 443
  for real clusters (pre-DNAT service VIP), 6443 for kindnet, which
  evaluates the post-DNAT node port. Without this, the controller's
  watches are silently dropped on kind and no CR ever goes Active.

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
- `scripts/kind-e2e.sh` — controller phase (apply CR → Active → ConfigMap
  → hot reload → enforced deny)

## Testing

- `internal/kube`: httptest coverage of CRUD, error decoding, watch
  streaming and context cancellation.
- `internal/controller`: render/merge unit tests (vocabulary translation,
  variable namespacing, restrict-first ordering, single-CR pass-through)
  and full Reconcile tests against a fake API server with the compiler
  stubbed — covering status transitions, ConfigMap create/update/skip,
  invalid-CR isolation, selector holding and drift healing.
- `scripts/kind-e2e.sh`: end-to-end — controller compiles a CR in-cluster
  (real cargo, real WASM), publishes the ConfigMap and the agent
  hot-reloads it. Enforcement is asserted by exec'ing a marker binary
  under a path only the CR's rule covers (`/var/tmp/warmor-cr-*`; the
  baked default blocks only `/tmp/**`) and watching the daemon's
  `warmor_events_total{action="DENY"}` counter tick up — attributing
  the deny to the CR specifically. The counter, not the daemon's log,
  is the signal: on kind the daemon evaluates every exec on the shared
  host kernel and its container log rotates within seconds. The kind
  node also does not share the host PID namespace, so the deny's
  SIGKILL cannot reach the probe — on kind the counter is the
  verifiable part of the chain.
