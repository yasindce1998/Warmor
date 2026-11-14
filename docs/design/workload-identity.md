# Workload identity and selection boundary (preparation, not enforcement)

## Safety and scope

This design prepares production-readiness work packages C/D. It does **not**
enable `WarmorPolicy.spec.selector`. Such policies must remain Pending until
publication, agent activation, kernel routing, and real-node tests below pass.
The existing HTTP JSON `/events` containerd monitor is not a runtime protocol
and must not be used for this path. This package never opens runtime sockets.

The intended identity chain is:

```
host cgroup ID + lifetime evidence
  -> exact runtime container ID (CRI v1 gRPC)
  -> sandbox metadata (pod UID, namespace, name)
  -> matching Kubernetes Pod UID, node, running container ID/name/attempt
  -> current API-server pod labels
  -> namespace-scoped selector
  -> exact selected policy generation/digest
```

Pod names, cgroup path substrings, shortened container IDs, image names, and
container-provided environment variables are not security identities. A runtime
namespace such as containerd `k8s.io` is not a Kubernetes namespace. Runtime pod
labels may corroborate metadata but never replace API-server selector labels.

## API boundary options

1. **CRI v1 + Kubernetes core/v1 (chosen preparation):** use generated
   `runtime.v1.RuntimeServiceClient` for `ListContainers` and `ListPodSandbox`.
   These are real protobuf/gRPC methods, usable across CRI runtimes. Join those
   objects to actual `core/v1.Pod` objects. The application owns dialing an
   authorized local socket, credentials, deadlines, retries, and connection
   closure. This package accepts a constructed client. Inventory is a bounded
   list operation, not a pretend event subscription.
2. **Native containerd gRPC (future optional adapter):** subscribe to native
   Events, list containers/tasks under an explicit containerd namespace, and
   resync after reconnect. Task PID plus verified host `/proc` start time and
   cgroup membership can provide cgroup binding evidence. Do not infer
   Kubernetes labels solely from containerd labels. This adds runtime-specific
   dependencies, unnecessary for the independent CRI identity join.
3. **Raw Kubernetes JSON only:** lightweight, but insufficient runtime
   corroboration. The existing Kubernetes REST client can list/watch into real
   Pod objects; client-go/informers are not required.

`internal/workload` stays independent of controller, enforcer, and BPF details.
Inputs are immutable snapshots of Pods, CRI inventory, and caller-verified
cgroup bindings. Outputs are copied corroborated identities, explicit unknown
reasons, and pure selector results. It must not publish policy, write maps,
kill processes, or open sockets.

The cgroup-binding producer is a separate trusted boundary: verify the exact
runtime ID, host mount/cgroup namespace, cgroup inode, boot/lifetime, and PID
start identity where PID evidence is used. Directory-name parsing alone is not
enough. Bind child cgroups explicitly, or prove ancestor resolution. Snapshot
replacement must remove dead bindings; IDs must not be assumed never reused.
This package cannot establish that evidence from CRI list responses.

### Prepared API and dependencies

`FetchInventory(ctx, CRIClient)` calls the real generated CRI methods. Pass
`runtimev1.NewRuntimeServiceClient(conn)`; production connection lifecycle is
deliberately not implemented here. `NewSnapshot(Inputs)` consumes inventory,
`[]corev1.Pod`, and verified `[]Binding`. `Lookup(cgroupID, lifetime)` returns
`Identity` plus `Reason`. Check `Reason == Verified` before interpreting an
empty `Catalog.Select(identity)` as a verified no-match. `NewCatalog` validates
namespace-local selectors and immutable policy references: namespace, UID,
positive accepted generation, and SHA-256 artifact digest.

Dependencies are matching `k8s.io/api`, `k8s.io/apimachinery`, and
`k8s.io/cri-api v0.35.10`, plus `google.golang.org/grpc v1.72.2`. These provide
actual Pod/selector and CRI wire semantics, not hand-written lookalikes. They
add Kubernetes serialization/validation and gRPC transitives and upgrade shared
x/sys, x/sync, x/text, and protobuf versions. No client-go, containerd client,
socket mount, or generated vendored protocol is added. Dependency-only commit
`9924c17` isolates the review cost in `go.mod`/`go.sum`.

`Identity.ImageRef` is a runtime-reported image reference, not an attested OCI
digest. Image-digest policy needs a separate verified image/manifest contract;
runtime image-reference formatting alone does not provide it.

## Policy selection and composition contract

Keep selection separate from composition and activation:

* An explicitly configured cluster baseline is mandatory for all eligible
  workloads. Its default action and treatment of host/system processes are
  installation policy, not an implicit empty-merge fallback.
* Namespace additions apply only to Pods in the policy's namespace.
  Cross-namespace policies need a separate administrator-controlled API, not an
  empty namespace or accidental broad watch permission.
* Workload additions use Kubernetes label-selector semantics, including `NotIn`
  matching an absent key. Labels and expressions are ANDed. Empty selectors
  mean all **verified Pods in that namespace**, never host processes,
  unresolved identities, or all namespaces.
* Select every match, not one by map iteration, name, insertion order, image
  prefix, or object count. Source identity is namespace plus immutable UID;
  include accepted spec generation and artifact digest.
* Preferred initial composition: baseline plus selected additions, with explicit
  denies dominating allows. An addition's default allow cannot override a
  baseline deny. Define `no-match` separately from explicit allow before
  combining independently compiled artifacts. The existing first-match verdict
  ABI does not supply that distinction, so simply merging evaluator results
  cannot safely enable selectors.
* Initial exceptions: none. Pod labels/workload authors cannot grant bypasses.
  A future exception API needs privileged authorship, exact scope, expiry,
  auditability, and an explicit list of overridable baseline rules. Warmor/system
  exclusions are administrator-owned scope, not magic user-settable labels.

The controller must publish a versioned selection manifest plus immutable
artifacts, preserving accepted LKG CR generations on invalid edits. Never flatten
selected policies node-wide. A manifest identifies baseline, namespace,
selector, namespace+UID, accepted generation, artifact digest, compiler/ABI,
and composition version. Agent validation rejects duplicate source identities,
unsupported semantics, missing baselines/artifacts, and digest mismatches.

## Lifecycle, startup races, and unavailable identity

1. Establish host node and boot identity; preflight cgroup/PID namespaces and
   mounts. Start identity-not-ready.
2. List node-local Pods, retain resourceVersion, then watch from that version.
   Handle bookmarks, UID deletion, expiry/410, reconnect, and bounded resync.
   Labels are mutable; resourceVersions are opaque, not numerically ordered.
   Same-name recreation is a different UID. Conflicting old/new Pod objects in
   the same namespace/name must not both become verified.
3. Fetch CRI sandbox/container inventory with deadlines. The lists are not
   atomic; accept only joins corroborated by both and exact current running Pod
   container status. Include regular, init, and ephemeral containers. Attempt
   mismatch/status lag yields unknown, never a guessed join.
4. Correlate host cgroups with exact runtime IDs through the trusted producer.
   Newly discovered cgroups remain unresolved until all sources agree.
5. Atomically replace the complete identity snapshot. Copy caller data; duplicate
   IDs/cgroup claims are conflicts, not last-writer-wins. Invalid individual
   bindings become unknown, not old verified identities. Inventory fetch failure
   is not authoritative emptiness: report degradation and enforce a coordinator-
   owned bounded staleness policy.
6. Recompute selection on Pod label, inventory, or policy-generation changes.
   Stage artifacts/maps, then atomically publish a selection generation to
   userspace/kernel. Cache keys include identity epoch, selected-set digest,
   and activation generation.
7. Deletion/restart/reassignment retires the old selection before another workload
   can inherit it. Late events need event-time/lifetime validation, not just a
   lookup against the current cgroup map. Drain evaluators and invalidate stale
   caches/maps consistently with the activation protocol.

Unknown identity is not an empty-label Pod and must never match selectors.
Distinguish unknown from a verified no-match. The coordinator explicitly chooses
audit-only or a dedicated unknown-scope baseline/quarantine. Never apply another
Pod's policy, expand a selected deny node-wide, or silently claim required
isolation is ready. Known-host handling is separate, not the unknown case.
Required identity freshness and active selected generation participate in
readiness. Liveness must not restart-loop during API/runtime outages.

## Integration requests and Kubernetes release gate

* **Controller:** keep selectors Pending. Agree on manifest/composition and
  accepted generation/digest before publishing selected artifacts. Separate
  Published from authenticated Applied acknowledgements.
* **Kubernetes/runtime wiring:** supply node-local Pod list/watch, authorized CRI
  connection lifecycle, polling/resync/freshness, verified host cgroup binding,
  and dynamic child-cgroup removal/reassignment. Unit tests do not install these.
* **Activation:** bind identity/selection epochs to evaluator leases. Atomically
  commit selected generations with kernel state; reject stale cache hits,
  actions, and in-flight writes following reassignment.
* **Kernel:** route exact cgroup+lifetime/selected generation to the right set,
  including unknown/host handling. Scope default-deny, preloads, and dynamic
  verdicts consistently; clear stale bindings.
* **Main/end-to-end:** prove opposing policies on two Pods cannot affect each
  other or the host. Exercise regular/init/ephemeral containers, late-created
  child cgroups, label changes, restart/same-name recreation, API/runtime outage,
  agent restart, stale events, concurrent reload, audit-first defaults, and
  non-root workloads on supported real nodes.

Only that end-to-end evidence passes the Kubernetes isolation gate. An
independent resolver/selector, a rendered chart, or passing in-memory gRPC tests
alone cannot justify enabling `spec.selector` or reporting Applied.
