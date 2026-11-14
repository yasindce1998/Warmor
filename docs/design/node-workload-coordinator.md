# Node-local workload coordinator (independent integration boundary)

`internal/workload/coordinator` adds concrete source lifecycle to the immutable
resolver in `internal/workload`. It is **not wired into the daemon, controller,
enforcer, or kernel**. No selector behavior or deployment permission changes.
This is not evidence that workload policy isolation works on a real node.

## Wiring API and ownership

1. Supply an explicitly authorized host node name and Kubernetes runtime scheme.
2. Construct `NewHostVerifier(HostConfig{...})` on Linux, with administrator-known
   host proc/cgroup mounts and independently known namespace identities. Set
   `MaxObservationGap` no larger than coordinator `MaxAge` (e.g. 30 seconds).
3. Construct `NewUnixRuntime(DefaultUnixRuntimeConfig(socketPath, socketUID,
   resolver, verifier))`. No socket discovery, TCP fallback or HTTP runtime shim.
   Whole-cgroup bindings are refused by default. Set
   `AssumeExclusiveCgroupOwnership` only under the separate validated runtime
   ownership contract below; live PID ownership alone is insufficient.
4. Construct `NewPodHTTPSource(DefaultPodHTTPConfig(apiRoot, node, httpClient))`.
   Supply a CA-verifying HTTPS client and rotating token provider (or authenticated
   client transport). HTTP redirects are disabled. Transport ownership stays with
   the caller; configure connection/header/TLS timeouts and close idle connections
   when the application stops. The API needs list/watch Pods; the server-side
   `spec.nodeName` field selector limits data, **not RBAC authorization**. A trusted
   API server and appropriately scoped credentials remain required.
5. `New(DefaultConfig(node, runtime), runtimeSource, podSource)`, then `Run(ctx)`
   exactly once. Run owns the runtime and verifier until cancellation. On a
   construction failure before Run, close already-created resources yourself.
6. Obtain `view := coordinator.Current()`, then
   `identity, reason := view.Lookup(cgroupID, eventLifetime)`. Accept only
   `reason == workload.Verified`. `Ready()` means the two sources are fresh,
   **not** that every cgroup is known or any policy has been activated.

Never manufacture an event lifetime from the current binding. A trusted event
producer must associate the observation with its actual incarnation. The opaque
lifetime includes host boot ID, producer-session randomness, and a monotonically
increasing observed incarnation; it is not a token reconstructible from a PID.
This package deliberately does not export a cgroup-ID-only verified lookup.

Custom Pollers and PodSources are trusted adapters: honor cancellation, bounds,
complete-set semantics, and synchronous callback ownership. The coordinator
copies Pods, protobuf inventory and binding slices before retaining them.

## Runtime PID trust is explicit, not provided by CRI

CRI v1 `ListContainers` and `ContainerStatus` **do not standardize a host PID or
process-start identity**. `TrustedVerboseInfoPID` supports one optional installed-
runtime contract: `ContainerStatus(verbose=true).Info["info"]` contains a numeric
`pid`. Its zero value refuses to resolve anything. Setting
`AssumeLivePIDOwnership: true` explicitly assumes that the authorized runtime
returns the live init PID for that exact container throughout observation,
including protection against stale status and PID reuse. Validate this guarantee
for the installed runtime/version before opting in. Merely observing a positive
integer in containerd/CRI-O verbose output does not prove that guarantee.

The adapter checks exact status ID, running state, creation timestamp, container
name and attempt before observation, then rechecks PID ownership after host
verification. These detect ordinary changes but **cannot fix a lying runtime or
an unchanged cached PID that was reused**. When this trust assumption cannot be
established, use a separately audited native runtime/task-lifetime adapter or
leave resolution disabled. No process-name search, PID enumeration, shortened ID,
directory-name parsing, runtime labels or Pod labels can replace this evidence.

### Exclusive cgroup ownership is a separate required runtime contract

`UnixRuntimeConfig.AssumeExclusiveCgroupOwnership` defaults to **false**, separately
from `AssumeLivePIDOwnership`. Only explicitly opt in if the installed runtime
guarantees that the exact cgroup containing the resolved init PID belongs
exclusively to that container: every process in that cgroup must belong to the
same container, including when other runtime containers cannot be resolved.
This guarantee must cover the binding's use, not merely the instant of one read.
CRI v1 does not provide it; runtime configuration/behavior must be independently
validated, or a separately audited runtime ownership-evidence adapter supplied.
If it cannot be established, leave the flag false and whole-cgroup identities
remain unknown. Host `ProcessClaim` callers must supply the same separate
`ExclusiveCgroupOwnership` assertion; its zero value refuses/retires bindings.

A live, correctly owned PID in `cgroup.procs` establishes membership, **not
exclusive container ownership of the cgroup**. Two containers can already share
a cgroup while only one PID resolves; neither a successful membership read nor
absence of two successful conflicting claims detects that case. No stale PID or
lying runtime is needed. Enumerating members and requiring every PID to be a
container init is not a solution: legitimate container children are ordinary
members. The proc checks below corroborate the cgroup location/lifetime only,
and cannot replace this additional runtime trust boundary.

## Host provenance and retirement

The verifier requires real procfs and unified cgroup-v2 superblocks; a matching
full-root cgroup2 mount in the producer's mountinfo; independently configured
host PID/cgroup namespaces; and the producer running in those host PID/cgroup
namespaces. Delegated cgroup subtrees, cgroup v1/hybrid membership, root cgroups,
relative/escaping membership and missing evidence are refused. `os.Root` pins
authorized roots and prevents file/symlink escape. The administrator must still
authorize those mounts; filesystem type is not an attestation of who mounted it.

For each exact runtime PID claim, it reads host `/proc/PID/stat` start ticks,
unified membership and PID/cgroup/mount namespace links; opens and pins that
exact cgroup directory; verifies its filesystem, device and inode; corroborates
the PID in bounded `cgroup.procs` reads relative to that pinned directory before
and after verification; then repeats the process evidence through both the
retained and current proc PID directories. Host PID namespace membership is
required so `cgroup.procs` numbers and runtime PID claims have the same meaning.
Boot and host namespace provenance are checked each pass. Duplicate PID/container
claims and conflicting cgroup claims are refused. Evidence changes, disappearance,
failed complete polls, excessive observation gaps and reconnection retire continuity. The next successful
observation gets a different lifetime. Holding directory descriptors prevents
an observed cgroup inode being recycled while that evidence remains retained.

Only the exact observed cgroup is bound. Unobserved child cgroups remain unknown;
there is no unsafe ancestor inheritance or recursive scan. Runtime-driven child
enumeration/event evidence is a future adapter, not silently claimed here.
The cgroup inode to BPF cgroup-ID relationship still requires validation on the
supported real kernels. Pinning and double reads are bounded observations, not
a kernel lease on future membership; a process can migrate or exit immediately
after verification. Freshness bounds do not substitute for event-time evidence.

## Freshness, reconnect and resource budgets

* CRI socket path is explicit/absolute, must be a non-world-writable socket
  owned by the configured UID, and every dial verifies Unix `SO_PEERCRED` UID.
  gRPC insecure credentials are used only over that authenticated local Unix
  transport. Administrator-owned parent directories/runtime remain trusted.
* Defaults: 3-second connect budget, 5-second RPC deadlines, 16 MiB receive/
  64 KiB send message limits. Every list/status RPC is bounded by the caller's
  overall 10-second poll budget; no unbounded goroutine-per-container fanout.
  gRPC reconnect uses capped randomized exponential backoff; the coordinator's
  failed poll/watch sessions use capped exponential scheduling (1–15 seconds).
* Pod list uses consistent opaque resourceVersion pagination and checks every
  returned node locally. Watch starts from that version with the identical
  node filter. Bookmarks do not renew the entire cache's age. UID-safe deletion,
  same-name recreation, modified-UID conflicts, terminating Pods, errors/410,
  malformed JSON and stream disconnects are handled conservatively by replacing
  or revoking the complete snapshot and relisting. resourceVersions are never
  parsed as integers or lexically compared.
* Defaults: 2,048 Pods, 8,192 containers/bindings, 4,096 sandboxes, 500 Pods/page,
  16 MiB total list/cache JSON, 1 MiB/event, 32 MiB/watch and 8,192 watch events.
  Watch is bounded to 20 seconds and the whole coordinator sync to MaxAge.
  Thus many small events and many large cached Pods cannot bypass byte bounds.
  Object allocations have Go/JSON/protobuf overhead; these are finite input
  budgets, **not** an exact RSS guarantee. Tune below installation memory limits.
* Host evidence reads have per-file byte bounds; no recursive proc/cgroup walks.
  Pinned cgroup descriptors peak at twice MaxBindings during replacement (plus
  roots and a constant transient overhead). Configure that cap and RLIMIT_NOFILE
  together. Unsupported/permission-denied containers remain unknown.
* Successful polls run every 5 seconds. MaxAge defaults to 30 seconds, measured
  from source-operation start, not completion. Every Pod event shares that
  list/watch session's original freshness deadline. Every failed source operation
  revokes immediately; neither old inventory nor a bookmark renews identity.
  Retained Views check the deadline directly even before expiry notification.
* Every publication has a new epoch. Replacement, deletion, failure, expiry and
  shutdown invalidate retained Views. Notifications are bounded, nonblocking,
  metadata-only and lossy, with a dropped counter; reconcile from Current rather
  than relying on events as a security log. Expiry is also explicitly published.

## Still required before workload enforcement

Daemon wiring, event-time lifetime production, selected-set generation/digest
activation, cache invalidation, evaluator/action leases, exact kernel routing,
unknown-scope policy, host-scope policy, readiness integration and real-node
opposing-policy tests are intentionally not implemented. View epochs help the
activation integration fence work but do not make a userspace lookup and a kernel
action one atomic transaction. A result must still be revalidated/fenced at
activation/action commit. Unknown is never a verified host task or no-match Pod.
Selectors must remain disabled/Pending under the main integration's safety gate.

Tests use test-owned TLS HTTP, Unix fake gRPC servers, and proc/cgroup fixtures
only. Fixture construction bypasses filesystem-superblock checks internally;
there is no exported production bypass. No cluster, real runtime socket, host
process inventory, privileged mount or kernel enforcement test is used.

## Local validation (2026-11-14)

* `go test -race -count=30 -cover ./internal/workload/...`: passed; coordinator
  statement coverage 84.0% (not a proof of enforcement or race completeness).
* `GOMAXPROCS=2 go test -p 2 -race ./...`: passed.
* `GOMAXPROCS=2 go vet -p 2 ./...`: passed.

Coverage includes concrete adapter composition, authenticated fake Unix CRI,
deadlines/reconnect, malformed/untrusted PID claims, post-observation runtime
claim changes, outage lifetime retirement, paginated TLS Pod list/watch,
node filtering, opaque versions, recreation/delayed deletion, byte/object
budgets, proc/cgroup membership and namespace fixtures, PID start changes,
escape refusal, duplicate claims, incarnation gaps, retained-view revocation,
concurrent readers, expiry, shutdown, and event backpressure. Production host
mount acceptance and actual cgroup/BPF-ID equivalence remain real-node gates.
