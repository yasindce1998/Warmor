# Authenticated node activation receipts (explicit opt-in)

Default behavior is unchanged: compilation and ConfigMap publication produce
`Published`, with `Applied=Unknown`. A download, mounted file, prepared WASM pool,
empty node set or controller readiness probe is **never** application evidence.
Selectors (including `{}`) remain Pending and cannot acquire Applied/Ready for
their desired generation from a retained node-wide generation's receipts.

## Trust and identity boundary

This feature authenticates **node self-reports, not remote attestation**. A
compromised node/daemon can lie about its own activation, steal its own pod token,
or deny service. Neither receipts nor `Applied=True` prove workload coverage,
kernel generation atomicity, successful prevention, or policy correctness.
An audit-mode activation remains audit-mode; its receipt is not enforcement.

The HTTPS endpoint accepts only a dedicated-audience, projected, **pod-bound**
ServiceAccount token. On **every** registration and receipt it uses the real
`authentication.k8s.io/v1/tokenreviews` REST API, with an explicit audience, and
requires authenticated response audiences and the exact authorized SA username.
It never decodes/trusts an unverified JWT payload. Legacy/static unbound SA
tokens are rejected. Kubernetes must return verified `pod-name` and `pod-uid`
authentication extras; missing support fails closed.

Synchronous Kubernetes GETs then verify:

* the live ServiceAccount UID equals TokenReview `user.uid`;
* the bound Pod UID/name/namespace, its `spec.serviceAccountName`, Running state,
  and controller ownerReference to the configured live DaemonSet UID;
* `spec.nodeName` from that Pod and the live Node UID;
* the daemon container's Running containerID, restartCount and startedAt epoch.

There is no client node-name argument, node-label identity or shared-SA-to-any-
node permission. Two daemons using the same SA can only report the node assigned
to their own API-verified bound Pod. Kubernetes API authentication, node/pod
assignment, the controller and ConfigMap writers are trusted. Restrict who can
create/edit pods with this SA, forge ownerReferences, mutate Pod/node status,
replace the DaemonSet, write the publication, or create SA tokens. Tokens are
bearer credentials: theft across nodes defeats isolation for the stolen identity.

## Exact generation, activation, freshness and restart fences

`activation-manifest.json` is committed in the **same ConfigMap write** as WASM
bytes and the accepted-source journal. It binds source namespace/name/UID and
**accepted generation**, snapshot SHA-256, desired revision, artifact SHA-256,
compiler identity, generated ABI and expected actual audit/learning/LSM posture.
`compiler` is the controller composition/cache profile (currently based on
compiler 7), not an assertion that the runtime compiled the module. The separate
`artifactCompiler` and `defaultAction` match the module's `warmor.build.v1`
declarations, emitted by the current compiler (`warmor-yaml/7`). Receipt mode
requires those declarations and compares them with the **same captured pool
identity used by signed assignment validation**, alongside digest and ABI. Missing
or contradictory artifact declarations cannot qualify. These are author-approved
build claims, authenticated only if an artifact signature was verified; they are
not independent proof of compiler provenance or arbitrary WASM semantics.
Even byte-identical output for a new source generation invalidates old receipts.
It also includes a **nonreusable random `publicationEpoch`**, persisted atomically
with each changed publication. No-op reconciliation preserves the committed
epoch, including across controller restarts; failed/conflicting writes do not
advance it. A successful A→B→A transition creates a new epoch for the returned A,
even with identical bytes, revision and accepted generations. Consequently no
old A receipt can resurrect if aggregation/watch processing misses B entirely.
Epochs are integrity-bound by the manifest ID, mounted manifest and authenticated
session; they do not add a signature or authentication against trusted ConfigMap
writers. Legacy manifests without an epoch are ineligible and must be republished.
The node must have the matching mounted manifest, not merely copy a challenge's
revision into a generic heartbeat.

The WASM runtime hashes the actual accepted bytes and the pool captures that
digest, instantiated ABI and build declarations with its compiled module. The
enforcer exposes that canonical pool identity only from its committed evaluator, after kernel
preparation and publication callback succeed. Startup must also have a running
event loop and local platform readiness. Failed load/commit retains the previous
identity; failed kernel rollback invalidates acknowledgement until recovery.
Receipt code never hashes the current policy pathname to infer active state.
`defaultDenyRequested` describes a request, **not** static-rule eligibility.

The daemon creates a new random boot epoch per process. Registration issues a
server-random, expiring challenge bound to the authenticated Pod/node/container
epoch and the exact manifest, and clears previous evidence for that node. Receipt
sequence numbers strictly increase within a registration. Challenge, boot epoch,
sequence, measurement time (bounded past age and 5s future skew), activation time
and exact active identity must match. Server restart clears registrations;
daemon re-registration fences old receipts; authoritative container restart and
Pod/node/SA replacement invalidate prior evidence during aggregation. A process
restart not yet visible in Kubernetes has a bounded stale window until fresh
registration, API status propagation or receipt expiry—not a hardware boot proof.

Every current-session report first passes bound-pod authentication, challenge,
boot epoch, strictly increasing sequence and measurement freshness checks. Only
then does it consume the sequence and revoke the prior positive evidence. A fresh
contradictory digest/ABI/posture/manifest or missing activation therefore cannot
leave the previous positive counted, even though its positive claim is rejected.
Stale, out-of-order or other-session reports cannot revoke newer evidence.
Explicit `withdrawn=true` reports use the same fences and do not require a healthy
desired-publication read. They assert no active digest. The daemon attempts this
authenticated withdrawal on any local Active error, readiness/identity mismatch,
or mounted-manifest failure before discarding its session. A new successful
registration and genuine matching active report can restore eligibility.

This is **not instantaneous failure detection**. If authentication, network, API
access or the controller endpoint is unavailable (including cancelled requests),
withdrawal cannot be confirmed. Previously accepted evidence may remain counted
until its existing challenge/receipt expiry; the client explicitly reports this
expiry-only bound and does not claim successful revocation. Between reporting
intervals there is likewise a detection window. Consumers must honor the hard
expiry below, and status only reflects revocation after a successful reconcile.

Aggregation re-reads the desired publication and live DS/SA/Pod/Node identities.
It requires a nonempty **operator-supplied complete desired node roster**, a
matching observed DS desired count, exactly one authorized Running daemon per
required node, Node Ready and a fresh exact-manifest receipt from every one.
The roster never shrinks to online reporters. Missing/offline/stale/replaced pods,
API errors, ambiguous duplicate daemons and zero desired nodes cannot yield
Applied=True. A desired-roster change requires an operator rollout; mismatched
DaemonSet desired count safely holds Unknown. The explicit roster is trusted
configuration, not a general reimplementation of Kubernetes scheduling.

Only current desired generations can become `Active`, `Applied=True`, Ready,
with `nodesApplied` and oldest fresh measurement `lastApplied`. Otherwise the
normal Published/Pending/Error semantics remain. Opt-in reconciliation checks
freshness at least every 10s **when reconciliation completes**. Status is a
snapshot, not a health lease: **consumers must check `receiptExpiresAt` against
their own clock**, and treat Applied as Unknown after expiry even if the
controller is stopped, compiling or partitioned. Probes remain local-only.

## Deployment gates and least privilege

Nothing is automatically trusted or issued. The chart defaults
`controller.nodeReceipts.enabled=false`, emits no TokenReview RBAC or token
projection in that mode, and refuses opt-in without all of:

```yaml
controller:
  enabled: true
  nodeReceipts:
    enabled: true
    audience: warmor-node-receipts.example.internal
    tlsSecretName: operator-provisioned-controller-tls
    caConfigMapName: operator-provisioned-controller-ca
    requiredNodes: [worker-a, worker-b] # complete desired daemon placement
    maxAge: 1m
```

Before enabling, an operator must provision `tls.crt`/`tls.key` in the release
namespace and a CA ConfigMap containing `ca.crt`. The server certificate SAN must
match `<fullname>-controller-receipts.<namespace>.svc`. Use a dedicated trust CA
and audience, not the Kubernetes API token audience. No insecure TLS bypass or
HTTP redirect is accepted. The controller also refuses receipt mode with an
unverified/plaintext Kubernetes API configuration. Certificate rotation requires
a controller restart; daemon CA changes require daemon restart. The chart
projects 600s audience-specific bound tokens, read again on every request. It
does not create any TokenRequest resources or grant daemons API RBAC. Existing
automountServiceAccountToken=false remains unchanged.

Apply the updated WarmorPolicy CRD before enabling: Helm does not upgrade files
under `crds/`. The additive `status.receiptExpiresAt` field must survive API
schema pruning. Consumers must reject an Applied claim with a missing expiry.

The opt-in controller ClusterRole grants **create tokenreviews only**, plus
**get** on named required Nodes. TokenReview creation is necessarily cluster-
scoped and can validate other tokens if compromised; it cannot be namespaced or
meaningfully resourceNames-limited. We deliberately do **not** bind
`system:auth-delegator` (which additionally grants SubjectAccessReview creation),
wildcards, cluster-admin, TokenRequests, Secrets or node writes. A namespaced
Role grants pod get/list, get on the named daemon SA, and get on the named DS.
Remove these bindings when disabling the feature. Review your CNI's hostNetwork
behavior: NetworkPolicy isolation for host-network daemons is implementation-
dependent, and TLS/authentication remains mandatory regardless.

Direct binary deployments can use `warmor-controller --node-receipts` with the
`--receipts-*` identity/roster/TLS/posture flags and daemon
`--receipt-controller=https://… --receipt-token-file=… --receipt-ca=…
--receipt-manifest=…`. No identity is taken from `--agent-id` or event labels.
Bare defaults/no CR sources and legacy ABI-0 artifacts do not qualify for desired-
generation acknowledgement. No fleet policy-server download claim is reused.

Controller receipts and fleet assignment intent are **separate, incompatible
deployment modes** in this integration. Combining `--receipt-controller` with
either `--server` or `--signed-assignments` is rejected at daemon entry, before
trust stores, TLS clients/listeners, policy loading or platform capture. Library
`ActiveReceipt` also refuses signed-assignment enforcers. The signed fleet's
bootstrap, clock/trust rechecks, durable state, compatibility validation and
generic-reload refusal are unchanged; no fleet assignment claims become controller
generation evidence. Detached `--verify-key` **artifact verification**, without
fleet mode, remains compatible and is tested through actual startup/activation
and HTTPS receipts. The chart does not provision detached policy signatures;
operators using artifact verification must provision a matching signed module
pair. The mounted controller ConfigMap remains the trusted desired-publication
channel, not a signed fleet-intent envelope.

Optional acknowledged-decision telemetry remains a separate contract. Controller
receipt mode does **not** supply `Options.Telemetry`, create a telemetry lease,
or use decision counters/activation labels as Applied evidence. For embedded
callers that do supply a collector, the shared enforcer transaction captures
`Pool.Identity()` and performs telemetry Replace/Seal only after kernel
preparation and durable commit, under the existing activation/evaluator/drain
locks. A caller-supplied telemetry revision cannot substitute for the pool's
actual artifact digest/ABI/build claims. Failed commits retain the previous
evaluator (never acknowledge the candidate); a failed kernel rollback invalidates
receipt acknowledgement and the client withdraws prior evidence. Ordinary
activation seals telemetry attribution without discarding a genuine committed
receipt identity. None of this wires canary telemetry into controller status.

## Evidence and limitations

Tests use owned fake HTTPS Kubernetes servers and real REST TokenReview/GET
implementations, real HTTPS client/endpoint transport, forged identity/replay/
restart/offline cases, byte-identical generation changes and controller status
aggregation. An enforcer test drives actual WASM initialization, real Start and
ActivatePolicy commit/rollback through the receipt client, with only the platform
backend faked, including A→B local activation drift and A→B→A publication epochs.
Fault tests cover fresh contradictions, explicit withdrawals, stale positive/
negative replay, failed/conflicting publication writes, no-op/restart epoch
stability, and transitions with no intermediate aggregation tick. Helm contract
tests check opt-in gates, named-node RBAC, projected
audience tokens and separated TLS service. These are not live-cluster acceptance,
real credentials, privileged kernel enforcement or hardware attestation tests.
