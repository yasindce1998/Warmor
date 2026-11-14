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
Even byte-identical output for a new source generation invalidates old receipts.
The node must have the matching mounted manifest, not merely copy a challenge's
revision into a generic heartbeat.

The WASM runtime hashes the actual accepted bytes. The enforcer exposes that
identity and instantiated ABI only from its committed evaluator, after kernel
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

## Evidence and limitations

Tests use owned fake HTTPS Kubernetes servers and real REST TokenReview/GET
implementations, real HTTPS client/endpoint transport, forged identity/replay/
restart/offline cases, byte-identical generation changes and controller status
aggregation. An enforcer test drives actual WASM initialization, real Start and
ActivatePolicy commit/rollback through the receipt client, with only the platform
backend faked. Helm contract tests check opt-in gates, named-node RBAC, projected
audience tokens and separated TLS service. These are not live-cluster acceptance,
real credentials, privileged kernel enforcement or hardware attestation tests.
