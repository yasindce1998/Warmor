# Signed deployment assignments (explicit opt-in)

The daemon's **`--signed-assignments`** mode verifies deployment intent separately
from the artifact signature and persists anti-replay state in its sole activation
record. The central server can durably relay externally signed bundles; it does
not sign them. Default unsigned and existing `--verify-key` behavior is unchanged.
A WASM-only signature does **not** authenticate policy ID, version, targeting, or
deployment authorization. This is not a hosted signer, clock-health service,
automatic canary signer, or a claim of live kernel-generation atomicity.
Daemon activation supports the same Linux/macOS durable fleet platforms as the
base activation path; Windows fleet mode remains explicitly refused. The
standalone signer/store primitives cross-compile for Windows; enforce private
Windows ACLs where Unix mode bits are not available.

## Two separate trust roles

1. **Artifact author/release key:** existing detached Ed25519 signature over
   exact WASM bytes. Keep the private key offline or in a release-signing
   system/HSM. Only this role approves executable content. The central policy
   server ordinarily receives artifacts, signatures and the **public** artifact
   verification key, never this private key.
2. **Assignment key:** a different Ed25519 key approves deploying a particular
   artifact and posture to an exact scope/audience. Provision its public key to
   agents independently of the policy server response. The library takes a
   private key only in `assignment.Sign` and the separate
   `warmor-policy-assignment` command; the daemon and server never load one.
   Prefer a separate deployment signer;
   the central server can relay pre-signed envelopes. Putting an assignment key
   on a server is an explicit trust decision, not a default. It still must not
   give the server the artifact private key.

An assignment signature is not a replacement for artifact verification. With
both enforced, compromise of an assignment signer can deploy any previously
approved artifact within its target grant (including a fresh higher-version
declaration); it cannot approve new artifact bytes without the artifact key.
This library does not prove compiler provenance or policy semantic equivalence.

### Provisioning and rotation procedure

There are deliberately no example private keys, private-key files, or generated
key material in the repository. Key generation and secure distribution remain
operator procedures:

1. Generate **distinct** Ed25519 artifact and assignment key pairs in their
   respective protected signing environments. Export public keys as PKIX PEM
   (`internal/crypto.LoadPublicKey` already parses this format). If file-backed
   keys are used, private keys are PKCS#8 PEM, owned by the signer with mode
   0600 in a mode-0700 directory, never a ConfigMap, source tree, command-line
   argument, container image, agent, or server artifact directory. Prefer a
   hardware-backed signer for production; the current `Sign` API is an in-memory
   software primitive, **not** an HSM integration.
2. Via authenticated administrator/configuration management, provision the
   artifact public trust separately from an assignment `Trust` map. Each
   assignment map entry binds a stable operator-chosen `KeyID` to public bytes,
   **one exact** `Target{Scope, Audience}`, and `CanRollback`. The envelope's key
   ID is only a lookup; no envelope may supply its own trust anchor. Normal
   deployment keys should have `CanRollback: false`; grant a separately
   controlled recovery key `CanRollback: true`. Never reuse artifact key bytes
   for assignment signing. The primitive enforces domain separation, not an
   inventory of your private keys.
3. Provision the same target independently on the agent, along with explicit
   supported ABIs, an immutable compiler allowlist, maximum envelope lifetime,
   and minimum local enforcement requirements. Unknown compiler/ABI, unmatched
   target or untrusted signer fails closed. No wildcard or selector expansion
   is supported. Multiple target grants require separate trust entries/map
   instances and independent durable sequence streams; never change the local
   target based on received metadata.
4. Rotate assignment keys by installing the new public grant through that same
   authenticated channel, temporarily overlapping grants, then using a new
   key ID with a sequence **greater than the agent's persisted high-water**.
   Remove the old grant after rollout. Never reset/recreate agent state or
   restart the deployment counter for a new signer. Serialize trust/config
   changes with commit using the stable `<assignment-config>.lock` file
   (`flock -x` on Unix, or `agentstore.WithConfigurationLock` for embedded users)
   **before** atomically replacing the configuration. The daemon takes that
   same lock and re-verifies current trust immediately around commit/start.
   Never unlink/replace the lock itself. This protocol ensures
   a verification token created before revocation cannot commit afterward.
   Tokens are immutable but not a live revocation service.
5. Artifact trust rotation is separate. Keep the old artifact public key as long
   as approved retained/recovery artifacts require it, or re-sign and verify
   them before removal. Existing single-key daemon configuration does not gain
   an automatic multi-key rotation facility from this change. Removing trust
   can deliberately make a stored active artifact ineligible for restart.

The assignment signer needs a durable monotonic allocator **per exact target**,
shared by normal and rollback signers. Skipped sequences are fine; reused ones
are not. It must reconcile the agent high-water after restore. No signer-side
allocator is implemented here. An attacker who can replace/delete/replay the
agent's entire local storage is outside the file-store threat model: protect it
with host access controls and, where needed, an external monotonic anchor/TPM.

## Envelope v1 contract

All of these are signed:

- format, assignment key ID, exact scope and audience;
- policy ID, positive version, lowercase SHA-256 of exact WASM bytes;
- ABI, immutable compiler identity, audit/enforce mode, default action, and
  required kernel default-deny posture;
- positive uint64 deployment sequence (independent of policy version);
- inclusive `IssuedAt`, exclusive `ExpiresAt`, in UTC Unix seconds;
- either no rollback or an authorization naming the exact current deployment
  sequence, complete current policy identity/posture, and nonempty reason. The
  enclosing signed policy is the exact authorized destination.

Signature input starts with the literal bytes
`warmor/policy-deployment/ed25519/v1\x00`. It then contains fields in the order
listed by `assignment.Canonical`: format u32; key ID, scope, audience strings;
policy; sequence u64; issue/expiry u64; rollback-presence byte; if present,
source sequence u64, source policy, reason string. A policy is ID string,
version u64, SHA-256 **hex string**, ABI u32, compiler string, mode string,
default-action string, require-default-deny byte. Integers are fixed-width
big-endian. Strings are u32 byte length followed by exact valid UTF-8 bytes;
there is no Unicode normalization. Booleans/presence are 0 or 1. Text sizes and
allowed values are validated before signing/verifying. No maps, floats,
delimiter concatenation, or raw JSON appear in the signature input. The tests
include an independently computed canonical-byte golden digest.

The wire representation is the exact compact Go JSON from `assignment.Encode`,
including null rollback and all posture fields, with standard base64 signature
and decimal integer encoding; limit 16 KiB, no trailing newline. `Decode`
requires byte-for-byte re-encoding, rejecting reordered/duplicate/unknown or
missing fields, alternative escapes, whitespace and trailing data. Binary
signature canonicalization is independent of this stricter transport rule.
Use `Encode`/`Decode`, not a generic lossy JSON-number intermediary.

`Verify` checks the signature, target grant, rollback capability, digest,
local ABI/compiler/posture constraints, and bounded validity interval. It returns
an immutable `Verified` token; zero values cannot be committed. It does not
interpret WASM, enable kernel enforcement, or attest a compiler build. Exact
artifact bytes and the actual ABI/runtime/kernel posture must be checked by
the activation owner. Local stricter requirements always win over even an
authorized rollback.

## Replay protection and legitimate rollback

`agentstore` has one exact target per file. It retains:

- greatest committed deployment sequence;
- greatest policy version and full identity at that version for every seen
  policy ID, including across policy changes and signer rotations;
- greatest trusted commit time (nanoseconds);
- the active signed envelope **and** immutable revision-directory basename.

A commit must have a strictly greater deployment sequence. Expiry or a valid
signature never relaxes this rule. Replaying even the current envelope is an
error; idempotent acknowledgement comes from the durable active record, not
re-committing an old message. At uint64 exhaustion, stop and re-enroll through
an explicit administrator procedure; counters never wrap.

An older policy version, different identity at an already-seen version, or
weaker posture than the active policy requires an explicit rollback. This also
applies after switching to another policy ID or rotating signer keys. Merely
using a new policy ID/higher version does not conceal a posture relaxation.
ABI/compiler identifiers themselves have no implied order; allowlists remain
the compatibility boundary.

For a rollback, the verifying key must have `CanRollback`, the new sequence must
exceed high-water, and the authorization's source must equal the exact current
active sequence **and complete policy**, not just its digest/version. A stale
authorization cannot be reused from a different active source. Rollback lowers
neither high-water nor historical policy-version marks. A subsequent forward
deploy above the historical maximum needs no rollback authorization; an
intermediate older version still needs fresh authorization. A same-version
replacement remains exceptional until a higher policy version is adopted.

Content semantics cannot be ordered by digest: a normal signer can authorize
different bytes at a higher version. Release controls/attestations must address
semantic rollback disguised as a new release.

## Crash-atomic publication

The active revision reference and replay marks share **one** checksummed JSON
record. Updates write a mode-0600 temporary file, fsync, rename, then fsync the
parent directory (Windows uses write-through replacement). The process lock
rejects simultaneous writers. Snapshot size is limited to 2 MiB and policy
history to 1,024 IDs; full history rejects writes, never evicts replay protection.
Keep the parent private on a local filesystem with reliable rename, sync and
advisory locks; do not replace/unlink the lock while running.

`Create` is an explicit first-enrollment operation and refuses existing state.
`Open` refuses missing, corrupt, wrong-target and unsupported state and repeats
the durable-publication barrier on the recovered record. It never silently
initializes/reset state or falls back to an older copy. Checksums detect
accidental corruption, not malicious administrator modification or full-disk
snapshot rollback. `Open` validates structure, **not cryptographic trust**;
re-verify the selected envelope/artifact using current trust before execution.

Signed commit uses `Enforcer.ActivateAssignment`'s shared drained, prepared, pre-swap
callback. Immutable module/signature files and their directories must already
be fsynced. After successful commit the evaluator swap must be infallible;
acknowledge only afterward. A crash before commit selects the previous record;
a crash after commit/before swap selects the new record on restart. This is
not a transaction over external kernel state; that must be reconstructed from
the selected record during boot. Kernel-generation atomicity is a separate task.

Pre-rename failures consume no sequence and permit a normal retry. A failed
post-rename barrier has uncertain crash outcome: `ErrIndeterminate` poisons the
store, prevents snapshots/further commits, and must stop activation/acknowledgement
until reopen/reconciliation. Do **not** delete that revision as an unpublished
candidate, auto-rollback the pointer, or accept a lower sequence. Reopen selects
and durably re-publishes whichever complete record survived. Tests inject both
sides of rename and exercise the existing real enforcer callback with a valid
WASM candidate, invalid module, failed clock check, retry, replay and restart.

## Clock and expiry: explicit fail-closed policy

The library does not pretend that `time.Now()` proves clock health. Callers must
establish a trusted wall clock and supply `Clock{Now, Trusted: true}` at verify
**and commit**. Unknown/zero/untrusted time refuses new activation, including
rollback. No unbounded skew allowance exists. `MaxLifetime` is mandatory;
issuance in the future and expiry at or before now are refused. Slow compilation
must not extend authorization: commit rechecks expiry and rejects time earlier
than verification or the durable last trusted commit. The store accepts years
1970–2200 to avoid timestamp serialization overflow.

Expiry is an **activation lease**, not an automatic instruction to remove a
running policy. An already-running verified evaluator is retained if clock
health is lost or its envelope expires; no weaker/unsigned fallback is selected.
On restart, the strict signed-mode integration must verify the selected record
at current trusted time. Unknown time, expired lease or revoked trust must leave
the agent not ready, with no unverified evaluator; provide a fresh signed
authorization through `--assignment-recovery`. Never renew an expired stored lease by rewriting its
timestamp or reusing its sequence.

## Operator configuration

Build `./cmd/warmor-policy-assignment`, `./cmd/warmor-server` and
`./cmd/warmor-daemon` (also included by `make tools`). The deployment signer runs
in a protected environment separate from the relay. First build an artifact
using `warmor-compile`; compiler version 7 embeds `warmor.build.v1` custom
section metadata with compiler identity `warmor-yaml/7` and default action.
Sign the final bytes with the offline artifact key **after** compilation.
Custom toolchains must append `policybuild.Metadata` before artifact signing and
export `abi_version() -> i32`. Signed mode rejects missing metadata/ABI. Metadata
is an artifact-author-approved declaration, not independent compiler provenance
or a proof that arbitrary WASM implements its claimed default action.

Create deployment-intent JSON matching `assignment.Deployment` (all fields,
including `format: 1`, exact `key_id`/`target`, `policy`, newly allocated
`sequence`, UTC Unix `issued_at`/`expires_at`, and `rollback: null` or the exact
source authorization). The signer checks the actual module ABI/digest and its
artifact-signed compiler/default-action metadata, then packages both signatures:

```sh
warmor-policy-assignment --intent deployment-intent.json --wasm policy.wasm \
  --artifact-public-key /protected/public/artifact.pub \
  --assignment-private-key /protected/deployment-signer/deployment.pk8 \
  --out deployment-bundle.json
```

The signer never allocates a sequence, infers a rollback source or uses an
artifact private key. It refuses overwriting output. Intent construction and
durable shared sequence allocation are deliberately operator/signing-service
responsibilities, not guessed from a stale server snapshot.

### Relay

`--assignment-trust-file` enables the relay on `warmor-server` and requires both
`--verify-key` and `--state-file`, even in insecure development mode. The trust
file is a JSON array of **public** grants, for example this shape (replace the
placeholder with independently provisioned public PEM contents):

```json
[{"id":"deployment-2026","public_key":"<PKIX PUBLIC KEY PEM>",
  "target":{"scope":"tenant/prod","audience":"node-1"},"can_rollback":false}]
```

Use the normal authenticated TLS server settings and upload canonical bundle
bytes to **`POST /api/v1/admin/deployments`** with administrator authentication.
The server verifies distinct artifact/assignment public keys, both signatures,
target grant, lifetime (maximum 24 hours), and monotonic per-audience publication;
retained bundles share the configured snapshot/artifact budgets with legacy
policies. Server restart preserves the bundle. Relay admission uses server wall
time only as an additional filter; agents independently require clock health.
Changing relay trust requires server restart; changed/revoked agent trust still
wins over already retained relay content.

**`GET /api/v1/deployment?agent_id=node-1`** requires the matching authenticated
agent identity, or explicit insecure development mode. Exact target scope remains
independently agent-verified. The response is one canonical `assignment.Bundle`:
base64 `envelope` (exact canonical bytes), base64 `wasm`, and base64 raw
`artifact_signature`. Protocol responses have `X-Warmor-Signed-Assignment: 1`.
Conditional polling uses `if_sequence` plus `if_envelope_hash`. Heartbeats retain
`deployment_sequence` and `envelope_hash` alongside full policy identity. A
same-artifact renewal with a higher sequence is activated, not skipped.

Signed relay publication is explicit per audience. It is **not** driven by
legacy label selectors, upload activation, rollouts, abort or canary handlers;
those cannot invent a new signed authorization. Operators must sign and upload
the intended deployment/rollback for each exact audience.

### Agent

Provision an administrator-owned config file:

```json
{
  "scope":"tenant/prod","audience":"node-1",
  "keys":[{"id":"deployment-2026","public_key":"<PKIX PUBLIC KEY PEM>","can_rollback":false}],
  "compilers":["warmor-yaml/7"],"max_lifetime_seconds":3600,
  "trusted_declaration_digests":["<exact lowercase SHA-256 from independently reviewed build>"],
  "require_enforce":true,"require_default_deny":true
}
```

Provision a **separate local time-health supervisor** that checks actual time
synchronization and atomically refreshes a protected JSON file containing
`{"checked_at":<UTC Unix seconds>,"valid_until":<UTC Unix seconds>}`. Leases must
be positive, at most 60 seconds, and include the current time. Unknown sync must
stop refresh; the daemon never writes or manufactures this attestation. Missing,
stale, future or malformed attestations refuse boot/new activation. This is an
explicit local trust boundary, not cryptographically authenticated network time.
The persisted high-water clock rejects regression across restarts/commits.

Create a private mode-0700 state directory on reliable local storage. First
enrollment is explicit and uses the signed bootstrap bundle:

```sh
warmor-daemon --signed-assignments --agent-id node-1 \
  --server https://policy-server.example:8443 --tls-ca ca.pem \
  --tls-cert node.crt --tls-key node.key --verify-key artifact.pub \
  --assignment-config /etc/warmor/assignment.json \
  --assignment-clock-health /run/warmor/clock-health.json \
  --assignment-state-dir /var/lib/warmor/signed \
  --assignment-bootstrap deployment-bundle.json \
  --lsm-enforce --require-lsm --default-deny
```

Omit `--assignment-bootstrap` on subsequent boots; it refuses existing state.
If a selected lease expired or trust was rotated, use
`--assignment-recovery fresh-deployment-bundle.json` instead, retaining existing
state and increasing sequence. Bootstrap and recovery are mutually exclusive.
For audit deployments, choose audit intent and agent requirements, use `--audit`,
and do not claim required kernel default-deny. An enforce intent must match
effective non-audit mode and a platform with enforcement capability. Required
kernel default-deny additionally requires `--lsm-enforce --require-lsm`, a capable
map, and eligible process **and** network static allowlists; preparation failures
prevent publication. Generic reload/SIGHUP, policy file watchers, YAML fallback,
and missing protocol capability cannot bypass signed intent.

The signed root's `assignment.json` is the **only** publication/startup authority;
it replaces PR38's `current`/`previous` pointer publication in this mode. Module
and sibling signature are staged in a private immutable revision directory;
startup compares the artifact digest to the selected envelope, and the runtime
loads its own single verified read. No public alias is maintained. Definite
unpublished candidates are removed; successful or indeterminate revisions are
retained. Automatic garbage collection is not implemented: monitor disk usage,
and never delete a state-selected/uncertain revision or replay history.

Trust changes use the lock procedure above, are re-read after drain, and local
minimum requirements cannot be overridden by a recovery key. Artifact public
trust is fixed for the process; restart is required to change it. Signed startup
rechecks current trust/time before starting capture. Running policy retention on
lease expiry remains intentional; boot and fresh activations still fail closed.

`trusted_declaration_digests` is mandatory in this integration, bounded to 256
exact independently reviewed module digests. Existing in-process optimizations
consume guest dependency/static declarations; a signature, compiler-name custom
section or matching assignment digest does not establish their truth. Do not
automatically populate these pins from a downloaded candidate or signature.
No pin means no signed activation, even for a validly signed audit deployment.

## Validation and remaining boundaries

Tests cover in-process HTTP relay/upload and client transport, real enforcer
event drain, actual ABI/build/posture mismatches, absent protocol, fresh trust/
clock checks, rotation-lock conflicts, sequence-aware acknowledgement/renewal,
restart, rollback, and publication faults. The store also has abrupt-process-exit
and pre-/post-rename tests. No live cluster/server, private release keys, HSM,
external clock supervisor or VM kernel was used to validate this integration.
Kernel generations, replicated relay storage, automated rollout signing, TPM
anti-rollback anchoring, automatic artifact trust rotation and semantic compiler
attestation remain separate work; this mode does not silently simulate them.

### Combining with generation-atomic activation

The generation-activation branch is independent and is not merged here. Its
combined API must preserve **one** error-returning durable commit hook, not a
chain of agentstore and PR38 pointer commits. Strict ABI/build/digest/posture
validation must inspect the same captured candidate used to build the kernel
generation and evaluator; fresh trust/time verification wraps the durable
agentstore commit. Old-generation references must drain according to that
branch's capture contract before retirement, without changing which deployment
is acknowledged.

An error after durable commit or after uncertain kernel publication is not an
ordinary retryable failure. The combined owner must expose explicit terminal/
indeterminate status, stop acknowledgement and competing activation, retain
selected/uncertain artifacts, and reconstruct kernel/evaluator from the selected
agentstore record on restart. It must not roll back only a pointer, reset marks,
acknowledge a rollback that did not publish, or treat two separately successful
commits as a transaction. Failure ordering must be reviewed when combining the
branches; these legacy-map tests do not establish generation-atomic guarantees.

The metadata-owner branch's `internal/policymeta.Source/Module/StaticDomain` is
the canonical shared runtime-observation surface. This branch deliberately uses
`internal/policybuild` only for artifact-signed compiler/default-action **claims**
in a custom section; it introduces no competing runtime metadata model. On
combination, compare `ModuleSHA256` and actual `ABIVersion` from a validated
`Module` against the signed policy, retain absent ABI as 0/reject it in signed
mode, and separately compare artifact build claims. Kernel/cache routing must
use the canonical model's independently trust-gated effective methods, never
raw guest masks/flags/domains. The signed configuration's independent digest
pins can supply the local declaration-attestation input; do not infer that trust
from a signature, build compiler name, or candidate digest. Keep sanitization,
count/key/encoding bounds and copied snapshots from the canonical owner.
