# Signed deployment assignments (library foundation)

**Not enabled or wired into the daemon/server.** This change adds
`internal/crypto/assignment` and `internal/agentstore`, plus tests of the real
enforcer commit callback. It does not add CLI flags, a network endpoint, a
signing service, or a production clock-health provider. Existing unsigned and
`--verify-key` behavior is unchanged. A WASM-only signature does **not**
authenticate policy ID, version, targeting, or deployment authorization.

## Two separate trust roles

1. **Artifact author/release key:** existing detached Ed25519 signature over
   exact WASM bytes. Keep the private key offline or in a release-signing
   system/HSM. Only this role approves executable content. The central policy
   server ordinarily receives artifacts, signatures and the **public** artifact
   verification key, never this private key.
2. **Assignment key:** a different Ed25519 key approves deploying a particular
   artifact and posture to an exact scope/audience. Provision its public key to
   agents independently of the policy server response. The library takes a
   private key only in `assignment.Sign`; it never discovers, generates, stores,
   or automatically loads a private key. Prefer a separate deployment signer;
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
key material in the repository. The following are operator procedures, not
implemented CLI commands:

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
   changes with prepare/commit (or re-verify with current trust in the callback)
   so a verification token created before revocation cannot commit afterward.
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

Commit belongs in `Enforcer.ActivatePolicy`'s drained, prepared, pre-swap
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
authorization through a pre-start recovery path. That recovery/bootstrap path
is not implemented here. Never renew an expired stored lease by rewriting its
timestamp or reusing its sequence.

## Required main activation/protocol hooks (not implemented)

1. Add an explicit signed-assignment opt-in mode and local trust/target/state/
   clock configuration. Validate them at startup. Legacy unsigned mode remains
   unchanged; once opted in, missing/invalid envelopes, lost state, unknown
   time or unsupported server capability **must never downgrade** to legacy
   WASM-only/unsigned verification or policy fallback.
2. Carry the exact encoded envelope alongside the artifact. Bind it to the
   downloaded metadata/digest and authenticated request identity. Existing
   `PolicyAssignment`, server persistence and rollout signing need schema/
   capability negotiation, signer-side durable sequence allocation, and
   authorized rollback issuance; none is faked by this library.
3. `ClientConfig.Verify` can verify downloads but cannot consume replay state
   before activation. `OnUpdate` must stage exact verified bytes, validate actual
   ABI/declared posture against effective daemon and kernel settings, drain and
   prepare via `ActivatePolicy`, and call `agentstore.Commit` in its commit
   callback with a fresh trusted clock/current trust decision.
4. **Replace**, do not chain, `stagedPolicyRevision.commit`'s separate `current`
   pointer authority for signed mode. Store `assignment.json` inside the revision
   root and use `Active.Revision` as the sole startup/publication reference.
   Any aliases are derived conveniences and cannot drive restore or security
   decisions. The existing `discard` method knows only `current`/`previous`;
   change retention to protect the state-selected revision and every uncertain
   publication before using it. Do not run two independent durability commits.
5. At signed-mode boot, `Open` state without automatic create, select one
   immutable revision, read once, verify its artifact signature and assignment
   with current trust/time, compare actual ABI/effective posture, then load
   exactly those bytes and reconstruct kernel state. Never choose `previous`
   just because current validation fails. A real rollback needs a fresh
   authorization and higher sequence through the recovery path.
6. Extend heartbeats/conditional polling with deployment sequence and full
   active identity; seed them from the durably restored and successfully loaded
   record. Same-artifact lease renewal must not be skipped by version/hash-only
   comparison. Re-acknowledge a matching restored record without replaying commit.
   Handle `ErrIndeterminate` as a fatal reconciliation requirement, not an
   ordinary failed download. Tests of these future hooks are required before
   claiming end-to-end signed-assignment enforcement.
