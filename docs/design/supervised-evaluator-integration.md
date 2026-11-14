# Experimental supervised evaluator integration

Status: **off by default, Linux only, not production validated**. This branch
connects the reviewed policy-host and metadata APIs to the enforcer, including
generation slots. It does not attach any security hooks in its tests or change
the default in-process backend. The process boundary/resource limitations in
`supervised-policy-host.md` still apply: this is not a general OS sandbox, an RSS
quota, protection from a compromised trusted host executable, or protection from
daemon downtime.

## Configuration and trust

Explicit opt-in is `--experimental-supervised-policy-host`, with `--verify-key`,
an absolute `--policy-host` executable path, and lowercase
`--policy-host-sha256`. There is no PATH search, environment inheritance, shared
compilation cache, automatic fallback or worker respawn. The standalone command
must currently be built/installed separately; release packaging is follow-up.
The flags select an active backend, not an informational readiness label.

`--policy-declaration-digests` is an optional comma-separated, administrator-owned
attestation of exhaustive deterministic declarations for exact module digests.
It must not be populated from downloaded assignments, signature verification,
compiler display labels or worker readiness. Empty means **no decision cache,
kernel cache or static allowlist authorization**. Raw `Metadata()` observations
remain available but only `policymeta.Source`'s effective methods authorize
optimizations. PR41's shared **127-byte process path** limit applies to compiler,
runtime static tables and metadata, for both JSON and binary encoding. Transport
pattern/frame maxima do not enlarge the kernel identity contract.

## Preparation and ownership

`Evaluator` combines Evaluate, Close and canonical `policymeta.Source`. A
`policyBackend` owns the whole evaluator/pool/runtime or single child lifetime;
generation slots share the owner only for initial IDs 0/1. All teardown is
idempotent. Comparing pool pointers is deliberately not used: all supervised
pools are nil, while different hosts have different lifetimes.

The supervised startup path resolves an immutable revision pair, stages a
signature-verified byte snapshot, and waits for bounded child-observed metadata
before platform creation. Generation candidates read verified bytes once and
stage exactly that snapshot; readiness and static completeness checks precede
kernel Prepare. The parent never invokes WASM Decode, custom-section parsing,
validation, compilation or instantiation on this path. The enforcer binary still
imports the legacy runtime because that remains the default backend.

The existing generation commit model is unchanged: register evaluator, commit
kernel pointer, publish userspace, invoke the sole durable callback, fence ring
events and drain captured leases, then retire the old host. A failed durable
commit retains both owners and the original closure/revision. Retrying the same
candidate finishes recovery without another child or kernel Prepare. Failed
preparation only closes/reaps the candidate. Worker evaluation/IPC/limit failure
denies that event without caching the error; the failed host remains terminal.
Reaped hosts cannot serve prior userspace cached allows. Health checks are
snapshots, not atomic liveness proofs; separately authorized static/kernel rules
are not globally revoked merely because their evaluator child exits.
Only an explicit activation starts another host. Budgets are process-lifetime
budgets: request/CPU exhaustion requires operator-controlled activation, not a
hidden renewal loop.

## Signed assignment seam

`Options.ExpectedAssignment` and `ActivateAssignment` validate actual digest,
ABI and authenticated build claims using `Source.Metadata().MatchArtifact`,
including in host mode. They also check effective runtime posture and trusted
static eligibility when default-deny is required. They do **not** verify signed
deployment intent, target, expiry, anti-replay or clock health: that remains the
assignment/agentstore caller's responsibility. A detached artifact signature
does not establish compiler provenance or truthful dependency declarations.

`ExpectedAssignment` disables generic reload/activation. Assignment activation
requires an artifact verification key and exactly one durable callback.
**Signed-assignment + atomic-generation startup/activation is explicitly rejected**,
including supervised mode, until a shared commit/recovery model is tested. This
branch does not wire the separate signed-mode daemon/client. Its flags are not
silently emulated, nor is agentstore nested inside legacy fleet publication.
Detached artifact signatures with unsigned fleet generations remain supported.

The standalone `--validate-policy` command remains the legacy in-process
validator and explicitly rejects all supervised flags, so selecting supervised
mode cannot silently route validation through the parent runtime.

## Evidence and remaining gates

Unprivileged integration tests build the actual host command and substitute only
the platform/kernel publication boundary. They exercise captured old-host leases,
post-commit uncertain durability, exact retry ownership, bad signatures and
malformed candidates before Prepare, terminal worker timeout/noncached denial,
effective trusted static/cache methods, and actual child-observed ABI/build
assignment mismatches. A real compiler-heavy valid module must hit the parent's
load deadline while active-generation events continue; immediate next activation
checks killed-child reaping/capacity release. No sleeper/mock worker stands in
for compilation.

Whole-daemon supported-kernel VM evidence, release packaging, sustained resource
and event-loss tests, native non-Linux execution, restart/power-loss continuity,
and the combined signed/atomic commit model remain open. No host-wide enforcing
run or BPF feature/object change is claimed here. Validation commands/results
are recorded at the final checkpoint, not inferred from this test inventory.
