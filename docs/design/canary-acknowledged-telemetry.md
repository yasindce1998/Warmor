# Canary telemetry: acknowledged-revision aggregate contract

**Status: proposed integration contract, not a shipped rollout gate.**

This document accompanies analyzer-only hardening. It adds no heartbeat field,
HTTP endpoint, telemetry ingestion library, evaluator loop, automatic rollback
flag, or rollout persistence change. Manual rollout operation is unchanged.
In particular, heartbeat liveness, a download, and a desired assignment are
**not** evidence that a policy was activated. Automatic fleet rollback must stay
disabled until the activation acknowledgement and the integration gates below
are implemented and tested.

## What the local library now guarantees

`internal/policyserver/canary.go` remains a library for **trusted local** decision
attribution. `RecordDecision(rolloutID, isCanary, denied)` is not suitable as a
fleet ingest API: the boolean has no identity, revision, deduplication, or
activation proof. Do not call it from a heartbeat handler in a loop over counts.

- `CanaryConfig.Validate` requires a finite deny-rate delta in `[0,1]`, positive
  minimum samples, nonnegative observation duration, and a positive bounded
  sample-retention window. `SampleWindow == 0` selects 10 minutes; the maximum is
  24 hours. Observation duration cannot exceed sample retention. Zero observation
  duration deliberately allows immediate **library** evaluation, not production
  gate enablement.
- `Configure` now returns an error. Invalid changes leave existing state intact.
  Equivalent configurations preserve observations; changed configurations reset
  evidence. A successful abort stays latched until explicit `Reset`.
- Only explicitly configured rollout IDs can allocate sample state. Callers own
  the configured-rollout cardinality limit and `Reset` on terminal cleanup.
- Each configured rollout has 128 fixed aggregate buckets, not an event list or
  lifetime counter. Samples expire on reads, records, and evaluations. A bucket
  expires as a whole, up to one bucket width early, never late. Memory is
  `O(configured rollouts * 128)`, independent of decision rate. This conservative
  approximation may leave a sparse window pending.
- Observation age starts with accepted decisions, not idle configuration time;
  it resets once all samples expire, stays nonnegative on backwards clocks, and
  is capped by sample retention. Both cohorts must independently have the minimum
  retained sample count. This is not proof of fleet coverage or continuous traffic.
- Zero samples never divide by zero. Counter overflow produces pending,
  `sample_overflow=true`, and empty counts rather than a partial health verdict.
- Failed `AbortRollout` calls leave evaluation **degraded**, return `false`, and
  populate `rollback_error`; later evaluations may retry. Only a nil abort error
  latches `rolled-back` and returns `true` once. `Metrics` never attempts abort.
  The legacy verdict means **control-plane abort accepted**, not fleet revert
  acknowledged. A separate fleet convergence state is required at integration.

Existing statement-style `Configure(...)` callers compile, but integration must
check its new error return. No production caller should ignore validation errors.

## Additive interface (proposed, deliberately not implemented)

Add a distinct aggregate ingestion interface after activation acknowledgement is
stable. Use validated integer counts, not event lists, floats, rates, caller
supplied cohorts, or cumulative process-wide allow/deny metrics.

```go
// Proposed shapes, not exported API or current heartbeat fields.
type TelemetrySource struct {
    AgentID       string // authenticated principal, never trusted from payload
    SessionID     string // server-authorized collector/process incarnation
}

type AcknowledgedRevision struct {
    PolicyID          string
    PolicyVersion     int64
    WASMHash          string
    AssignmentRevision uint64 // opaque equivalent is fine; not policy version
    ActivationID      string // distinguishes A -> B -> A activations of A
}

type DecisionSnapshot struct {
    SchemaVersion uint32
    Revision      AcknowledgedRevision
    Sequence      uint64 // strictly increasing within SessionID, starts at 1
    Total         uint64 // cumulative only within this ActivationID
    Denied        uint64 // <= Total; same decision population and activation
}

type CanaryTelemetry interface {
    Ingest(source TelemetrySource, snapshot DecisionSnapshot) (IngestResult, error)
}
```

`IngestResult` should distinguish accepted contribution, cursor-only/bootstrap,
duplicate, stale, and ineligible attribution. The ingest operation never aborts
or advances a rollout; a separate, initially report-only evaluator consumes its
window view. The server supplies receipt time and authenticated identity. A
trusted activation/assignment ledger supplies immutable acknowledgement and
cohort evidence; the snapshot cannot manufacture that evidence.

The exact names and representation of assignment revision, activation token,
session lease, and hash must follow the activation branch's final types. Do not
invent independent lookalike acknowledgement state in the analyzer.

The activation work currently adds `HeartbeatRequest.PolicyID`, `PolicyHash`,
and `ActivationError` alongside `PolicyVersion`, with corresponding stored
agent fields. These distinguish applied artifact identity and failed activation
from desired assignment. They do **not** supply an assignment/cohort generation,
collector-session lease, per-activation identity, or snapshot sequence. Therefore
landing that acknowledgement work alone is necessary but insufficient for this
aggregate contract. Reuse its `PolicyHash` as the artifact identity rather than
introducing a competing hash field on the wire; add the missing fenced identities
and ledger semantics explicitly in a subsequent integration change.

## Attribution and activation boundary

1. Authenticate the request and bind `AgentID` to the principal before ingestion.
   Authorize `SessionID` against one live collector incarnation. Re-registration
   alone must not permit replay of a revoked incarnation. Never derive the
   identity from an embedded telemetry field.
2. Resolve the complete revision tuple against a recorded **successful local
   activation acknowledgement** for that agent/session. Require policy identity,
   policy version, artifact hash, assignment revision, and activation identity.
   Policy version alone collides between policies; artifact hash alone does not
   identify assignment/cohort generation.
3. Resolve a server-authored rollout generation and cohort from the acknowledged
   assignment history. Store this association with the cursor. Never recompute
   a historical sample's cohort using today's percentage or labels. An agent
   still running the old revision after receiving a canary assignment does not
   become a canary observation. Ambiguous, stale, failed, revoked, unassigned, or
   mismatched activations contribute to neither cohort, with a reason counter.
4. Each successful activation starts fresh counters and a distinct ActivationID,
   even if the same policy/version returns after an abort or retry. Seal the old
   collector before swapping the active revision; a snapshot must not straddle
   revisions or mix audit/monitor decisions with enforced decisions. Initial
   delivery may drop unsealed late old-activation reports rather than guess.
5. A percentage, label, policy, cohort, configuration, or collector-session change
   must not move accumulated counts to a new generation. Require a new eligible
   assignment/activation boundary and baseline cursor, or explicitly seal the
   old segment with ledger evidence. Fail closed to pending if this is missing.

Counters cover one documented population: finalized policy allow/deny decisions
for that acknowledged revision and enforcement mode. Specify treatment of
timeouts, evaluation failures, audit-only denies, fallback decisions, and lost
events before shipping. Do not silently fold these into `Denied`; expose loss
and quality indicators and keep the gate pending when data is unreliable.

## Sequencing, deduplication, and atomicity

Keep a high-water sequence and payload digest per authorized source session,
plus the last eligible activation's cumulative counters and attribution key.
All validation, cursor advancement, and aggregate contribution must be one
transaction/critical section.

- First report for a session or activation establishes a cursor and contributes
  **zero**, even if its counters are nonzero. Never count unknown prehistory.
  A zero-counter bootstrap followed by a normal snapshot permits all new work.
- Same sequence with identical normalized payload is an idempotent no-op. Same
  sequence with different content is a conflict, not an overwrite. Lower
  sequences are stale and cannot mutate counts or cursor. Sequence wrap is an
  error; establish a new authorized session rather than wrapping.
- For a higher sequence in the same activation, cumulative counters cannot
  decrease. Compute `deltaTotal = Total - lastTotal` and
  `deltaDenied = Denied - lastDenied`; require `deltaDenied <= deltaTotal` as
  well as `Denied <= Total`. A higher sequence with identical counters advances
  the cursor but adds no decisions. A sequence gap can be accepted because the
  counters are cumulative, subject to the freshness/window checks below.
- Malformed reports do not advance any cursor or partially update either
  cohort. A valid but expired/ineligible report can advance a cursor without a
  contribution; record why so its old counts cannot enter a later fresh window.
  The authenticated session high-water survives activation changes, preventing
  a delayed previous activation report from switching the active cursor back.
- Reject reports exceeding bounded identifier lengths, body size, supported
  schema, allowed batch count, maximum reporting gap, or checked integer totals.
  Never cast `uint64` telemetry counts to the local analyzer's `int` counters.
  The aggregate path needs checked `uint64` additions and a pending-on-overflow
  quality state. Compute rates only from validated nonzero denominators.

Concurrent duplicate delivery must add a delta at most once. Persist cursor and
contribution atomically if promising restart continuity. Otherwise declare a
new analysis generation on server restart: discard windows, seed all cursors,
require new observation and coverage, and forbid automatic actions until then.
Restoring one side without the other causes replay or lost evidence.

## Window, time, and resource bounds

Use server monotonic receipt time, not agent wall-clock timestamps, for the
initial conservative window. A delta represents the interval from the previous
accepted snapshot receipt to this one. Count it only when the whole interval
belongs to one eligible activation/cohort generation, the previous cursor is
still within the retained window, and the interval is no larger than a bounded
reporting gap. Otherwise advance/seed the cursor and drop the interval. Never
spread a lifetime counter uniformly across time or put arbitrarily old backlog
into the current window. Agent event time can be diagnostic only until there
is a clock/interval validation protocol.

Aggregate accepted deltas into fixed rolling buckets with conservative expiry,
like the local analyzer. Window membership is an approximation of decision time
bounded by the reporting-gap limit, not exact remote event-time accounting.
Expose that bound and reporting lag. Require positive production warm-up time,
minimum fresh samples **and minimum independently acknowledged sources per
cohort**, acceptable coverage/loss, and a full fresh observation generation
before a health verdict. A busy or compromised agent must not be mistaken for
fleet coverage. Missing baseline, no traffic, stale sessions, or all-canary
assignment remains pending, never healthy by default.

Cap active rollouts, configured windows, sources per rollout, identifier sizes,
reports per request, and global cursor memory. No raw event retention or
agent-controlled Prometheus labels. Eviction revokes or forces cursor-only
rebootstrap of that source, never recounts its cumulative history. Retain lease
revocation/high-water evidence as needed to reject old sessions, or use a new
server epoch that invalidates all old leases. Terminal rollout cleanup drops
windows and cursors; late reports cannot recreate a rollout.

## Integration dependencies and enablement order

1. **Activation owner:** land durable/verified activation acknowledgements,
   full revision identity, collector session fencing, and assignment/cohort
   history. Provide lookup or immutable evidence usable at ingest. Download or
   assignment success must not advance the applied revision. Failed activation
   must preserve the previous enforced revision and truthful acknowledgement.
2. **Fleet persistence owner:** `AbortRollout` must return nil only after the
   authoritative desired baseline and terminal rollout state are committed
   consistently. Surface persistence/revert failures and fence concurrent
   completion/abort by rollout generation. The analyzer cannot repair a manager
   that suppresses its own errors. Keep actual agent convergence separate.
3. **Main integration:** add a bounded collector tied to active revision swaps,
   an optional versioned heartbeat payload (or separate authenticated endpoint),
   server validation/ledger lookup, and a checked aggregate ingestion library.
   Support old agents by treating absent telemetry as no evidence. Preserve
   existing heartbeat behavior; telemetry failure cannot fabricate an ack.
4. Run the aggregate evaluator **report-only**, outside heartbeat handling. Add
   admin visibility for window age, source coverage, drop reasons, sequence
   status, quality, revision/cohort attribution, and pending reasons.
5. Only after end-to-end gates pass, add an explicit default-off automatic
   rollback setting with production validation and audit records. Check active
   rollout/generation immediately before abort, handle the manager error, and
   publish abort-requested separately from fleet-revert-confirmed. Never mark a
   fleet rollback complete until baseline activation acknowledgements converge.

No step above is completed by this analyzer patch. Do not claim the automatic
rollout safety gate is shipped when cherry-picking it.

## Required integration acceptance tests

- Forged source/session, cross-policy equal versions, hash mismatch, desired but
  unacknowledged revision, activation failure, stale acknowledgement, and
  revision A -> B -> A do not contaminate either cohort.
- Identical retry, conflicting duplicate, out-of-order delivery, sequence gaps,
  reset counters, decreasing deny/total, impossible deltas, integer overflow,
  and concurrent duplicates obey the atomic cursor contract.
- Percentage/label changes and late heartbeats cannot reattribute historical
  samples. Activation during a snapshot interval cannot mix revisions.
- Rolling expiry, idle windows, burst traffic, tiny windows, long reporting gaps,
  clock reversal/jump, session eviction/rejoin, revoked sessions, and restart
  restore/rebootstrap cannot resurrect stale decisions or create a verdict from
  missing data. Resource limits hold under adversarial cardinality.
- Missing/stale baseline and unacknowledged or uncovered canary agents remain
  pending. Report-only mode never calls abort. Concurrent evaluation, manual
  abort, completion, and persistence failures never produce phantom success.
- A canary denies more than baseline, a verified abort commits, agents are
  assigned baseline, then acknowledge successful baseline activation. Assert
  each state separately, including an offline/failed-revert agent that prevents
  fleet-converged status even after the control-plane abort succeeds.
