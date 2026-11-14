# Drift observations and fleet comparison

Status: bounded local collection ships with `--drift`. The policy server's
comparison library, heartbeat transport, admin API, and metrics are available,
but the daemon **does not submit its host aggregate for fleet comparison**:
real workload identity and per-workload collection are not yet available.
Owner: policy server + enforcer.

## Agent side (`--drift`)

- A streaming enricher records `event_type:comm` patterns (for example,
  `exec:bash`, `network:curl`) into a bounded local collector. This is one
  host-level observation, not a container-image fingerprint.
- Rates are events per minute over a **rolling ten-minute window**, not since
  daemon startup. Sixty time buckets bound state independently of event volume;
  expiry can conservatively omit at most one bucket at the oldest boundary.
- Pattern cardinality is capped at 1,024, including the `__other__` overflow
  pattern. Comms are attacker-controlled; their short length does not itself
  bound the number of distinct patterns. Keys are capped at 256 bytes.
- Snapshots remain available through the enforcer's `DriftFingerprint()` Go
  API, not a new CLI or HTTP endpoint. The first full window is marked
  `warmup`; the detector does not compare warmup with mature observations.
- Idle collector state expires after thirty minutes. A cancellable maintenance
  loop runs every fifteen seconds, independently of `--attack-graph`, event
  traffic, and whether a policy server is configured.

## Identity and heartbeat safety

`ImageHash` is deliberately empty in the current host-level collector. The
daemon omits that fingerprint field entirely from the heartbeat; registration,
policy polling, and ordinary heartbeats continue normally. Startup logs and
`--help` explicitly describe local-only collection.

A policy-file digest identifies policy content, **not a workload image**.
Neither hostname, node pool, comm, cgroup ID, nor an operator-supplied grouping
string establishes image identity. Even a real image digest cannot describe a
host aggregate containing unrelated workloads. Future fleet submission needs a
runtime-backed identity **and** observations scoped to that workload. The
identity guard preserves a source-supplied identity; it never derives one from
policy files or overrides it with an operator key.

The client stamps a submitted fingerprint's `AgentID` with its configured
agent identity, and the server overwrites it with the authenticated request
identity. The adapter copies the source snapshot before the client stamps it.

## Migration from policy-hash grouping

Earlier daemon versions shipped every host snapshot under the current policy's
SHA-256 (or the `--drift-image-key` override). This conflated policy equality
with workload equality and could report differences between unrelated hosts as
image drift. Those implicit comparisons are no longer produced.

- `--drift` now enables bounded **local** collection and does not require
  `--server`. It does not currently produce new fleet anomalies from the daemon.
- `--drift-image-key` remains accepted for command-line compatibility, but is
  **deprecated and ignored**, with a startup warning. Remove it from manifests;
  it does not opt back into policy-hash or arbitrary-cohort comparisons.
- Existing server fingerprints age out under the server's stale/TTL policy;
  they are not evidence of new workload-scoped observations after upgrade.
- Alerting that relied on automatic host grouping must be reviewed. Do not
  substitute a policy hash or node-pool label into `ImageHash` to restore it.
  A future explicit cohort comparison would need a separate grouping kind,
  rather than masquerading as an image comparison.

## Server side

- Heartbeat transport still accepts identified fingerprints from integrations
  with genuine scoped identity. Unidentified daemon observations are omitted,
  so validation cannot reject an otherwise valid host heartbeat for missing
  image identity.
- The detector owns copies of submitted vectors, rejects invalid/non-finite
  rates, bounds total fingerprints (4,096), images (256), agents per image
  (256), and patterns per fingerprint (1,024), and expires submissions thirty
  minutes after local receipt. The stale loop can prune earlier according to
  its configured threshold. No sender timestamp can pin state indefinitely.
- Heartbeat validation uses the detector's actual admission limits, including
  its 1,024-pattern default. Oversized/invalid reports return HTTP 400 rather
  than acknowledging telemetry the detector cannot retain. This replaces the
  older 10,000-pattern HTTP allowance; integrations must bound their vectors.
- Only mature fingerprints with matching window durations and overlapping
  timestamps are compared. Legacy window-zero fingerprints compare only with
  other legacy window-zero fingerprints, not new rolling observations.
- `GET /api/v1/admin/drift` (admin JWT) returns status and anomalies;
  `?agent_id=` filters by agent. `--drift-threshold` defaults to a z-score of 3.
- Server metrics (`--metrics-port`, 0 disables) expose unlabelled totals
  `warmor_drift_tracked_images` and `warmor_drift_anomalies`. Per-agent/image
  breakdowns remain behind the authenticated admin API to avoid unbounded
  Prometheus labels. The metrics listener itself is unauthenticated.
- Fingerprints are in memory and are lost on server restart. Anomalies are
  calculated on read. Runtime lifecycle/identity integration remains future
  work; see [lifecycle assumptions](../../internal/attackgraph/LIFECYCLE.md).
