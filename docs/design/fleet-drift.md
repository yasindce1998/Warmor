# Fleet drift detection: fingerprints in heartbeats

Status: shipped (`--drift` on agents, `--drift-threshold`/`--metrics-port`
on the server).
Owner: policy server + enforcer.

## The gap

`internal/drift` shipped a behavioral fingerprint collector and a z-score
detector as tested libraries that nothing reached: no agent collected
fingerprints, no transport carried them, and the server never ran the
detector. This change wires the whole chain:

```
agent (--drift)                     server
┌─────────────────────┐            ┌──────────────────────────────┐
│ pipeline enricher   │  heartbeat │ drift.Detector (z-scores per │
│  counts "type:comm" │ ─────────> │  image group)                │
│  rate vectors       │  + finger- │  → /api/v1/admin/drift       │
│                     │  print     │  → warmor_drift_* gauges     │
└─────────────────────┘            └──────────────────────────────┘
```

## Agent side (`--drift`)

- A pipeline enricher (the same `streaming.SecurityEvent` stream the
  sinks see) counts one counter per **`event_type:comm`** pair (e.g.
  `exec:bash`, `network:curl`). Comm granularity is chosen for bounded
  cardinality (task comms are 16 bytes) — filenames or argument lists
  would explode the fingerprint and leak paths into heartbeats.
- Rates are per-minute averages **since daemon start** (the library's
  semantics), not a sliding window: a single 30 s interval is too noisy
  for z-scores, and long-run rates are what "this node behaves like the
  others" means.
- Every heartbeat attaches the current snapshot
  (`HeartbeatRequest.fingerprint`). Agents without `--drift` keep
  sending plain heartbeats; nothing changes for them.
- The client stamps the fingerprint's `AgentID` with its own agent ID,
  and the server **overwrites it again** with the authenticated request
  identity — a fingerprint can never claim to be another agent.

## Grouping (the "image hash")

The detector compares agents **running the same image**. Agents cannot
see container images (no runtime integration yet — the same gap that
leaves blast-radius remote resolution unimplemented), so the grouping key
is a proxy:

- default: the **SHA-256 of the current policy file**, recomputed per
  heartbeat, so agents enforcing the same policy are compared and a
  policy change re-groups the agent on the next heartbeat;
- `--drift-image-key <string>` overrides it for workload-based grouping
  (e.g. the same value per node pool or DaemonSet).

For homogeneous fleets (one fleet-wide policy) both defaults behave the
same: every agent lands in one group.

## Server side

- `handleHeartbeat` validates the fingerprint (present image hash,
  bounded length, at most 10 000 patterns — it is untrusted input that
  lives in server memory) and submits it to `drift.Detector`.
- The stale loop prunes fingerprints silent for twice the stale
  threshold (an agent gone from the comparison instead of skewing it
  forever) and republishes the metrics.
- **Admin API:** `GET /api/v1/admin/drift` (admin JWT) returns per-image
  fleet status and every anomaly; `?agent_id=` filters to one agent.
- **Metrics** (`--metrics-port`, 0 = off, served unauthenticated like the
  daemon's): `warmor_drift_tracked_images` and `warmor_drift_anomalies`
  — totals only, deliberately unlabeled: per-image and per-agent
  breakdowns are agent-influenced data and would invite label-cardinality
  abuse on a metrics endpoint; they live behind the authenticated admin
  API instead.
- `--drift-threshold` (default 3.0) sets the z-score threshold.

## Known limits

- Rates are cumulative since daemon start; an agent that restarts
  starts over (its fingerprint briefly has high-variance rates until it
  accumulates samples again).
- The grouping key is a policy hash, not a real container image; agents
  enforcing the same policy but running different workloads will
  legitimately differ. Use `--drift-image-key` for heterogeneous fleets.
- One fingerprint per agent (node), not per container: container-level
  drift needs the runtime integration that does not exist yet.
- Anomalies are computed on read (admin API / metrics loop), not cached
  per event; with very large fleets this is O(agents × patterns) per
  read.
- The server keeps fingerprints in memory only; they are lost on restart
  and repopulate as agents heartbeat.
