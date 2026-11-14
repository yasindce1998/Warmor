# Intelligence lifecycle assumptions

These are bounded, best-effort observations, not an authoritative runtime
inventory. No kernel/BPF lifecycle hooks are added here.

| State | Default hard bounds | Expiry |
| --- | --- | --- |
| Attack graph | 4,096 cgroups; fixed technique database per cgroup | 30 min since last correlated event received |
| Relationship graph | 4,096 nodes, 16,384 edges | 30 min since node/edge received, independently |
| Local drift collector | 256 agents, 1,024 patterns per agent, 61 bounded time buckets | idle agents: max(30 min, 2 × window); patterns: rolling window |
| Fleet drift detector | 4,096 fingerprints, 256 images, 256 agents/image, 1,024 patterns/fingerprint | 30 min since local submission |
| Process lineage | 100,000 PIDs, depth 16 | 1 hour since observed exec |

Constructors accept configuration and injectable monotonic, concurrency-safe
clocks. Capacity eviction removes least-recently-observed entries (or the
least-recently-active image for the detector's image cap). Counts/indexes are
bounded even if exit notifications never arrive. Event timestamps are display
metadata, not retention clocks. Future detector timestamps are clamped to
receipt time. Caller-owned snapshots/maps may be modified after return.

The enforcer's existing 15-second intelligence metrics loop prunes both graphs,
including during silence, and resets blast-radius gauges before republishing.
At most 4,096 cgroup-labelled gauges are exported per snapshot. A Prometheus
server can still retain historical time series for departed cgroups until its
own retention expires; local gauge expiry cannot bound external TSDB history.
Metrics reachability uses one bounded connected-component snapshot, not BFS
with path allocation for every container.

Lineage and drift collectors expose `Prune()` and also expire on access/write.
The enforcer-main owner should call `lineageTracker.Prune()` and
`driftCollector.Prune()` from its periodic maintenance loop, even when attack
graphs are disabled. No package starts an unmanaged background goroutine.
Runtime process-exit integration should call `RecordExit`; container-removal
integration should call graph `Remove`/`RemoveNode`. These must use real runtime
identity. A process exit is **not** sufficient evidence of container removal.
Until runtime start-time/generation identity is available, PID/cgroup reuse
before expiry cannot be distinguished reliably. The lineage tracker rejects
parents observed after a child rather than attributing it to an obvious reused
PID. Long-lived quiet processes can expire; missing ancestry must not be
treated as proof that no ancestor exists.

## Drift comparability and identity

The collector computes rates over its configured rolling window, never elapsed
daemon uptime. Sixty equal-duration buckets bound state independently of event
volume. The oldest bucket is expired conservatively: at most one bucket width
(window/60) of recent events can be omitted at the boundary. Snapshot reads do
not reset counts. Pattern churn is folded into `__other__` after the budget is
reached; discarded key lengths are capped at 256 bytes. Image changes reset
the observation window. New collectors mark snapshots `warmup` for a full
window; the detector excludes them and compares only matching window durations
whose timestamps overlap. Legacy window-zero submissions compare only with
other legacy window-zero submissions, not new rolling fingerprints.

Node-side collection currently aggregates host events and deliberately leaves
`ImageHash` empty. Host version, hostname, comm, and cgroup ID are **not** workload
identity and must not be substituted. Fleet submission requires a genuine
grouping identity and per-workload observation before enabling that comparison.
Heartbeat integration must omit unidentified fingerprints, not reject ordinary
heartbeats or invent a grouping key. That integration belongs to the fleet/
enforcer-main owners; the detector itself refuses empty identity.
