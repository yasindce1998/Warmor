# Node-side intelligence chain: attack graph, blast radius, dashboard, SIEM

Status: shipped (`--attack-graph`, `--dashboard-port`, `--event-sink syslog:`).
Owner: enforcer.

## The gap

Four intelligence features exist as tested libraries that nothing
reaches (see STATUS.md): the MITRE attack graph
(`internal/attackgraph`), blast-radius analysis (`internal/blastradius`),
the SSE web dashboard (`internal/dashboard`) and the SIEM syslog sink
(`internal/streaming/siem.go`). This change wires all four into the
daemon, behind flags, with metrics and docs. Fleet drift
(`internal/drift`) is deliberately **not** in this change: it needs
agent→server fingerprint transport and server-side aggregation, and is
its own follow-up.

## Where they plug in

Every feature consumes the same stream the sinks see:
`streaming.SecurityEvent` flowing through the enforcer's pipeline
(`Pipeline.Emit` after every policy decision). The pipeline already
supports `Enricher`s (lineage, escape detection) and `Sink`s (stdout,
file, webhook), so:

- **Correlator** (`attackgraph.Correlator.Enrich`) is an enricher: it
  labels events with `mitre_techniques` / `mitre_tactic`, so every sink
  (including SIEM) carries MITRE context.
- **Attack graph** (`attackgraph.Graph.Ingest`) is an observer wrapped
  as an enricher: it builds the per-container technique/kill-chain
  graph. It correlates internally, so it needs no ordering guarantee
  against the Correlator.
- **Blast-radius collector** (`blastradius.Collector.ProcessEvent`) is
  an enricher: it builds the container-relationship graph (network and
  mount edges between cgroups).
- **Dashboard** is a *sink*: a small adapter in `internal/dashboard`
  (`NewSink`) maps `SecurityEvent` → the dashboard's eval `Event`
  (`time`, `pid`, `comm`, `action`, `reason`) and calls `Publish`.

## Flags

| flag | default | effect |
|------|---------|--------|
| `--attack-graph` | off | adds the three enrichers above and the metrics loop |
| `--dashboard-port` | 0 (off) | serves `/dashboard` + `/dashboard/events` (SSE) on the port, and adds the dashboard sink so the pipeline exists without `--event-sink` |
| `--dashboard-bind` | `127.0.0.1` | literal listen IP (`localhost` also accepted); remote/wildcard IPs require explicit choice |
| `--dashboard-token-file` | unset | optional HTTP Basic password file (user `warmor`); alternatively use `WARMOR_DASHBOARD_TOKEN` |
| `--event-sink syslog:[udp\|tcp://]host:port` | — | CEF-formatted events over syslog; bare `syslog:host:port` means UDP |

The dashboard gets its own `http.Server` rather than a route on the
metrics port because the metrics server has a 10 s `WriteTimeout`,
which would kill every SSE stream mid-flight; the dashboard server sets
none. It does set 5 s header, 10 s request-read and 60 s idle-connection
timeouts, plus a 16 KiB header limit; none limits the lifetime of an active
SSE response. See [dashboard access](../dashboard.md) for authentication
and reverse-proxy deployment.

## Metrics

Updated by a ticker (the same shape as the existing map-entries loop)
while `--attack-graph` is on, every 15 s:

- `warmor_attack_graph_containers` — containers with correlated behavior
- `warmor_attack_graph_techniques` — distinct MITRE techniques observed
- `warmor_attack_graph_tactic_coverage{tactic}` — technique nodes per tactic
- `warmor_attack_graph_progression` — deepest kill-chain stage reached (0–6)
- `warmor_blast_radius_reachable{cgroup}` — containers reachable from
  that cgroup in the relationship graph (BFS, unlimited hops)

## Known limits

- The attack graph keeps entries for containers that have exited; there
  is no cgroup-removal event wired to `Graph.Remove`. Bounded by the
  number of containers seen since start.
- The blast-radius collector's remote/volume resolution
  (`resolveRemoteContainer`, `resolveVolumeContainer`) returns 0 today —
  edges appear only for shared-namespace registration, which nothing
  calls yet; the metrics therefore mostly read 0 until container
  runtime integration lands.
- The dashboard shows policy evaluations only (the shipped UI); attack
  graph and blast radius are metrics/`/metrics` territory for now.
