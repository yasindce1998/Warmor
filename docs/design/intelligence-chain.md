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

## Correlation and graph model

The attack graph correlates events to MITRE ATT&CK techniques and builds a
per-container kill-chain graph: nodes are observed techniques, edges point from
earlier to later tactics and weights reinforce on repetition. `Graph.Summary()`
reports container count, technique coverage and `HighestProgression` — how deep
into the kill chain any container has reached.

The embedded technique database covers 28 container-relevant techniques across
all 11 kill-chain tactics:

| Tactic | Techniques |
|--------|-----------|
| Initial Access | Exploit Public App (T1190), Valid Accounts (T1078) |
| Execution | Unix Shell (T1059.004), Deploy Container (T1610), Ingress Tool Transfer (T1105), Service Execution (T1569.002) |
| Persistence | Cron (T1053.003), Systemd Service (T1543.002), Account Manipulation (T1098) |
| Privilege Escalation | Escape to Host (T1611), Exploitation (T1068), Setuid/Setgid (T1548.001), Process Injection (T1055) |
| Defense Evasion | Build Image on Host (T1612), File Deletion (T1070.004), Rootkit (T1014), Obfuscated Files (T1027) |
| Discovery | Container Discovery (T1613), Network Service Scan (T1046), System Info (T1082), File Discovery (T1083), Process Discovery (T1057), Network Connections (T1049) |
| Lateral Movement | SSH (T1021.004) |
| Collection | Credentials in Files (T1552.001), Data Staged (T1074) |
| Exfiltration | Alternative Protocol (T1048), Web Protocols (T1071.001), Non-App Layer Protocol (T1095) |
| Impact | Data Destruction (T1485), Service Stop (T1489), Resource Hijacking (T1496) |

Correlation rules map events to techniques via event type, exact `comm` match and
substring path match (for example `exec` + `nsenter` → T1611, `exec` + `xmrig` →
T1496); custom rules use `NewCorrelatorWithRules`.

The blast-radius collector builds a live relationship graph and answers "if
container X is breached, what else is reachable?" via BFS. Edge types: network
connections (directed), shared volumes (directed) and shared PID/IPC namespaces
(bidirectional). Queries: `Reach` (undirected BFS, worst case), `ReachDirected`
(outgoing only, realistic lateral movement), `ImpactScore` (0–1, fraction of the
fleet reachable from one container) and `MostConnected` (highest-risk node).
They are intended for incident response, segmentation planning and risk scoring.

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
