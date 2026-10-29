# Experimental Features (library only)

> **Status: Library only.** Everything on this page is Go code with unit
> tests that is **not wired into `warmor-daemon` or `warmor-server` on
> `main`**. No binary, flag or config value reaches any of it. See
> [Feature Status](STATUS.md) — wiring these into the daemon and server is a
> listed contribution area.

Three security-intelligence subsystems exist in this state. Each would be fed
by the event pipeline once wired; today nothing calls them.

## Attack graph (MITRE ATT&CK) — `internal/attackgraph`

Correlates runtime events to MITRE ATT&CK techniques and builds a
per-container kill-chain graph (nodes = observed techniques, edges point from
earlier to later tactics, weights reinforce on repetition). `Graph.Summary()`
reports container count, technique coverage and `HighestProgression` — how
deep into the kill chain any container has reached.

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

Correlation rules map events to techniques via event type, exact `comm`
match and substring path match (e.g. `exec` + `nsenter` → T1611, `exec` +
`xmrig` → T1496); custom rules via `NewCorrelatorWithRules`.

## Blast radius — `internal/blastradius`

Builds a live relationship graph of containers and answers "if container X is
breached, what else is reachable?" via BFS. Edge types: network connections
(directed), shared volumes (directed), shared PID/IPC namespaces
(bidirectional). Queries: `Reach` (undirected BFS, worst case),
`ReachDirected` (outgoing only, realistic lateral movement), `ImpactScore`
(0–1, fraction of the fleet reachable from one container) and `MostConnected`
(highest-risk node). Intended for incident response, segmentation planning
and risk scoring.

## Drift detection — `internal/drift`

Identifies containers that deviate from the behavioral norm of peers running
the same image. Each agent would compute a behavioral fingerprint — event
rates per minute for `exec:`/`file:`/`net:` patterns — and the detector
compares agents per image hash with z-score outlier detection
(`|z| > threshold`, default 3.0). Anomalies are `excess`, `deficit` or
`unique` (a pattern no peer exhibits — always flagged). Requires at least 2
agents per image.
