# Attack Graph Visualization

> **Status: Experimental, library only.** This describes the Go package `internal/attackgraph`, which has unit tests but is **not wired into `warmor-daemon` or `warmor-server` on `main`**. No binary, flag or config value reaches it. No event pipeline calls `Graph.Ingest` or `Correlator.Enrich` today. See [Feature Status](STATUS.md).

The attack graph engine correlates runtime security events to MITRE ATT&CK techniques and builds a per-container kill-chain graph showing how far an attacker has progressed.

## MITRE ATT&CK Coverage

The embedded technique database covers 28 container-relevant techniques across all 11 kill-chain tactics:

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

Tactics are ordered by kill-chain progression (reconnaissance through impact). The `TacticIndex` function returns each tactic's position in this ordering.

## Correlation Rules

The `Correlator` maps incoming `SecurityEvent` structs to technique IDs using `MatchRule` entries. Each rule specifies:

| Field | Purpose |
|-------|---------|
| `EventType` | Required event type: `exec`, `file`, `network`, `mount`, `ptrace` |
| `CommMatch` | Exact match on the process command name (e.g. `curl`, `nmap`) |
| `PathMatch` | Substring match on filename or remote address (e.g. `/etc/crontab`, `:22`) |

A rule matches when all non-empty fields match the event. Multiple rules can map to the same technique. The correlator deduplicates results per event.

The `Enrich` method annotates events with `mitre_techniques` and `mitre_tactic` labels in-place, implementing the `streaming.Enricher` pattern.

### Default Rule Examples

- `exec` + `CommMatch:"nsenter"` maps to T1611 (Escape to Host)
- `file` + `PathMatch:".aws/credentials"` maps to T1552.001 (Credentials in Files)
- `exec` + `CommMatch:"xmrig"` maps to T1496 (Resource Hijacking)

Custom rules can be provided via `NewCorrelatorWithRules`.

## Kill-Chain Graph Construction

When `Graph.Ingest` receives a security event:

1. The correlator identifies matching technique IDs.
2. For each technique, a `Node` is created or updated (incrementing `Count`, updating `LastSeen`).
3. Kill-chain edges are added between all existing nodes whose tactics are earlier in the chain and the new node (and vice versa). Edges point from earlier tactics to later ones.
4. Edge weights increment on repeated observations, tracking reinforcement of attack paths.

Each container (identified by cgroup ID) maintains an independent graph.

## API

```go
// Create
correlator := attackgraph.NewCorrelator()
graph := attackgraph.NewGraph(correlator)

// Ingest events (intended to be called from the event pipeline; not wired on main)
graph.Ingest(event)

// Query a single container's graph
cg := graph.GetContainer(cgroupID)
// cg.Nodes — map[techniqueID]*Node
// cg.Edges — []*Edge{From, To, Weight, LastSeen}

// List all tracked containers
ids := graph.Containers()

// Remove a container on termination
graph.Remove(cgroupID)
```

## Summary Metrics

`Graph.Summary()` returns a `GraphSummary` with:

| Field | Description |
|-------|-------------|
| `ContainerCount` | Number of containers with observed attack activity |
| `TechniqueCount` | Distinct techniques observed across all containers |
| `TacticCoverage` | Map of tactic to number of technique observations |
| `HighestProgression` | Maximum kill-chain index reached by any container (0=reconnaissance, 10=impact) |

The `HighestProgression` value indicates how deep into the kill chain an attacker has reached. A value of 10 (impact) means a container has exhibited behavior spanning the full attack lifecycle.

## Implementation Files

- `internal/attackgraph/mitre.go` — Technique database and tactic ordering
- `internal/attackgraph/correlator.go` — Event-to-technique correlation engine
- `internal/attackgraph/graph.go` — Per-container graph with kill-chain edges
