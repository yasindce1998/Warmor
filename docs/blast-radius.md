# Cross-Container Blast Radius Mapping

> **Status: Experimental, library only.** This describes the Go package `internal/blastradius`, which has unit tests but is **not wired into `warmor-daemon` or `warmor-server` on `main`**. No binary, flag or config value reaches it. No running component builds or queries the graph today. See [Feature Status](STATUS.md).

The blast radius subsystem builds a live relationship graph of containers and analyzes how a compromise in one container could spread to others. It answers: "If container X is breached, what else is reachable?"

## How It Works

The collector is designed to turn inter-container interactions (network connections, shared volumes, shared namespaces) into directed edges in an in-memory graph. On `main` nothing feeds it events. When queried, a BFS traversal computes which containers are reachable from a given source, with full path details.

## Edge Types

| Edge Type | Constant | Discovery Method |
|-----------|----------|-----------------|
| Network connection | `network` | Observed TCP/UDP connection between containers (source IP:port resolved to target cgroup) |
| Shared volume | `shared_volume` | Mount event where the path is also mounted by another container |
| Shared PID namespace | `shared_pid_ns` | Registered via `RegisterSharedNamespace` (bidirectional) |
| Shared IPC namespace | `shared_ipc_ns` | Registered via `RegisterSharedNamespace` (bidirectional) |

Network and volume edges are directional (A initiated connection to B). Namespace edges are always added in both directions since they represent symmetric relationships.

## Graph Structure

Each container is a `ContainerNode` identified by its cgroup ID, with metadata (image, namespace, name, labels, first/last seen timestamps). Edges track source, destination, type, details (e.g., remote address), last-seen time, and hit count. The graph is concurrency-safe (RWMutex).

## Analysis Methods

### Reach (undirected BFS)

```go
analyzer.Reach(cgroupID, maxHops) *BlastRadius
```

Traverses both incoming and outgoing edges to find all containers reachable from the source. This models the worst case: an attacker who can exploit any relationship in either direction. Set `maxHops` to 0 for unlimited depth.

### ReachDirected (directed BFS)

```go
analyzer.ReachDirected(cgroupID, maxHops) *BlastRadius
```

Follows only outgoing edges from the source. This models realistic lateral movement: an attacker can only reach containers that the compromised container actively communicates with.

### ImpactScore

```go
analyzer.ImpactScore(cgroupID) float64
```

Returns a value between 0.0 and 1.0 representing the fraction of all other containers reachable from the source (using undirected BFS). A score of 1.0 means a single compromise reaches the entire cluster.

### MostConnected

```go
analyzer.MostConnected() (cgroupID uint64, edgeCount int)
```

Returns the container with the highest total edge count (incoming + outgoing). This is the highest-risk node in the graph since it has the most lateral movement paths.

## Collector Integration

The `Collector` bridges the warmor event pipeline to the blast radius graph:

1. Each `SecurityEvent` with a non-zero cgroup ID creates or updates a node.
2. Network events (`event.EventType == "network"`) create directed edges when the remote address resolves to a known container.
3. Mount events (`event.EventType == "mount"`) create directed edges when the mount path is shared with another container.
4. Shared namespaces are registered explicitly via `RegisterSharedNamespace` (e.g., from container runtime metadata).

Usage:

```go
graph := blastradius.NewGraph()
collector := blastradius.NewCollector(graph)
analyzer := blastradius.NewAnalyzer(graph)

// Feed events (no pipeline does this on main)
collector.ProcessEvent(event)

// Query blast radius
result := analyzer.Reach(compromisedCgroupID, 3)
score := analyzer.ImpactScore(compromisedCgroupID)
```

## Use Cases

**Incident response** -- When a container is compromised, immediately determine which other containers are at risk and need inspection or isolation. The path details in `BlastRadius.Reachable` show the exact chain of relationships.

**Network policy planning** -- Use `MostConnected` and `ImpactScore` to identify containers that would benefit most from network segmentation. High-connectivity nodes are prime candidates for stricter NetworkPolicy rules.

**Risk scoring** -- Continuously compute `ImpactScore` for all containers and alert when any single container can reach more than a threshold percentage of the cluster.

**Forensic analysis** -- After an incident, replay events through the collector to reconstruct the relationship graph at the time of breach and trace possible lateral movement paths.

## Implementation Files

- `internal/blastradius/graph.go` -- Graph data structure (nodes, edges, thread-safe operations)
- `internal/blastradius/analyzer.go` -- BFS reachability, impact scoring, connectivity analysis
- `internal/blastradius/collector.go` -- Event-to-graph bridge, namespace registration
