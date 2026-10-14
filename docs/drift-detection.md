# Drift Detection Across Fleet

> **Status: Experimental, library only.** This describes the Go package `internal/drift`, which has unit tests but is **not wired into `warmor-daemon` or `warmor-server` on `main`**. No binary, flag or config value reaches it. Agents do not compute or submit fingerprints, and the server does not run the detector. See [Feature Status](STATUS.md).

Warmor's drift detection identifies containers that deviate from the behavioral norm of their peers. By comparing runtime fingerprints across all instances of the same image, it surfaces compromised or misconfigured containers without requiring predefined rules.

## How It Works

### Behavioral Fingerprinting

The design has each warmor agent record security-relevant events and compute a **behavioral fingerprint** — a vector of event rates (events per minute) over a configurable observation window.

Events are recorded as `type:target` patterns:

| Pattern | Meaning |
|---------|---------|
| `exec:/usr/bin/curl` | Process execution |
| `file:/etc/passwd` | File access |
| `net:443` | Network connection |

The fingerprint collector accumulates raw event counts per agent, then normalizes them to per-minute rates when a snapshot is taken. This produces a comparable vector regardless of when each agent started reporting.

### Fleet Comparison

Fingerprints are grouped by **image hash** — only containers running the same image are compared against each other. This ensures the baseline reflects the expected behavior for that workload.

### Z-Score Outlier Detection

For each event pattern observed across the fleet, the detector computes the mean and standard deviation of rates across all agents running that image. Each agent's rate is then scored:

```
z = (agent_rate - mean) / stddev
```

An anomaly is raised when `|z| > threshold`. The anomaly includes a direction:

| Direction | Meaning |
|-----------|---------|
| `excess` | Agent has significantly higher rate than peers |
| `deficit` | Agent has significantly lower rate than peers |
| `unique` | Pattern observed only on this agent (no peers exhibit it) |

Unique patterns (e.g., only one container running `wget`) are always flagged regardless of z-score, as they indicate behavior no peer shares.

A minimum of 2 agents per image is required before detection activates.

## API

### Report Fingerprint

Callers submit fingerprints to the detector (no agent does this on `main`):

```go
detector.Submit(&drift.BehaviorFingerprint{
    AgentID:   "node-3-pod-abc",
    ImageHash: "sha256:abc123...",
    Vectors:   map[string]float64{"exec:/bin/ls": 12.5, "file:/etc/hosts": 0.3},
    Timestamp: time.Now(),
})
```

Or directly from a collector:

```go
detector.SubmitFromCollector(collector, "node-3-pod-abc")
```

### Query Anomalies

```go
// All anomalies for an image
anomalies := detector.Anomalies("sha256:abc123...")

// Anomalies for a specific agent
agentAnomalies := detector.AnomaliesForAgent("node-3-pod-abc", "sha256:abc123...")

// Fleet-wide status summary
statuses := detector.Status()
```

The `DriftAnomaly` struct returned contains:

| Field | Description |
|-------|-------------|
| `agent_id` | The outlier agent |
| `pattern` | Event pattern that deviates |
| `z_score` | How far from the mean (signed) |
| `direction` | `excess`, `deficit`, or `unique` |
| `rate` | Agent's actual rate (events/min) |
| `mean_rate` | Fleet average for this pattern |

### Fleet Status

`detector.Status()` returns per-image summaries including agent count, anomaly count, and last update timestamp.

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `threshold` | `3.0` | Z-score threshold for flagging anomalies. Lower values increase sensitivity. |
| `window` | `5m` | Observation window for fingerprint collection. Longer windows smooth transient spikes. |

## Tips

- **Start with threshold 3.0** — this catches clear outliers (3 standard deviations) while avoiding false positives from normal variance.
- **Lower to 2.0 for high-security workloads** — more sensitive, but expect some noise in heterogeneous deployments.
- **Unique patterns are high-signal** — a container executing a binary no peer uses is a strong indicator of compromise.
- **Combine with policy enforcement** — use drift alerts as input to tighten allowlist policies via `warmor-policy-gen`.
- **Minimum fleet size matters** — detection requires at least 2 agents per image. Statistical reliability improves with 5+.
