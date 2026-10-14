# Policy Simulator

> **Status: Shipped** (`warmor-simulate`). The **daemon has no event-store sink** on `main`, and the policy server does not call the simulator. Record events with the file sink, using a file name that matches `events-*.ndjson`. See [Integration](#integration-with-policy-server) below and [Feature Status](STATUS.md).
>
> **Known issue:** the daemon's sinks record `decision` in lowercase (`allow`, `deny`), but the simulator compares against `ALLOW`/`DENY`. For events recorded by `warmor-daemon`, the "New denials" and "New allows" sections are therefore always empty. The decision breakdown (`ALLOW`/`DENY`/`LOG` counts) is still correct.

`warmor-simulate` replays recorded security events against a candidate policy and reports the impact before you deploy it. This lets you preview new denials or relaxed allows without touching production.

## How It Works

1. **Record**: Run the agent with `--event-sink file:<dir>/events-<name>.ndjson`. The simulator reads every `events-*.ndjson` file in the directory. The daily-rotated `EventStore` sink exists in `internal/simulator`, but the daemon cannot select it yet.
2. **Load**: The simulator reads events from the store, filtered by a time window.
3. **Replay**: Each event is evaluated against the candidate policy (YAML or compiled WASM) using the same WASM policy engine used at runtime.
4. **Compare**: The candidate decision is compared to the original recorded decision. Events that flip from ALLOW to DENY (new denials) or DENY to ALLOW (new allows) are tracked and deduplicated.
5. **Report**: A summary is printed showing decision breakdown and unique behavioral changes.

## Installation

```bash
go build -o bin/ ./cmd/warmor-simulate
```

## Usage

```bash
warmor-simulate --policy <path> --data <event-dir> [flags]
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--policy` | required | Path to candidate policy file (.yaml or .wasm) |
| `--data` | required | Path to the event store directory |
| `--since` | `168h` (7 days) | Only replay events from this duration ago |
| `-o` | stdout | Output file path |
| `--format` | `text` | Output format: `text` or `json` |
| `--version` | -- | Print version and exit |

## Examples

```bash
# Preview impact of a stricter policy over the last 24 hours
warmor-simulate --policy strict.yaml --data /var/lib/warmor/events --since 24h

# Full 7-day replay, JSON output to file
warmor-simulate --policy new-policy.wasm --data ./events -o report.json --format json
```

## Example Output

### Text format

```
Policy Simulation Report
========================

Events replayed: 14832
Duration:        312ms

Decision breakdown:
  ALLOW: 14201 (95.7%)
  DENY:  588 (4.0%)
  LOG:   43 (0.3%)

New denials (3 unique patterns):
  TYPE       COMMAND          TARGET                                   COUNT
  ----------------------------------------------------------------------------------
  exec       python3          /usr/bin/python3                         42
  network    curl             203.0.113.5:8080                         7
  file       nginx            /etc/shadow                              2

No new allows -- all previously-denied events remain denied.
```

### JSON format

The JSON output contains the same data as a structured object suitable for programmatic consumption:

```json
{
  "total_events": 14832,
  "would_allow": 14201,
  "would_deny": 588,
  "would_log": 43,
  "unique_new_denials": [
    {"event_type": "exec", "comm": "python3", "target": "/usr/bin/python3", "count": 42, "reason": "not in allowlist"}
  ],
  "unique_new_allows": [],
  "duration": 312000000
}
```

## Integration with Policy Server

To record events today, use the daemon's file sink with a matching file name:

```bash
sudo warmor-daemon --policy current.wasm --audit \
  --event-sink file:/var/lib/warmor/events/events-current.ndjson
```

There is no agent configuration file and no `event-store` sink type on `main`.

**Planned, not implemented:** the policy server invoking the simulator as part of a promotion workflow:

1. A new candidate policy is pushed to the policy server.
2. The server calls `warmor-simulate` against the recorded event stream.
3. If new denials exceed a threshold, the promotion is blocked and the report is surfaced to the operator.
4. If safe, the policy is promoted to active enforcement.

This allows safe, data-driven policy iteration without risking unexpected breakage in production workloads.

## Event Store Format

With the (not yet selectable) `EventStore` sink, events are stored as newline-delimited JSON (ndjson), one file per UTC day:

```
events-2026-06-18.ndjson
events-2026-06-19.ndjson
```

Each line is a full `SecurityEvent` struct including the original enforcement decision, enabling accurate before/after comparison.
