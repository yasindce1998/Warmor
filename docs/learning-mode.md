# Live Policy Synthesis (Learning Mode)

`warmor-learn` consumes the security events that `warmor-daemon` streams from the eBPF pipeline and synthesizes a least-privilege policy YAML that allows only the behavior seen during the learning window.

`warmor-learn` does not attach to the kernel itself (that needs root and is the daemon's job). It reads the newline-delimited JSON events the daemon writes with `--event-sink file:<path>`, either replaying a recorded log or following it live. It exits with an error instead of writing a policy if no events were recorded, since an empty deny-all policy would block everything.

## How It Works

```
Container Events (eBPF)
        |
        v
  warmor-daemon streaming pipeline
        |
        v
  ndjson event log  (--event-sink file:<path>, or a warmor-simulate event store)
        |
        v
  warmor-learn --events <path> [--follow]
        |
        v
    Recorder (sink)  -- records per-cgroup profiles
        |
        v
    Synthesizer      -- converts profiles to allow rules
        |
        v
   Policy YAML (deny-all-else)
```

1. **Recorder** -- implements `streaming.Sink`. For each security event it updates a `ContainerProfile` tracking execs, file accesses, network connections, binds, listens, mounts, and ptrace targets.
2. **Session** -- orchestrator that owns the recorder, runs until the input is exhausted, the configured duration elapses, or it is interrupted, then calls the synthesizer.
3. **Synthesizer** -- iterates the profile maps and emits one `allow` rule per unique behavior. Merges profiles across containers when multiple cgroup IDs are observed. Sets `default_action: deny`.

## Installation

```bash
go install github.com/yasindce1998/warmor/cmd/warmor-learn@latest
```

## CLI Usage

```bash
warmor-learn [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-events` | (required) | Event source: an ndjson event log (`warmor-daemon --event-sink file:<path>`), a `warmor-simulate` event-store directory (`events-*.ndjson`), or `-` for stdin |
| `-follow` | `false` | Keep reading events appended to the `-events` file (like `tail -f`) until `-duration` elapses or Ctrl+C. File input only; use `tail -F log \| warmor-learn -events -` to survive log rotation |
| `-duration` | `30m` | Maximum learning window (e.g. `5m`, `1h`; `0` = no limit). Replaying a file stops earlier at end of input |
| `-cgroup` | (all) | Comma-separated cgroup IDs to observe |
| `-o` | stdout | Output file for the generated policy YAML |
| `-name` | auto | Name field in the generated policy |
| `-version` | -- | Print version and exit |

Press Ctrl+C to stop early; the policy is generated from whatever was observed up to that point. If nothing was recorded (empty input, or every event filtered out by `-cgroup`) the command exits 1 without writing a policy. Malformed lines are skipped with a warning.

### Examples

```bash
# The daemon writes every event (allowed and denied) to an ndjson log
warmor-daemon --audit --event-sink file:/var/log/warmor/events.ndjson ...

# Learn from a specific container's recorded events, write policy to file
warmor-learn -events /var/log/warmor/events.ndjson -cgroup 12345 -o policy.yaml

# Follow the live log for 1 hour, learning from all containers
warmor-learn -events /var/log/warmor/events.ndjson -follow -duration 1h -o learned.yaml

# Follow indefinitely (stop with Ctrl+C)
warmor-learn -events /var/log/warmor/events.ndjson -follow -duration 0 -o policy.yaml

# Learn from a warmor-simulate event store, or from stdin
warmor-learn -events ./events/ -o learned.yaml
tail -F /var/log/warmor/events.ndjson | warmor-learn -events - -duration 10m -o learned.yaml
```

## API Integration

The `learner` package can be embedded in the policy server or daemon:

```go
session := learner.NewSession(learner.Config{
    Duration:  5 * time.Minute,
    CgroupIDs: []uint64{12345},
    Name:      "my-app",
})

// Attach session.Recorder() to the streaming pipeline as a sink
pipeline.AddSink(session.Recorder())

// Block until duration elapses or context is cancelled
session.Run(ctx)

// Retrieve stats and policy
fmt.Println(session.Stats())
data, _ := session.MarshalPolicy()
```

## Example Workflow

```
1. Deploy:    run your workload with warmor-daemon --event-sink file:events.ndjson
2. Learn:    warmor-learn -events events.ndjson -follow -duration 10m -cgroup <id> -o learned.yaml
3. Review:   inspect learned.yaml, remove noise, tighten rules
4. Merge:    warmor-policy-merge base.yaml learned.yaml -o final.yaml
5. Enforce:  warmor-daemon --policy final.wasm
```

## Recorded Behavior Categories

| Category | Profile Key | Example |
|----------|-------------|---------|
| Process execution | `binary path` | `/usr/bin/curl` |
| File access | `file path` | `/etc/resolv.conf` |
| Outbound connections | `proto:addr:port` | `tcp:10.0.1.5:443` |
| Socket binds | `proto:port` | `tcp:8080` |
| Socket listens | `proto:port` | `tcp:8080` |
| Mounts | `mount type` | `proc` |
| Ptrace | `target comm` | `node` |

## Tips

- **Record a full operational cycle** -- short windows miss infrequent behaviors like log rotation or cron jobs.
- **Filter by cgroup** -- targeting specific containers produces tighter policies than learning everything at once.
- **Combine with policy-gen** -- use `warmor-policy-gen` for offline audit-log analysis and `warmor-learn` for live observation; merge results with `warmor-policy-merge`.
