# Temporal Policies

> **Status: Experimental, library only. Do not use `temporal:` in policies yet.** `internal/temporal` (enricher and guard) has unit tests but is **not wired into `warmor-daemon` on `main`**. The YAML compiler does not know the `temporal:` key and **silently ignores it**. A rule with a `temporal:` block therefore compiles into an **unconditional** rule: a `deny` with `max_container_age: "5m"` denies at every container age. See [Feature Status](STATUS.md).

Warmor temporal policies add time-based constraints to security rules, allowing you to restrict container behavior based on container age, time of day, and day of week.

## Constraint Types

| Constraint | Description | Example Use |
|------------|-------------|-------------|
| `max_container_age` | Deny after container exceeds this age | Block network after 24h (detect long-lived shells) |
| `min_container_age` | Deny before container reaches this age | Allow DB writes only after 30s warmup |
| `time_of_day` | Restrict to a UTC time window | Permit deploys only during business hours |
| `days_of_week` | Restrict to specific weekdays | Block exec on weekends |

## Policy YAML Syntax (planned; ignored by the compiler on main)

```yaml
name: temporal-hardening
version: 1

rules:
  - name: no-network-after-startup
    event: network
    conditions:
      all:
        - comm: { eq: "curl" }
    action: deny
    temporal:
      max_container_age: "5m"

  - name: maintenance-window-only
    event: process
    conditions:
      all:
        - path: { glob: "/usr/bin/apt*" }
    action: deny
    temporal:
      time_of_day:
        start: { hour: 2, minute: 0 }
        end: { hour: 4, minute: 0 }
      days_of_week: [Tuesday, Thursday]

  - name: no-weekend-deploys
    event: process
    conditions:
      all:
        - comm: { eq: "helm" }
    action: deny
    temporal:
      days_of_week: [Monday, Tuesday, Wednesday, Thursday, Friday]
```

### Time-of-Day Ranges

Ranges are evaluated in UTC. Overnight windows that wrap past midnight are supported:

```yaml
temporal:
  time_of_day:
    start: { hour: 22, minute: 0 }
    end: { hour: 6, minute: 0 }
```

This allows the action between 22:00 and 06:00 UTC.

## How It Works

The temporal system consists of two components, designed to sit in the event pipeline (neither is wired on `main`):

1. **Enricher** — Tracks container start times by cgroup ID and annotates every security event with temporal labels (`container_age_ms`, `wall_clock`, `day_of_week`).

2. **Guard** — Evaluates temporal rules against enriched events. Each rule binds a constraint to an event matcher (by event type and/or comm name). If the constraint is violated, the guard returns a deny decision with the rule name as reason.

### Pipeline Flow

```
BPF event → Enricher.Enrich(event) → Guard.CheckEvent(event) → allow/deny
                 │                            │
                 ├─ adds wall_clock label     ├─ matches rule to event
                 ├─ adds day_of_week label    ├─ calls Evaluate(constraint, age, clock)
                 └─ adds container_age_ms     └─ returns ActionDeny if violated
```

### Container Lifecycle

Register containers when they start and unregister on exit. Nothing does this automatically on `main`; there is no container start-time source yet.

```go
enricher.RegisterContainer(cgroupID, time.Now())
// ... container exits ...
enricher.UnregisterContainer(cgroupID)
```

## Use Cases

**Startup window** — Allow network calls (dependency fetching, config pulls) only in the first 60 seconds, then lock down:

```yaml
temporal:
  max_container_age: "60s"
```

**Maintenance windows** — Permit package installs or schema migrations only during off-peak hours:

```yaml
temporal:
  time_of_day:
    start: { hour: 2, minute: 0 }
    end: { hour: 5, minute: 0 }
```

**Day restrictions** — Prevent deployments or privileged operations on weekends:

```yaml
temporal:
  days_of_week: [Monday, Tuesday, Wednesday, Thursday, Friday]
```

**Warmup grace period** — Suppress alerts for expected init behavior (healthcheck probes, readiness scripts) during the first 30 seconds:

```yaml
temporal:
  min_container_age: "30s"
```

## Combining Constraints

All constraints within a single rule are AND-ed. The event is denied only if **any** constraint is violated (i.e., the event falls outside the allowed window). Combine multiple constraints for precise control:

```yaml
temporal:
  max_container_age: "1h"
  time_of_day:
    start: { hour: 9, minute: 0 }
    end: { hour: 17, minute: 0 }
  days_of_week: [Monday, Tuesday, Wednesday, Thursday, Friday]
```

This allows the matched action only during business hours on weekdays, and only within the first hour of container life.
