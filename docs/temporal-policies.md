# Temporal Policies

> **Status: Shipped for YAML policies, Linux container age.** `warmor-compile` compiles a rule's `temporal:` block into the WASM policy, and `warmor-daemon` sends the policy the event's time and its container's age. Container age is only known for container cgroups on Linux (see [Limits](#limits)); everywhere else an age constraint treats the age as unknown and **fails closed**. See [Feature Status](STATUS.md).

A temporal block restricts *when* a rule's operation is permitted: by container age, UTC time of day and UTC day of week.

## Semantics in one sentence

A temporal block describes the window in which the operation is **permitted**. The rule's action applies when its conditions match **and the event is outside that window**.

```yaml
  - name: no-curl-after-startup
    event: network
    conditions:
      all:
        - comm: { eq: "curl" }
    action: deny
    temporal:
      max_container_age: "5m"    # curl is permitted during the first 5 minutes
```

This rule denies `curl` once its container is older than 5 minutes. Inside the window the rule does not match, and evaluation continues with the next rule (and finally `default_action`), exactly as if the conditions had not matched.

## Constraints

| Key | Value | Inside the window when |
|-----|-------|------------------------|
| `max_container_age` | Duration string | container age <= the value |
| `min_container_age` | Duration string | container age >= the value |
| `time_of_day` | `{ start: { hour, minute }, end: { hour, minute } }` | UTC time is between start and end, both minutes inclusive |
| `days_of_week` | List of weekday names | the UTC calendar day is listed |

All constraints in one block are AND-ed: the event is inside the window only if it satisfies every one of them, so the action applies if **any** of them is violated.

- **Durations** are Go durations (`"90s"`, `"5m"`, `"24h"`) plus a leading day component (`"7d"`, `"1d12h"`; a day is 24h). They must be quoted strings, greater than zero and a whole number of milliseconds. `min_container_age` may not exceed `max_container_age`.
- **Time of day** is in **UTC**. `hour` is 0-23 and `minute` 0-59, and both are required integers. The window covers the start minute through the end minute inclusive: `02:00`-`04:00` permits 02:00:00 through 04:00:59. If `start` is later than `end` the window wraps past midnight (`22:00`-`06:00` permits 22:00:00 through 06:00:59 the next morning). `start` equal to `end` is rejected, since it would permit a single minute.
- **Days** are full English names, case-insensitive (`Monday`, `tuesday`), at least one, no duplicates. The day is the UTC calendar day of the event, evaluated independently of `time_of_day`: for a `22:00`-`06:00` window on `[Friday]`, 23:00 Friday is inside but 01:00 Saturday is not.
- **Actions:** temporal blocks are allowed on `deny` and `log` rules, including `mode: audit`. They are rejected on `allow` rules: acting outside the permitted window would allow exactly when the operation is *not* permitted.

The compiler is strict about the block: unknown keys (`max_age`, `tz`, ...), wrong types (`max_container_age: 300`, `hour: "2"`), out-of-range values and an empty or null `temporal:` are compile errors, never ignored. Note that unknown keys elsewhere in a rule are still ignored by the compiler, so a misspelt `temporal:` key itself (`temporl:`) is not caught. Check the output of `warmor-compile --rust-only`: a temporal rule's check ends in `&& !(...)`.

## Unknown age or time: fail closed

The container age is **unknown** when the event does not come from a container cgroup (host processes, systemd services, user sessions), when the daemon cannot date the container (see [Limits](#limits)), and on Windows and macOS. The time is unknown only if the host has no usable clock.

An unknown value is **outside every window that depends on it**. So `max_container_age` and `min_container_age` rules apply their action to events of unknown age, and time rules to events of unknown time. A security rule cannot show the event is inside the permitted window, so it acts.

The consequence to plan for: **a `max_container_age` or `min_container_age` deny rule also denies matching host processes**, because they have no container age. Scope such rules with conditions, or restrict the daemon to container cgroups with `--cgroup-filter`. Rules with only `time_of_day`/`days_of_week` are not affected; they apply to every event.

## Examples

This is [`examples/policies/temporal-hardening.yaml`](../examples/policies/temporal-hardening.yaml) with the description, reasons and some comments trimmed. CI validates the file:

```yaml
name: temporal-hardening
version: 1

rules:
  # Startup window: dependency fetches are permitted in the first minute only.
  - name: no-network-tools-after-startup
    event: network
    conditions:
      all:
        - comm: { any_of: ["curl", "wget"] }
    action: deny
    temporal:
      max_container_age: "60s"

  # Warmup: no database writes during the first 30 seconds.
  - name: no-db-writes-during-warmup
    event: file
    conditions:
      all:
        - path: { glob: "/var/lib/postgresql/**" }
        - operation: { eq: "write" }
    action: deny
    temporal:
      min_container_age: "30s"

  # Maintenance window: package installs only Tue/Thu 22:00-04:30 UTC.
  - name: apt-maintenance-window
    event: process
    conditions:
      all:
        - path: { glob: "/usr/bin/apt*" }
    action: deny
    temporal:
      time_of_day:
        start: { hour: 22, minute: 0 }
        end: { hour: 4, minute: 30 }
      days_of_week: [Tuesday, Wednesday, Thursday, Friday]

  # No weekend deploys.
  - name: no-weekend-deploys
    event: process
    conditions:
      all:
        - comm: { eq: "helm" }
    action: deny
    temporal:
      days_of_week: [Monday, Tuesday, Wednesday, Thursday, Friday]

  # Log interactive shells outside business hours or after the first hour.
  - name: log-late-shells
    event: process
    conditions:
      all:
        - path: { any_of: ["/bin/sh", "/bin/bash"] }
    action: log
    temporal:
      max_container_age: "1h"
      time_of_day:
        start: { hour: 9, minute: 0 }
        end: { hour: 17, minute: 0 }
      days_of_week: [Monday, Tuesday, Wednesday, Thursday, Friday]

default_action: allow
```

Note on the maintenance window: `days_of_week` is checked against the event's own UTC day, so the after-midnight part of a Tuesday-night window is on Wednesday. That is why the rule lists Wednesday and Friday too. The cost is that the 00:00-04:30 part of Tuesday and Thursday mornings, and 22:00-23:59 on Wednesday and Friday, are also permitted; there is no way to express "the night starting on Tuesday" exactly.

## How it works

There is one rule engine: the compiled WASM policy. Nothing in Go evaluates temporal rules at runtime.

1. **Compiler.** `warmor-compile` parses the block into `internal/temporal.Constraint` and generates Rust that checks it after the rule's conditions: `if (conditions) && !(window) { return action }`. Compiled policies export `abi_version() = 3`.
2. **Host inputs (policy ABI version 3).** For modules that declare ABI version 3 the host sends two values with every event, each `0` when unknown:
   - the wall clock, as UTC Unix seconds: the event's own timestamp (when the kernel saw the operation), not the evaluation time, so a recorded event replays with the same decision. Events without a timestamp are stamped at evaluation. The policy derives the minute of the day and weekday from it with integer arithmetic. Sending one raw value instead of precomputed calendar fields keeps a single source of truth and gives hand-written policies the full timestamp.
   - the container age in milliseconds: the event timestamp minus the container start time. A known age is at least 1 ms.

   In the binary ABI these are at offsets 245 (`u32`) and 249 (`u48` little-endian) of the 256-byte event struct, in what used to be padding. In the JSON ABI they are the keys `wall_clock_unix` and `container_age_ms`. Modules declaring an older ABI version (or none) are sent neither, so their behaviour and caching are unchanged.
3. **Container start time.** The daemon resolves the event's cgroup id to its container (`internal/container.CgroupResolver`) and dates the container by the **earliest start time of any process in its cgroup subtree** (`/proc/<pid>/stat` field 22, measured on `CLOCK_BOOTTIME` and converted to wall time). The container's init process starts when the container does and lives as long as it, so this is the container's start to within a clock tick. The value is cached per cgroup. It is only looked up for event types whose policy reads container age.
4. **No caching, no kernel fast path.** A temporal decision can change for the same event a moment later, so it must not be reused. The compiler declares the `wall_clock` / `container_age` fields-read bits (`FieldBitTime`, `FieldBitContainerAge` in `internal/compiler/fields.go`) for every event type with a temporal rule. The decision cache never stores or serves decisions for those event types, and no kernel policy-map key covers time, so they are never synced to the BPF map. Every such event is evaluated by the policy. Event types without temporal rules in the same policy are cached and synced as before. A time-bucketed cache key was rejected: a window can close at any minute and an age limit at any millisecond, so no bucket size is sound.

### Why not cgroup directory timestamps

cgroup v2 is kernfs. It has no birth time (`statx` reports no `STATX_BTIME`). Its `mtime`/`ctime` are either the moment the VFS inode was instantiated (the first access, and again after the inode is evicted from the cache) or the last `chown`/`chmod`/child-cgroup change. Both make a container look younger than it is, which is the permissive direction for `max_container_age`. The time the daemon first saw a cgroup is worse: for containers that predate the daemon it is arbitrarily late. Neither is used, and an undatable container's age is reported unknown (fail closed) rather than guessed.

## Limits

- **Container age needs Linux, a container cgroup and the host PID namespace.** The container's pids are read from `cgroup.procs`, which lists pids in the reader's PID namespace, so `warmor-daemon` must run with `hostPID` (the shipped DaemonSet does). On Windows and macOS, for host processes, and for containers the resolver does not recognise (see the runtime patterns in `internal/container`), age is unknown.
- **Accuracy.** The start time has clock-tick resolution (10 ms). A process migrated into the container's cgroup from outside (possible only from the host, with root) can make the container look older. A container whose processes run in a nested cgroup not under its scope directory is dated by the processes the resolver can see. Undatable starts are retried at most every 2 seconds per cgroup. At most 10,000 processes are examined per container.
- **Clock.** Times are UTC only; there is no time-zone or DST support. The wall clock is the event timestamp, derived from the kernel's monotonic clock at daemon start; a host suspend or a wall-clock step after the daemon started skews it. The binary ABI's `u32` seconds stop at 2106, after which the time is unknown.
- **Performance.** Event types with temporal rules bypass the decision cache and the kernel fast path, so every such event costs one WASM evaluation (typically tens of microseconds).
- **Hand-written policies.** Rust policies can read the same inputs by declaring ABI version 3 (see [Rust policy examples](rust-policy-examples.md#host-contract)). The bundled `policies/temporal-access` crate does.
- **Simulation.** Event sinks record the event time and, when the enforcing policy read container age, the container start (`container_start`); `warmor-simulate` replays both. Events recorded under a policy without age rules carry no container start, so replaying them against an age rule sees an unknown age and reports would-be denials.
- **Tooling.** `warmor-policy-merge` and `warmor-policy-diff` carry `temporal:` blocks through and compare them, but do not validate them; compile the result.
